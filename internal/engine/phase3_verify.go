package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/report"
	"github.com/fabriziosalmi/security-audit-cli/internal/spec"
	"github.com/fabriziosalmi/security-audit-cli/internal/store"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// SubmitVerifier enforces adversarial separation (verifier != hunter), validates the Phase 3 record
// against report-schema.json and source files on disk, updates linked ledger units, and writes findings.json.
func SubmitVerifier(req VerifierSubmitRequest) (map[string]any, error) {
	rs := store.New(req.OutputDir)
	meta, err := rs.LoadMetadata()
	if err != nil {
		return nil, err
	}
	state, err := rs.LoadState()
	if err != nil {
		return nil, err
	}
	assign, ok := state.Agents[req.AgentID]
	if !ok || assign.Role != "verifier" {
		return nil, fmt.Errorf("agent_id %q is not a registered Phase 3 verifier", req.AgentID)
	}
	env, ok := state.Candidates[req.Fingerprint]
	if !ok {
		return nil, fmt.Errorf("unknown candidate fingerprint %q", req.Fingerprint)
	}
	if req.AgentID == env.HunterID {
		return nil, fmt.Errorf("adversarial isolation violation: verifier %q cannot equal hunter %q", req.AgentID, env.HunterID)
	}
	if req.Decision != "confirmed" && req.Decision != "needs_validation" && req.Decision != "rejected" {
		return nil, fmt.Errorf("invalid decision %q (expected confirmed, needs_validation, or rejected)", req.Decision)
	}

	rawBytes, err := json.Marshal(req.Record)
	if err != nil {
		return nil, err
	}
	var finding validator.Finding
	if err := json.Unmarshal(rawBytes, &finding); err != nil {
		return nil, fmt.Errorf("unmarshal record: %w", err)
	}
	if finding.Verdict != req.Decision {
		return nil, fmt.Errorf("record.verdict %q does not match decision %q", finding.Verdict, req.Decision)
	}
	if finding.Fingerprint != req.Fingerprint {
		return nil, fmt.Errorf("record.fingerprint %q does not match candidate fingerprint %q", finding.Fingerprint, req.Fingerprint)
	}

	errs := validator.ValidateSingleFinding(finding, req.Record, "$", meta.Target, false)
	if len(errs) > 0 {
		return nil, fmt.Errorf("verifier record failed schema/source validation: %s", strings.Join(errs, "; "))
	}

	units, err := rs.LoadLedger()
	if err != nil {
		return nil, err
	}
	if req.Check != nil {
		req.Check.AgentID = req.AgentID
		linkedSet := make(map[string]bool)
		for _, cid := range env.LinkedUnits {
			linkedSet[cid] = true
		}
		for i := range units {
			u := &units[i]
			if linkedSet[u.CoverageID] {
				if u.Status == "planned" {
					aid := req.AgentID
					u.AgentID = &aid
					u.Status = "candidate"
					u.ResultFingerprints = []string{req.Fingerprint}
				}
				u.LocalChecks = append(u.LocalChecks, *req.Check)
				u.ReviewedPaths = uniqueStrings(append(u.ReviewedPaths, req.Check.ReviewedPaths...))
			}
		}
		if err := rs.SaveLedger(units); err != nil {
			return nil, err
		}
	}

	env.Phase3VerifierID = req.AgentID
	env.Phase3Decision = req.Decision
	env.FinalRecord = &finding
	env.FinalRaw = req.Record
	if meta.Profile == "quick" || req.Decision == "rejected" {
		env.Phase5Verified = true
		env.NeedsFreshVerify = false
	} else {
		env.Phase5Verified = false
		env.NeedsFreshVerify = true
	}
	assign.Completed = true

	if err := rs.SyncFindings(meta.Target, state); err != nil {
		return nil, err
	}
	if err := rs.SaveState(state); err != nil {
		return nil, err
	}

	return map[string]any{
		"status":           "ok",
		"fingerprint":      req.Fingerprint,
		"decision":         req.Decision,
		"phase5_satisfied": env.Phase5Verified,
	}, nil
}

// SubmitRecordVerifier handles Phase 5 independent record verification and detects material replacements
// that require an additional fresh independent verifier.
func SubmitRecordVerifier(req RecordVerifySubmitRequest) (map[string]any, error) {
	rs := store.New(req.OutputDir)
	meta, err := rs.LoadMetadata()
	if err != nil {
		return nil, err
	}
	state, err := rs.LoadState()
	if err != nil {
		return nil, err
	}
	assign, ok := state.Agents[req.AgentID]
	if !ok || assign.Role != "record_verifier" {
		return nil, fmt.Errorf("agent_id %q is not a registered Phase 5 record_verifier", req.AgentID)
	}
	env, ok := state.Candidates[req.Fingerprint]
	if !ok || env.FinalRecord == nil {
		return nil, fmt.Errorf("candidate %q has no Phase 3/4 record to verify", req.Fingerprint)
	}
	if req.AgentID == env.HunterID || req.AgentID == env.Phase3VerifierID {
		return nil, fmt.Errorf("adversarial isolation violation: record_verifier %q cannot match hunter or Phase 3 verifier", req.AgentID)
	}
	for _, prev := range env.Phase5VerifierIDs {
		if req.AgentID == prev {
			return nil, fmt.Errorf("adversarial isolation violation: record_verifier %q already reviewed %q", req.AgentID, req.Fingerprint)
		}
	}

	materialReplacement := false
	switch req.Decision {
	case "verified":
		env.Phase5VerifierIDs = append(env.Phase5VerifierIDs, req.AgentID)
		env.Phase5Verified = true
		env.NeedsFreshVerify = false
	case "replace":
		if !validator.IsVisibleText(req.Reason, 0) {
			return nil, fmt.Errorf("replacement requires a non-empty reason")
		}
		if req.Record == nil {
			return nil, fmt.Errorf("replacement requires a replacement record object")
		}
		rawBytes, err := json.Marshal(req.Record)
		if err != nil {
			return nil, err
		}
		var newFinding validator.Finding
		if err := json.Unmarshal(rawBytes, &newFinding); err != nil {
			return nil, fmt.Errorf("unmarshal replacement record: %w", err)
		}
		if newFinding.Fingerprint != req.Fingerprint {
			return nil, fmt.Errorf("replacement fingerprint %q must match %q", newFinding.Fingerprint, req.Fingerprint)
		}
		errs := validator.ValidateSingleFinding(newFinding, req.Record, "$", meta.Target, false)
		if len(errs) > 0 {
			return nil, fmt.Errorf("replacement record failed validation: %s", strings.Join(errs, "; "))
		}

		materialReplacement = IsMaterialReplacement(*env.FinalRecord, newFinding)
		env.FinalRecord = &newFinding
		env.FinalRaw = req.Record
		env.Phase5VerifierIDs = append(env.Phase5VerifierIDs, req.AgentID)
		if materialReplacement && newFinding.Verdict != "rejected" {
			env.Phase5Verified = false
			env.NeedsFreshVerify = true
		} else {
			env.Phase5Verified = true
			env.NeedsFreshVerify = false
		}
	default:
		return nil, fmt.Errorf("invalid Phase 5 decision %q (expected verified or replace)", req.Decision)
	}

	assign.Completed = true
	if err := rs.SyncFindings(meta.Target, state); err != nil {
		return nil, err
	}
	if err := rs.SaveState(state); err != nil {
		return nil, err
	}

	return map[string]any{
		"status":                        "ok",
		"fingerprint":                   req.Fingerprint,
		"decision":                      req.Decision,
		"material_replacement":          materialReplacement,
		"requires_another_fresh_verify": env.NeedsFreshVerify,
		"phase5_verified":               env.Phase5Verified,
	}, nil
}

// IsMaterialReplacement implements the exact Phase 5 rule from VALIDATION-AND-REPORTING.md:
// "Do not apply a Phase 5 replacement as final when it promotes a record to a stronger verdict,
// including any promotion to confirmed, or materially changes the root cause, trace, execution input
// or observed result, demonstrated impact, or severity."
func IsMaterialReplacement(oldF, newF validator.Finding) bool {
	verdictStrength := map[string]int{"rejected": 0, "needs_validation": 1, "confirmed": 2}
	if verdictStrength[newF.Verdict] > verdictStrength[oldF.Verdict] {
		return true
	}
	if oldF.RootCause != newF.RootCause || oldF.ClaimedRootCause != newF.ClaimedRootCause {
		return true
	}
	if len(oldF.Trace) != len(newF.Trace) {
		return true
	}
	for i := range oldF.Trace {
		if oldF.Trace[i].Kind != newF.Trace[i].Kind || oldF.Trace[i].File != newF.Trace[i].File || oldF.Trace[i].Line != newF.Trace[i].Line || oldF.Trace[i].Scope != newF.Trace[i].Scope {
			return true
		}
	}
	if oldF.Execution != nil && newF.Execution != nil {
		if !reflect.DeepEqual(oldF.Execution.Payloads, newF.Execution.Payloads) || oldF.Execution.ObservedResult != newF.Execution.ObservedResult {
			return true
		}
	} else if (oldF.Execution == nil) != (newF.Execution == nil) {
		return true
	}
	if oldF.Severity != nil && newF.Severity != nil {
		if oldF.Severity.Impact.Score != newF.Severity.Impact.Score || oldF.Severity.OverallSeverity != newF.Severity.OverallSeverity {
			return true
		}
	} else if (oldF.Severity == nil) != (newF.Severity == nil) {
		return true
	}
	return false
}

// ValidateRun validates coverage-ledger.json, findings.json, and source paths on disk.
func ValidateRun(outputDir string) (map[string]any, error) {
	rs := store.New(outputDir)
	meta, err := rs.LoadMetadata()
	if err != nil {
		return nil, err
	}
	cat, err := spec.LoadCatalog()
	if err != nil {
		return nil, err
	}
	validBlocks := cat.ValidBlockMap()

	ledgerErrs, err := validator.ValidateCoverageLedgerFile(rs.LedgerPath(), meta.Target, outputDir, validBlocks)
	if err != nil {
		return nil, fmt.Errorf("ledger read error: %w", err)
	}

	var findingsErrs []string
	findingsCount := 0
	if _, stErr := os.Stat(rs.FindingsPath()); stErr == nil {
		fErrs, ferr := validator.ValidateFindingsFile(rs.FindingsPath(), meta.Target)
		if ferr != nil {
			return nil, fmt.Errorf("findings read error: %w", ferr)
		}
		findingsErrs = fErrs
		findings, _ := rs.LoadFindings()
		findingsCount = len(findings)
	}

	units, _ := rs.LoadLedger()
	valid := len(ledgerErrs) == 0 && len(findingsErrs) == 0
	return map[string]any{
		"valid":          valid,
		"units_count":    len(units),
		"findings_count": findingsCount,
		"ledger_errors":  nonNilSlice(ledgerErrs),
		"finding_errors": nonNilSlice(findingsErrs),
	}, nil
}

// Render enforces the Phase 5/6 terminal gates and deterministically generates
// REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md, and findings.sarif via internal/report.
func Render(req RenderRequest) (*RenderResponse, error) {
	valRes, err := ValidateRun(req.OutputDir)
	if err != nil {
		return nil, err
	}
	if valid, _ := valRes["valid"].(bool); !valid {
		return nil, fmt.Errorf("cannot render Phase 6 reports while validators fail: %v", valRes)
	}

	rs := store.New(req.OutputDir)
	meta, err := rs.LoadMetadata()
	if err != nil {
		return nil, err
	}
	state, err := rs.LoadState()
	if err != nil {
		return nil, err
	}
	units, err := rs.LoadLedger()
	if err != nil {
		return nil, err
	}
	findings, err := rs.LoadFindings()
	if err != nil {
		return nil, err
	}

	if req.IncompleteReason != "" {
		meta.RunStatus = "incomplete"
		meta.IncompleteReason = req.IncompleteReason
	}

	var unvalidatedFPs []string
	var unverifiedPhase5FPs []string
	for fp, env := range state.Candidates {
		if env.FinalRecord == nil {
			unvalidatedFPs = append(unvalidatedFPs, fp)
		} else if !env.Phase5Verified || env.NeedsFreshVerify {
			unverifiedPhase5FPs = append(unverifiedPhase5FPs, fp)
		}
	}
	sort.Strings(unvalidatedFPs)
	sort.Strings(unverifiedPhase5FPs)

	if (len(unvalidatedFPs) > 0 || len(unverifiedPhase5FPs) > 0) && meta.RunStatus != "incomplete" {
		return nil, fmt.Errorf("cannot mark run complete: unvalidated candidates=%v, unverified Phase 5 records=%v (pass incomplete_reason if budget exhausted)", unvalidatedFPs, unverifiedPhase5FPs)
	}

	var confirmed, needsVal, rejected []validator.Finding
	for _, f := range findings {
		env, exists := state.Candidates[f.Fingerprint]
		if exists && (!env.Phase5Verified || env.NeedsFreshVerify) {
			continue
		}
		switch f.Verdict {
		case "confirmed":
			confirmed = append(confirmed, f)
		case "needs_validation":
			needsVal = append(needsVal, f)
		case "rejected":
			rejected = append(rejected, f)
		}
	}

	statusCounts := map[string]int{}
	for _, u := range units {
		statusCounts[u.Status]++
	}
	if statusCounts["planned"] > 0 || statusCounts["in_progress"] > 0 {
		if meta.RunStatus != "incomplete" {
			return nil, fmt.Errorf("cannot render complete report while %d planned and %d in_progress units remain", statusCounts["planned"], statusCounts["in_progress"])
		}
	} else if meta.RunStatus != "incomplete" {
		meta.RunStatus = "complete"
	}

	if err := rs.SaveMetadata(meta); err != nil {
		return nil, err
	}

	reportMD := report.BuildReportMD(meta, state, units, statusCounts, confirmed, needsVal, rejected, unvalidatedFPs, unverifiedPhase5FPs)
	detailMD := report.BuildFindingsDetailMD(confirmed)
	needsValMD := report.BuildNeedsValidationMD(needsVal)
	sarifBytes, err := report.BuildSARIF(confirmed)
	if err != nil {
		return nil, err
	}

	reportPath := filepath.Join(req.OutputDir, "REPORT.md")
	detailPath := filepath.Join(req.OutputDir, "FINDINGS-DETAIL.md")
	needsValPath := filepath.Join(req.OutputDir, "NEEDS-VALIDATION.md")
	sarifPath := filepath.Join(req.OutputDir, "findings.sarif")

	if err := store.WriteFileAtomic(reportPath, []byte(reportMD), 0o600); err != nil {
		return nil, err
	}
	if err := store.WriteFileAtomic(detailPath, []byte(detailMD), 0o600); err != nil {
		return nil, err
	}
	if err := store.WriteFileAtomic(needsValPath, []byte(needsValMD), 0o600); err != nil {
		return nil, err
	}
	if err := store.WriteFileAtomic(sarifPath, sarifBytes, 0o600); err != nil {
		return nil, err
	}

	if unvalidatedFPs == nil {
		unvalidatedFPs = []string{}
	}
	return &RenderResponse{
		RunStatus:           meta.RunStatus,
		IncompleteReason:    meta.IncompleteReason,
		ReportPath:          reportPath,
		FindingsDetailPath:  detailPath,
		NeedsValidationPath: needsValPath,
		SarifPath:           sarifPath,
		ConfirmedCount:      len(confirmed),
		NeedsValCount:       len(needsVal),
		RejectedCount:       len(rejected),
		HardeningCount:      len(state.HardeningNotes),
		UnvalidatedFPs:      unvalidatedFPs,
	}, nil
}
