package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/report"
	"github.com/fabriziosalmi/security-audit-cli/internal/scanner"
	"github.com/fabriziosalmi/security-audit-cli/internal/spec"
	"github.com/fabriziosalmi/security-audit-cli/internal/store"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// ValidateRun validates coverage-ledger.json, findings.json, source paths on disk, and cross-file consistency.
func ValidateRun(outputDir string) (map[string]any, error) {
	return ValidateRunWithGate(outputDir, "")
}

// EvaluateFailOnGate evaluates whether findings pass the requested severity/verdict gate threshold.
func EvaluateFailOnGate(failOn string, findings []validator.Finding) (bool, string, error) {
	if failOn == "" {
		return true, "", nil
	}
	severityRank := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}
	switch failOn {
	case "critical", "high", "medium", "low":
		minRank := severityRank[failOn]
		var matched []string
		for _, f := range findings {
			if f.Verdict == "confirmed" && f.Severity != nil {
				if severityRank[f.Severity.OverallSeverity] >= minRank {
					matched = append(matched, fmt.Sprintf("%s (%s)", f.Fingerprint, f.Severity.OverallSeverity))
				}
			}
		}
		if len(matched) > 0 {
			return false, fmt.Sprintf("fail_on=%s triggered by %d confirmed finding(s): %s", failOn, len(matched), strings.Join(matched, ", ")), nil
		}
		return true, "", nil
	case "needs_validation", "any":
		var matched []string
		for _, f := range findings {
			if f.Verdict == "confirmed" || f.Verdict == "needs_validation" {
				matched = append(matched, fmt.Sprintf("%s (%s)", f.Fingerprint, f.Verdict))
			}
		}
		if len(matched) > 0 {
			return false, fmt.Sprintf("fail_on=%s triggered by %d finding(s): %s", failOn, len(matched), strings.Join(matched, ", ")), nil
		}
		return true, "", nil
	default:
		return false, "", fmt.Errorf("invalid fail_on threshold %q (expected critical, high, medium, low, needs_validation, or any)", failOn)
	}
}

// ValidateRunWithGate validates a run directory and optionally evaluates a CI failure threshold.
func ValidateRunWithGate(outputDir, failOn string) (map[string]any, error) {
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

	units, _ := rs.LoadLedger()
	var findings []validator.Finding
	var findingsErrs []string
	findingsCount := 0
	if _, stErr := os.Stat(rs.FindingsPath()); stErr == nil {
		fErrs, ferr := validator.ValidateFindingsFile(rs.FindingsPath(), meta.Target)
		if ferr != nil {
			return nil, fmt.Errorf("findings read error: %w", ferr)
		}
		findingsErrs = fErrs
		findings, _ = rs.LoadFindings()
		findingsCount = len(findings)
		if len(ledgerErrs) == 0 && len(findingsErrs) == 0 {
			crossErrs := validator.ValidateCrossFileConsistency(units, findings)
			findingsErrs = append(findingsErrs, crossErrs...)
		}
	}

	if state, serr := rs.LoadState(); serr == nil {
		driftErrs, _ := scanner.DetectSourceDrift(meta.Target, state)
		findingsErrs = append(findingsErrs, driftErrs...)
	}

	gatePassed, gateReason, gerr := EvaluateFailOnGate(failOn, findings)
	if gerr != nil {
		return nil, gerr
	}

	valid := len(ledgerErrs) == 0 && len(findingsErrs) == 0
	res := map[string]any{
		"valid":          valid,
		"gate_passed":    gatePassed,
		"units_count":    len(units),
		"findings_count": findingsCount,
		"ledger_errors":  nonNilSlice(ledgerErrs),
		"finding_errors": nonNilSlice(findingsErrs),
	}
	if gateReason != "" {
		res["gate_failure_reason"] = gateReason
	}
	return res, nil
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
		return nil, fmt.Errorf(
			"cannot mark run complete: unvalidated candidates=%v, unverified Phase 5 records=%v "+
				"(pass incomplete_reason if budget exhausted)",
			unvalidatedFPs, unverifiedPhase5FPs,
		)
	}
	if len(state.UncoveredQueue) > 0 && meta.RunStatus != "incomplete" {
		return nil, fmt.Errorf(
			"cannot mark run complete while %d uncovered hunter entries have not been reviewed by a coverage critic",
			len(state.UncoveredQueue),
		)
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
			return nil, fmt.Errorf(
				"cannot render complete report while %d planned and %d in_progress units remain",
				statusCounts["planned"], statusCounts["in_progress"],
			)
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

	advisoryPaths := []string{}
	var advisoryManifestRel []string
	if len(confirmed) > 0 {
		advDir := filepath.Join(req.OutputDir, "advisories")
		if err := os.MkdirAll(advDir, 0o700); err != nil {
			return nil, fmt.Errorf("create advisories dir: %w", err)
		}
		for _, f := range confirmed {
			advRel := filepath.ToSlash(filepath.Join("advisories", "GHSA-"+f.Fingerprint+".md"))
			advAbs := filepath.Join(req.OutputDir, advRel)
			advMD := report.BuildAdvisoryMD(meta, f)
			if err := store.WriteFileAtomic(advAbs, []byte(advMD), 0o600); err != nil {
				return nil, fmt.Errorf("write advisory %s: %w", advRel, err)
			}
			advisoryPaths = append(advisoryPaths, advAbs)
			advisoryManifestRel = append(advisoryManifestRel, advRel)
		}
	}

	// Build cryptographic SHA-256 integrity manifest (sha256sum -c compatible)
	manifestFiles := []string{
		"run-metadata.json",
		"architecture.md",
		"coverage-ledger.json",
		"findings.json",
		"REPORT.md",
		"FINDINGS-DETAIL.md",
		"NEEDS-VALIDATION.md",
		"findings.sarif",
	}
	manifestFiles = append(manifestFiles, advisoryManifestRel...)
	hashes := make(map[string]string, len(manifestFiles))
	var manifestBuilder strings.Builder
	for _, fname := range manifestFiles {
		fpath := filepath.Join(req.OutputDir, fname)
		if h, herr := scanner.FileHashSHA256(fpath); herr == nil {
			hashes[fname] = h
			fmt.Fprintf(&manifestBuilder, "%s  %s\n", h, fname)
		}
	}
	manifestPath := filepath.Join(req.OutputDir, "manifest.sha256")
	if err := store.WriteFileAtomic(manifestPath, []byte(manifestBuilder.String()), 0o600); err != nil {
		return nil, err
	}

	gatePassed, gateReason, gerr := EvaluateFailOnGate(req.FailOn, findings)
	if gerr != nil {
		return nil, gerr
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
		AdvisoryPaths:       advisoryPaths,
		ManifestPath:        manifestPath,
		ArtifactHashes:      hashes,
		ConfirmedCount:      len(confirmed),
		NeedsValCount:       len(needsVal),
		RejectedCount:       len(rejected),
		HardeningCount:      len(state.HardeningNotes),
		UnvalidatedFPs:      unvalidatedFPs,
		GatePassed:          gatePassed,
		GateFailureReason:   gateReason,
	}, nil
}

// Status returns a zero-token deterministic summary of an audit run and the exact next required actions to reach Phase 6 render.
func Status(req StatusRequest) (*StatusResponse, error) {
	if req.OutputDir == "" {
		return nil, fmt.Errorf("output_dir is required")
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

	_, archErr := rs.LoadArchitecture()
	archWritten := archErr == nil

	counts := map[string]int{}
	var plannedIDs, inProgressIDs []string
	for _, u := range units {
		counts[u.Status]++
		switch u.Status {
		case "planned":
			plannedIDs = append(plannedIDs, u.CoverageID)
		case "in_progress":
			inProgressIDs = append(inProgressIDs, u.CoverageID)
		}
	}

	var unvalidatedFPs, unverifiedPhase5FPs []string
	for fp, env := range state.Candidates {
		if env.FinalRecord == nil {
			unvalidatedFPs = append(unvalidatedFPs, fp)
		} else if !env.Phase5Verified || env.NeedsFreshVerify {
			unverifiedPhase5FPs = append(unverifiedPhase5FPs, fp)
		}
	}
	sort.Strings(unvalidatedFPs)
	sort.Strings(unverifiedPhase5FPs)

	_, driftedFiles := scanner.DetectSourceDrift(meta.Target, state)

	var actions []string
	if !archWritten {
		actions = append(actions, "write architecture.md via sec-audit architecture")
	}
	if len(units) == 0 {
		actions = append(actions, "seed coverage-ledger.json via sec-audit ledger-seed")
	}
	if len(plannedIDs) > 0 {
		actions = append(actions, fmt.Sprintf("assign and submit hunter(s) for %d planned unit(s)", len(plannedIDs)))
	}
	if len(inProgressIDs) > 0 {
		actions = append(actions, fmt.Sprintf("submit pending hunter result(s) for %d in_progress unit(s)", len(inProgressIDs)))
	}
	if len(state.UncoveredQueue) > 0 {
		actions = append(actions, fmt.Sprintf("assign and submit coverage critic to drain %d uncovered queue entry/entries", len(state.UncoveredQueue)))
	}
	if len(unvalidatedFPs) > 0 {
		actions = append(actions, fmt.Sprintf("assign and submit Phase 3 verifier(s) for candidate fingerprint(s): %s", strings.Join(unvalidatedFPs, ", ")))
	}
	if len(unverifiedPhase5FPs) > 0 {
		actions = append(actions, fmt.Sprintf("assign and submit Phase 5 record_verifier(s) for fingerprint(s): %s", strings.Join(unverifiedPhase5FPs, ", ")))
	}
	if len(driftedFiles) > 0 {
		actions = append(actions, fmt.Sprintf("resolve source file drift on: %s", strings.Join(driftedFiles, ", ")))
	}

	readyToRender := len(actions) == 0
	if readyToRender {
		actions = []string{"ready: run sec-audit render"}
	}

	return &StatusResponse{
		RunID:                 meta.RunID,
		Repo:                  meta.Repo,
		Profile:               meta.Profile,
		RunStatus:             meta.RunStatus,
		CurrentWave:           state.CurrentWave,
		ArchitectureWritten:   archWritten,
		AgentsSpent:           meta.AgentsSpent,
		Budget:                meta.Budget,
		UnitStatusCounts:      counts,
		PlannedUnitIDs:        nonNilSlice(plannedIDs),
		InProgressUnitIDs:     nonNilSlice(inProgressIDs),
		UncoveredQueueCount:   len(state.UncoveredQueue),
		UnvalidatedCandidates: nonNilSlice(unvalidatedFPs),
		UnverifiedPhase5FPs:   nonNilSlice(unverifiedPhase5FPs),
		SourceDriftFiles:      nonNilSlice(driftedFiles),
		ReadyToRender:         readyToRender,
		NextRequiredActions:   actions,
	}, nil
}
