package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/fabriziosalmi/security-audit-cli/internal/report"
	"github.com/fabriziosalmi/security-audit-cli/internal/spec"
	"github.com/fabriziosalmi/security-audit-cli/internal/store"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// ValidateRun validates coverage-ledger.json, findings.json, source paths on disk, and cross-file consistency.
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

	units, _ := rs.LoadLedger()
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
		if len(ledgerErrs) == 0 && len(findingsErrs) == 0 {
			crossErrs := validator.ValidateCrossFileConsistency(units, findings)
			findingsErrs = append(findingsErrs, crossErrs...)
		}
	}

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
