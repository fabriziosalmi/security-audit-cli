package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// RenderRequest is the input for sec-audit render / sec_audit_render.
type RenderRequest struct {
	OutputDir        string `json:"output_dir"`
	IncompleteReason string `json:"incomplete_reason,omitempty"`
}

// RenderResponse lists the generated Phase 6 artifact paths and terminal run status.
type RenderResponse struct {
	RunStatus          string   `json:"run_status"`
	IncompleteReason   string   `json:"incomplete_reason,omitempty"`
	ReportPath         string   `json:"report_path"`
	FindingsDetailPath string   `json:"findings_detail_path"`
	NeedsValidationPath string  `json:"needs_validation_path"`
	SarifPath          string   `json:"sarif_path"`
	ConfirmedCount     int      `json:"confirmed_count"`
	NeedsValCount      int      `json:"needs_validation_count"`
	RejectedCount      int      `json:"rejected_count"`
	HardeningCount     int      `json:"hardening_count"`
	UnvalidatedFPs     []string `json:"unvalidated_fingerprints"`
}

// Render enforces the Phase 5/6 terminal gates and deterministically generates
// REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md, and findings.sarif.
func Render(req RenderRequest) (*RenderResponse, error) {
	valRes, err := ValidateRun(req.OutputDir)
	if err != nil {
		return nil, err
	}
	if valid, _ := valRes["valid"].(bool); !valid {
		return nil, fmt.Errorf("cannot render Phase 6 reports while validators fail: %v", valRes)
	}

	meta, err := loadMetadata(req.OutputDir)
	if err != nil {
		return nil, err
	}
	state, err := loadState(req.OutputDir)
	if err != nil {
		return nil, err
	}
	units, err := loadLedger(req.OutputDir)
	if err != nil {
		return nil, err
	}
	findings, err := loadFindings(req.OutputDir)
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
		// Only include records that passed Phase 5 verification
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

	if err := saveMetadata(req.OutputDir, meta); err != nil {
		return nil, err
	}

	reportMD := buildReportMD(meta, state, units, statusCounts, confirmed, needsVal, rejected, unvalidatedFPs, unverifiedPhase5FPs)
	detailMD := buildFindingsDetailMD(meta, confirmed)
	needsValMD := buildNeedsValidationMD(meta, needsVal)
	sarifBytes, err := buildSARIF(meta, confirmed)
	if err != nil {
		return nil, err
	}

	reportPath := filepath.Join(req.OutputDir, "REPORT.md")
	detailPath := filepath.Join(req.OutputDir, "FINDINGS-DETAIL.md")
	needsValPath := filepath.Join(req.OutputDir, "NEEDS-VALIDATION.md")
	sarifPath := filepath.Join(req.OutputDir, "findings.sarif")

	if err := os.WriteFile(reportPath, []byte(reportMD), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(detailPath, []byte(detailMD), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(needsValPath, []byte(needsValMD), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(sarifPath, sarifBytes, 0o600); err != nil {
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

func buildReportMD(meta *RunMetadata, state *InternalState, units []validator.CoverageUnit, counts map[string]int, confirmed, needsVal, rejected []validator.Finding, unvalidatedFPs, unverifiedP5 []string) string {
	var b strings.Builder
	b.WriteString("# Security Audit Report\n\n")

	// Section 1: Run metadata, scope, budget, partial pass disclosure
	b.WriteString("## 1. Run Scope and Execution Statement\n\n")
	fmt.Fprintf(&b, "- **Repository**: `%s`\n", meta.Repo)
	fmt.Fprintf(&b, "- **Source Ref**: `%s` (dirty worktree: `%v`)\n", meta.SourceRef, meta.DirtyWorktree)
	fmt.Fprintf(&b, "- **Profile**: `%s`\n", meta.Profile)
	fmt.Fprintf(&b, "- **Run Status**: `%s`\n", meta.RunStatus)
	if meta.IncompleteReason != "" {
		fmt.Fprintf(&b, "- **Incomplete Reason**: `%s`\n", meta.IncompleteReason)
	}
	if len(meta.ScopePaths) > 0 {
		fmt.Fprintf(&b, "- **Scope Paths**: `%s` (partial scoped pass)\n", strings.Join(meta.ScopePaths, "`, `"))
	} else {
		b.WriteString("- **Scope Paths**: full repository\n")
	}
	if meta.Budget != nil {
		fmt.Fprintf(&b, "- **Agent Budget**: %d spent / %d planned\n", meta.AgentsSpent, *meta.Budget)
	} else {
		fmt.Fprintf(&b, "- **Agents Spent**: %d (unbounded budget)\n", meta.AgentsSpent)
	}
	fmt.Fprintf(&b, "- **Execution Policy**: `%s` (read-only target inspection and bounded local sandbox checks only; no live or shared endpoints probed)\n", meta.ExecutionPolicy)
	if len(meta.PriorRunPaths) == 0 {
		b.WriteString("- **Prior Runs**: No prior coverage ledger was used. A single pass does not exhaust the target.\n")
	} else {
		fmt.Fprintf(&b, "- **Prior Runs Evaluated**: `%s`\n", strings.Join(meta.PriorRunPaths, "`, `"))
	}
	if meta.Profile == "quick" || len(meta.ScopePaths) > 0 || meta.RunStatus == "incomplete" || counts["deferred"] > 0 || counts["out_of_scope"] > 0 {
		b.WriteString("\n> **Coverage Disclosure**: This run represents a partial pass. See the Coverage Summary section for deferred, blocked, or out-of-scope units.\n")
	}
	if len(unvalidatedFPs) > 0 || len(unverifiedP5) > 0 {
		b.WriteString("\n### Unvalidated / Unverified Ledger Candidates (Not Confirmed Findings)\n\n")
		for _, fp := range unvalidatedFPs {
			fmt.Fprintf(&b, "- `%s` (candidate validation incomplete)\n", fp)
		}
		for _, fp := range unverifiedP5 {
			fmt.Fprintf(&b, "- `%s` (independent Phase 5 verification incomplete)\n", fp)
		}
	}
	b.WriteString("\n")

	// Section 2: Security Posture Summary
	b.WriteString("## 2. Security Posture Summary\n\n")
	fmt.Fprintf(&b, "This audit confirmed **%d** source-grounded vulnerability record(s), recorded **%d** blocked lead(s) requiring validation (`needs_validation`), and refuted **%d** candidate hypothesis/hypotheses (`rejected`) across **%d** deterministic coverage unit(s).\n\n",
		len(confirmed), len(needsVal), len(rejected), len(units))

	// Section 3: Confirmed Findings Table
	b.WriteString("## 3. Confirmed Findings Summary\n\n")
	if len(confirmed) == 0 {
		b.WriteString("No confirmed boundary violations were established in this pass.\n\n")
	} else {
		b.WriteString("| Severity | Fingerprint | Title | Entrypoint -> Sink | Observed Result |\n")
		b.WriteString("| :--- | :--- | :--- | :--- | :--- |\n")
		for _, f := range confirmed {
			first := f.Trace[0]
			last := f.Trace[len(f.Trace)-1]
			loc := fmt.Sprintf("`%s:%d` -> `%s:%d`", first.File, first.Line, last.File, last.Line)
			fmt.Fprintf(&b, "| **%s** | `%s` | %s | %s | %s |\n",
				strings.ToUpper(f.Severity.OverallSeverity), f.Fingerprint, escapeTable(f.Title), loc, escapeTable(f.Execution.ObservedResult))
		}
		b.WriteString("\n")

		// Section 4: Each Confirmed Finding
		b.WriteString("## 4. Confirmed Findings\n\n")
		for _, f := range confirmed {
			fmt.Fprintf(&b, "### [%s] %s (`%s`)\n\n", strings.ToUpper(f.Severity.OverallSeverity), f.Title, f.Fingerprint)
			fmt.Fprintf(&b, "- **Root Cause**: %s\n", f.RootCause)
			fmt.Fprintf(&b, "- **Intended Control**: %s\n", f.IntendedBehavior)
			fmt.Fprintf(&b, "- **Attacker Perspective**: %s\n", f.Execution.AttackerPerspective)
			fmt.Fprintf(&b, "- **Observed Result**: %s\n", f.Execution.ObservedResult)
			fmt.Fprintf(&b, "- **Priority Rationale**: Likelihood `%s` (%s) x Impact `%s` (%s) => Overall `%s` (Confidence: `%s`)\n",
				f.Severity.Likelihood.Score, f.Severity.Likelihood.Reason,
				f.Severity.Impact.Score, f.Severity.Impact.Reason,
				f.Severity.OverallSeverity, f.Confidence.Score)
			fmt.Fprintf(&b, "- **Smallest Source Fix**: %s\n\n", f.Remediation.Strategy)
		}
	}

	// Section 5: Needs Validation Table (strictly no severity)
	b.WriteString("## 5. Needs Validation Leads (Unresolved Blockers — No Severity Assigned)\n\n")
	if len(needsVal) == 0 {
		b.WriteString("No unresolved `needs_validation` leads remain.\n\n")
	} else {
		b.WriteString("| Fingerprint | Title | Source Trace | Exact Blocker(s) | Validation Plan |\n")
		b.WriteString("| :--- | :--- | :--- | :--- | :--- |\n")
		for _, f := range needsVal {
			first := f.Trace[0]
			last := f.Trace[len(f.Trace)-1]
			loc := fmt.Sprintf("`%s:%d` -> `%s:%d`", first.File, first.Line, last.File, last.Line)
			var plans []string
			if f.ValidationPlan != nil {
				if f.ValidationPlan.Local != "" {
					plans = append(plans, "Local: "+f.ValidationPlan.Local)
				}
				if f.ValidationPlan.Deployment != "" {
					plans = append(plans, "Owner-observed: "+f.ValidationPlan.Deployment)
				}
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
				f.Fingerprint, escapeTable(f.Title), loc, escapeTable(strings.Join(f.Blockers, "; ")), escapeTable(strings.Join(plans, " / ")))
		}
		b.WriteString("\n")
	}

	// Section 6: Hardening Notes
	b.WriteString("## 6. Hardening Notes\n\n")
	if len(state.HardeningNotes) == 0 {
		b.WriteString("No additional defense-in-depth hardening notes recorded.\n\n")
	} else {
		for _, note := range state.HardeningNotes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
		b.WriteString("\n")
	}

	// Section 7: Coverage Summary
	b.WriteString("## 7. Deterministic Coverage Summary\n\n")
	fmt.Fprintf(&b, "- **Total Ledger Units**: %d\n", len(units))
	fmt.Fprintf(&b, "- **Covered**: %d\n", counts["covered"])
	fmt.Fprintf(&b, "- **Candidate**: %d\n", counts["candidate"])
	fmt.Fprintf(&b, "- **Blocked**: %d\n", counts["blocked"])
	fmt.Fprintf(&b, "- **Deferred**: %d\n", counts["deferred"])
	fmt.Fprintf(&b, "- **Out of Scope**: %d\n", counts["out_of_scope"])
	fmt.Fprintf(&b, "- **Not Applicable**: %d\n", counts["not_applicable"])
	fmt.Fprintf(&b, "- **Final Clean Critic Completed**: `%v`\n", state.FinalCleanDone)

	return b.String()
}

func buildFindingsDetailMD(meta *RunMetadata, confirmed []validator.Finding) string {
	var b strings.Builder
	b.WriteString("# Findings Detail (Confirmed Medium, High, and Critical)\n\n")
	count := 0
	for _, f := range confirmed {
		sev := f.Severity.OverallSeverity
		if sev != "medium" && sev != "high" && sev != "critical" {
			continue
		}
		count++
		fmt.Fprintf(&b, "## [%s] %s (`%s`)\n\n", strings.ToUpper(sev), f.Title, f.Fingerprint)
		fmt.Fprintf(&b, "%s\n\n", f.Description)
		fmt.Fprintf(&b, "- **Root Cause**: %s\n", f.RootCause)
		fmt.Fprintf(&b, "- **Intended Behavior**: %s\n\n", f.IntendedBehavior)

		b.WriteString("### Ordered Source Trace\n\n")
		for idx, t := range f.Trace {
			fmt.Fprintf(&b, "%d. **[%s]** `%s:%d` (`%s`): %s\n", idx+1, t.Kind, t.File, t.Line, t.Scope, t.Description)
		}
		b.WriteString("\n### Supporting Evidence\n\n")
		for _, ev := range f.Evidence {
			fmt.Fprintf(&b, "- `%s:%d`: %s\n", ev.File, ev.Line, ev.Description)
		}
		if len(f.Conditions) > 0 {
			b.WriteString("\n### Conditions\n\n")
			for _, c := range f.Conditions {
				fmt.Fprintf(&b, "- `%s`: %s\n", c.Kind, c.Description)
			}
		}
		b.WriteString("\n### Target-Neutral Bounded Reproduction\n\n")
		fmt.Fprintf(&b, "- **Attacker Perspective**: %s\n", f.Execution.AttackerPerspective)
		b.WriteString("- **Payloads / Inputs**:\n")
		for _, p := range f.Execution.Payloads {
			fmt.Fprintf(&b, "  - `%s`\n", p)
		}
		b.WriteString("- **Instructions**:\n")
		for idx, inst := range f.Execution.Instructions {
			fmt.Fprintf(&b, "  %d. %s\n", idx+1, inst)
		}
		fmt.Fprintf(&b, "- **Observed Result**: %s\n\n", f.Execution.ObservedResult)

		b.WriteString("### Remediation\n\n")
		fmt.Fprintf(&b, "%s\n\n", f.Remediation.Strategy)
		for _, cc := range f.Remediation.CodeChanges {
			fmt.Fprintf(&b, "**File**: `%s`\n```\n%s\n```\n\n", cc.FileName, cc.FixedCode)
		}
	}
	if count == 0 {
		b.WriteString("No confirmed medium, high, or critical findings in this run.\n")
	}
	return b.String()
}

func buildNeedsValidationMD(meta *RunMetadata, needsVal []validator.Finding) string {
	var b strings.Builder
	b.WriteString("# Needs Validation Leads\n\n")
	b.WriteString("> These records represent source-grounded hypotheses blocked by a missing local capability or unobserved deployment fact. They carry **no severity**.\n\n")
	if len(needsVal) == 0 {
		b.WriteString("No unresolved `needs_validation` records in this run.\n")
		return b.String()
	}
	for _, f := range needsVal {
		fmt.Fprintf(&b, "## %s (`%s`)\n\n", f.Title, f.Fingerprint)
		fmt.Fprintf(&b, "%s\n\n", f.Description)
		fmt.Fprintf(&b, "- **Claimed Root Cause**: %s\n\n", f.ClaimedRootCause)
		b.WriteString("### Source Trace\n\n")
		for idx, t := range f.Trace {
			fmt.Fprintf(&b, "%d. **[%s]** `%s:%d` (`%s`): %s\n", idx+1, t.Kind, t.File, t.Line, t.Scope, t.Description)
		}
		b.WriteString("\n### Evidence\n\n")
		for _, ev := range f.Evidence {
			fmt.Fprintf(&b, "- `%s:%d`: %s\n", ev.File, ev.Line, ev.Description)
		}
		b.WriteString("\n### Exact Blockers\n\n")
		for _, blk := range f.Blockers {
			fmt.Fprintf(&b, "- %s\n", blk)
		}
		b.WriteString("\n### Resolution Plan\n\n")
		if f.ValidationPlan != nil {
			if f.ValidationPlan.Local != "" {
				fmt.Fprintf(&b, "- **Bounded Local Check**: %s\n", f.ValidationPlan.Local)
			}
			if f.ValidationPlan.Deployment != "" {
				fmt.Fprintf(&b, "- **Owner-Observed Deployment Check**: %s\n", f.ValidationPlan.Deployment)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func buildSARIF(meta *RunMetadata, confirmed []validator.Finding) ([]byte, error) {
	rules := make([]map[string]any, 0, len(confirmed))
	results := make([]map[string]any, 0, len(confirmed))

	for _, f := range confirmed {
		level := "warning"
		if f.Severity.OverallSeverity == "high" || f.Severity.OverallSeverity == "critical" {
			level = "error"
		} else if f.Severity.OverallSeverity == "low" || f.Severity.OverallSeverity == "informational" {
			level = "note"
		}
		sink := f.Trace[len(f.Trace)-1]
		rules = append(rules, map[string]any{
			"id":               f.Fingerprint,
			"shortDescription": map[string]any{"text": f.Title},
			"fullDescription":  map[string]any{"text": f.Description},
			"help":             map[string]any{"text": f.Remediation.Strategy},
		})
		results = append(results, map[string]any{
			"ruleId":  f.Fingerprint,
			"level":   level,
			"message": map[string]any{"text": f.RootCause + " — Observed: " + f.Execution.ObservedResult},
			"locations": []map[string]any{
				{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{"uri": sink.File},
						"region":           map[string]any{"startLine": sink.Line},
					},
				},
			},
		})
	}

	sarifDoc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":           "sec-audit",
						"informationUri": "https://github.com/fabriziosalmi/security-audit-cli",
						"rules":          rules,
					},
				},
				"results": results,
			},
		},
	}
	out, err := json.MarshalIndent(sarifDoc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func escapeTable(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.TrimSpace(s)
}
