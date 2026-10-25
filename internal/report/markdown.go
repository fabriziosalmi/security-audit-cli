package report

import (
	"fmt"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/store"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// BuildReportMD generates the 7-section deterministic REPORT.md defined by VALIDATION-AND-REPORTING.md.
func BuildReportMD(
	meta *store.RunMetadata,
	state *store.InternalState,
	units []validator.CoverageUnit,
	counts map[string]int,
	confirmed, needsVal, rejected []validator.Finding,
	unvalidatedFPs, unverifiedP5 []string,
) string {
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
	fmt.Fprintf(
		&b,
		"- **Execution Policy**: `%s` (read-only target inspection and bounded local sandbox checks only; "+
			"no live or shared endpoints probed)\n",
		meta.ExecutionPolicy,
	)
	if len(meta.PriorRunPaths) == 0 {
		b.WriteString("- **Prior Runs**: No prior coverage ledger was used. A single pass does not exhaust the target.\n")
	} else {
		fmt.Fprintf(&b, "- **Prior Runs Evaluated**: `%s`\n", strings.Join(meta.PriorRunPaths, "`, `"))
	}
	if meta.Profile == "quick" || len(meta.ScopePaths) > 0 ||
		meta.RunStatus == "incomplete" || counts["deferred"] > 0 || counts["out_of_scope"] > 0 {
		b.WriteString("\n> **Coverage Disclosure**: This run represents a partial pass. " +
			"See the Coverage Summary section for deferred, blocked, or out-of-scope units.\n")
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
	fmt.Fprintf(
		&b,
		"This audit confirmed **%d** source-grounded vulnerability record(s), "+
			"recorded **%d** blocked lead(s) requiring validation (`needs_validation`), "+
			"and refuted **%d** candidate hypothesis/hypotheses (`rejected`) across **%d** deterministic coverage unit(s).\n\n",
		len(confirmed), len(needsVal), len(rejected), len(units),
	)

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
	b.WriteString("## 5. Needs Validation Leads (Unresolved Blockers: No Severity Assigned)\n\n")
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

// BuildFindingsDetailMD generates FINDINGS-DETAIL.md for confirmed medium, high, and critical findings.
func BuildFindingsDetailMD(confirmed []validator.Finding) string {
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

// BuildNeedsValidationMD generates NEEDS-VALIDATION.md for unresolved blocked leads without severity.
func BuildNeedsValidationMD(needsVal []validator.Finding) string {
	var b strings.Builder
	b.WriteString("# Needs Validation Leads\n\n")
	b.WriteString("> These records represent source-grounded hypotheses blocked by a missing local capability " +
		"or unobserved deployment fact. They carry **no severity**.\n\n")
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

// BuildAdvisoryMD generates a standalone Coordinated Disclosure / GitHub Security Advisory (GHSA)
// Markdown document for a single confirmed finding.
func BuildAdvisoryMD(meta *store.RunMetadata, f validator.Finding) string {
	var b strings.Builder
	sev := "UNKNOWN"
	if f.Severity != nil && f.Severity.OverallSeverity != "" {
		sev = strings.ToUpper(f.Severity.OverallSeverity)
	}
	fmt.Fprintf(&b, "# Security Advisory: %s (`%s`)\n\n", f.Title, f.Fingerprint)

	b.WriteString("## Summary\n\n")
	if meta != nil {
		fmt.Fprintf(&b, "- **Repository**: `%s`\n", meta.Repo)
		fmt.Fprintf(&b, "- **Source Ref**: `%s` (dirty worktree: `%v`)\n", meta.SourceRef, meta.DirtyWorktree)
	}
	fmt.Fprintf(&b, "- **Severity**: `%s`\n", sev)
	if f.Confidence != nil && f.Confidence.Score != "" {
		fmt.Fprintf(&b, "- **Confidence**: `%s` (%s)\n", f.Confidence.Score, f.Confidence.Reason)
	}
	fmt.Fprintf(&b, "- **Root Cause**: %s\n", f.RootCause)
	fmt.Fprintf(&b, "- **Intended Behavior**: %s\n\n", f.IntendedBehavior)
	fmt.Fprintf(&b, "%s\n\n", f.Description)

	b.WriteString("## Affected Component and Source Trace\n\n")
	for idx, t := range f.Trace {
		fmt.Fprintf(&b, "%d. **[%s]** `%s:%d` (`%s`): %s\n", idx+1, t.Kind, t.File, t.Line, t.Scope, t.Description)
	}

	b.WriteString("\n## Supporting Evidence\n\n")
	for _, ev := range f.Evidence {
		fmt.Fprintf(&b, "- `%s:%d`: %s\n", ev.File, ev.Line, ev.Description)
	}
	if len(f.Conditions) > 0 {
		b.WriteString("\n## Preconditions\n\n")
		for _, c := range f.Conditions {
			fmt.Fprintf(&b, "- `%s`: %s\n", c.Kind, c.Description)
		}
	}

	if f.Execution != nil {
		b.WriteString("\n## Proof of Concept and Bounded Reproduction\n\n")
		fmt.Fprintf(&b, "- **Attacker Perspective**: %s\n", f.Execution.AttackerPerspective)
		b.WriteString("- **Payloads / Inputs**:\n")
		for _, p := range f.Execution.Payloads {
			fmt.Fprintf(&b, "  - `%s`\n", p)
		}
		b.WriteString("- **Reproduction Steps**:\n")
		for idx, inst := range f.Execution.Instructions {
			fmt.Fprintf(&b, "  %d. %s\n", idx+1, inst)
		}
		fmt.Fprintf(&b, "- **Observed Result**: %s\n", f.Execution.ObservedResult)
	}

	if f.Severity != nil {
		b.WriteString("\n## Impact and Severity\n\n")
		fmt.Fprintf(&b, "- **Likelihood**: `%s` (%s)\n", f.Severity.Likelihood.Score, f.Severity.Likelihood.Reason)
		fmt.Fprintf(&b, "- **Impact**: `%s` (%s)\n", f.Severity.Impact.Score, f.Severity.Impact.Reason)
		fmt.Fprintf(&b, "- **Overall Severity**: `%s`\n", f.Severity.OverallSeverity)
	}

	if f.Remediation != nil {
		b.WriteString("\n## Recommended Remediation\n\n")
		fmt.Fprintf(&b, "%s\n\n", f.Remediation.Strategy)
		for _, cc := range f.Remediation.CodeChanges {
			fmt.Fprintf(&b, "**File**: `%s`\n```\n%s\n```\n\n", cc.FileName, cc.FixedCode)
		}
	}

	return b.String()
}

func escapeTable(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.TrimSpace(s)
}
