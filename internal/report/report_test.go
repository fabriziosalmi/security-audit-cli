package report

import (
	"strings"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/store"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

func TestMarkdownAndSARIFBuilders(t *testing.T) {
	budget := 12
	meta := &store.RunMetadata{
		RunID:            "run-1",
		Repo:             "demo",
		SourceRef:        "abc1234",
		Profile:          "standard",
		ScopePaths:       []string{"internal/api"},
		Budget:           &budget,
		AgentsSpent:      8,
		ExecutionPolicy:  "sandboxed-source-and-local-only",
		RunStatus:        "incomplete",
		IncompleteReason: "validation_budget_exhausted",
	}
	state := &store.InternalState{
		HardeningNotes: []string{"Add strict rate limiting on login"},
		FinalCleanDone: false,
	}
	confirmed := []validator.Finding{
		{
			Verdict:          "confirmed",
			Fingerprint:      "FIND-0001",
			Title:            "SQL Injection in Lookup",
			Description:      "Raw query concat",
			RootCause:        "Missing parameter binding",
			IntendedBehavior: "Parameterized query",
			Trace: []validator.TraceEntry{
				{Kind: "entrypoint", File: "api.go", Line: 10, Scope: "Handler", Description: "Input"},
				{Kind: "sink", File: "db.go", Line: 42, Scope: "Query", Description: "Exec"},
			},
			Evidence: []validator.EvidenceEntry{
				{File: "db.go", Line: 42, Description: "fmt.Sprintf SQL"},
			},
			Conditions: []validator.ConditionEntry{
				{Kind: "code", Description: "Always reachable"},
			},
			Severity: &validator.SeverityBlock{
				OverallSeverity: "high",
				Impact:          validator.ScoreReason{Score: "high", Reason: "DB read"},
				Likelihood:      validator.ScoreReason{Score: "high", Reason: "Unauthenticated"},
			},
			Confidence: &validator.ScoreReason{Score: "high", Reason: "Verified"},
			Execution: &validator.ExecutionBlock{
				AttackerPerspective: "HTTP client",
				Payloads:            []string{"' OR 1=1--"},
				Instructions:        []string{"Send GET /lookup"},
				ObservedResult:      "All rows returned",
			},
			Remediation: &validator.RemediationBlock{
				Strategy:    "Use placeholders",
				CodeChanges: []validator.CodeChange{{FileName: "db.go", FixedCode: "db.Query(q, arg)"}},
			},
		},
	}
	needsVal := []validator.Finding{
		{
			Verdict:          "needs_validation",
			Fingerprint:      "FIND-0002",
			Title:            "Potential SSRF behind proxy",
			Description:      "Depends on egress policy",
			ClaimedRootCause: "Unfiltered URL",
			Trace: []validator.TraceEntry{
				{Kind: "entrypoint", File: "webhook.go", Line: 15, Scope: "Send", Description: "URL"},
				{Kind: "sink", File: "webhook.go", Line: 30, Scope: "Do", Description: "Fetch"},
			},
			Evidence: []validator.EvidenceEntry{
				{File: "webhook.go", Line: 30, Description: "http.Get"},
			},
			Blockers: []string{"Egress firewall policy not in repo"},
			ValidationPlan: &validator.ValidationPlan{
				Local:      "Mock upstream",
				Deployment: "Inspect VPC egress rules",
			},
		},
	}

	counts := map[string]int{"covered": 3, "candidate": 2, "deferred": 1}
	repMD := BuildReportMD(meta, state, make([]validator.CoverageUnit, 6), counts, confirmed, needsVal, nil, []string{"FIND-0099"}, []string{"FIND-0098"})
	for _, want := range []string{
		"FIND-0001",
		"FIND-0002",
		"FIND-0099",
		"FIND-0098",
		"Coverage Disclosure",
		"Add strict rate limiting on login",
	} {
		if !strings.Contains(repMD, want) {
			t.Fatalf("REPORT.md missing %q", want)
		}
	}

	detMD := BuildFindingsDetailMD(confirmed)
	if !strings.Contains(detMD, "### Target-Neutral Bounded Reproduction") || !strings.Contains(detMD, "db.Query(q, arg)") {
		t.Fatalf("FINDINGS-DETAIL.md missing expected content: %s", detMD)
	}

	nvMD := BuildNeedsValidationMD(needsVal)
	if !strings.Contains(nvMD, "they carry **no severity**") && !strings.Contains(nvMD, "They carry **no severity**") {
		t.Fatalf("NEEDS-VALIDATION.md missing no-severity banner")
	}

	sarifBytes, err := BuildSARIF(confirmed)
	if err != nil || !strings.Contains(string(sarifBytes), `"level": "error"`) {
		t.Fatalf("BuildSARIF failed: %v\n%s", err, string(sarifBytes))
	}
}
