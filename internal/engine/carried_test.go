package engine_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/engine"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

const (
	fpCarriedConfirmed = "api.go:Handle:carried-confirmed"
	fpCarriedLead      = "deploy/net.conf:carried-lead-outside-scope"
	fpThisRunOrphan    = "api.go:Handle:found-this-run-not-on-a-unit"
)

func confirmedRecordFor(fp string) map[string]any {
	return map[string]any{
		"verdict":           "confirmed",
		"fingerprint":       fp,
		"title":             "Handle trusts the caller",
		"description":       "Handle acts on input without checking who sent it.",
		"root_cause":        "Handle has no authorization check.",
		"intended_behavior": "Handle must check the caller before acting.",
		"trace": []map[string]any{
			{"kind": "entrypoint", "file": "api.go", "line": 2, "scope": "Handle", "description": "Receives input"},
			{"kind": "sink", "file": "api.go", "line": 3, "scope": "Handle", "description": "Acts on it"},
		},
		"evidence": []map[string]any{{"file": "api.go", "line": 3, "description": "No check before the action"}},
		"conditions": []map[string]any{
			{"kind": "authentication_level", "description": "Any caller"},
		},
		"execution": map[string]any{
			"attacker_perspective": "Unauthenticated caller",
			"payloads":             []string{"x"},
			"instructions":         []string{"Call Handle with x"},
			"observed_result":      "Handle acted on x",
		},
		"remediation": map[string]any{"strategy": "Check the caller in Handle."},
		"severity": map[string]any{
			"likelihood":       map[string]any{"score": "high", "reason": "Direct call"},
			"impact":           map[string]any{"score": "medium", "reason": "Unauthorized action"},
			"overall_severity": "medium",
		},
		"confidence": map[string]any{"score": "high", "reason": "Read in source"},
	}
}

func leadRecordFor(fp string) map[string]any {
	return map[string]any{
		"verdict":            "needs_validation",
		"fingerprint":        fp,
		"title":              "Firewall rule may miss a path",
		"description":        "The output rule may not cover every destination.",
		"claimed_root_cause": "The deny list is incomplete.",
		"trace": []map[string]any{
			{"kind": "sink", "file": "deploy/net.conf", "line": 1, "scope": "output chain", "description": "Deny list"},
		},
		"evidence":        []map[string]any{{"file": "deploy/net.conf", "line": 1, "description": "Deny list"}},
		"blockers":        []string{"Needs the deployed host"},
		"validation_plan": map[string]any{"deployment": "Inspect the host ruleset"},
	}
}

func rejectedRecordFor(lead map[string]any) map[string]any {
	return map[string]any{
		"verdict":            "rejected",
		"fingerprint":        lead["fingerprint"],
		"title":              lead["title"],
		"description":        lead["description"],
		"claimed_root_cause": lead["claimed_root_cause"],
		"trace":              lead["trace"],
		"evidence":           lead["evidence"],
		"reason":             "The default policy drops every destination the deny list does not name.",
	}
}

// carriedRun reproduces the run6 shape: a quick run with scope_paths whose
// prior run left a confirmed finding in scope and a needs_validation lead
// outside scope_paths (deploy/). Its only hunter covers its unit and lists
// neither carried fingerprint, so no unit ever links them.
func carriedRun(t *testing.T, extraCandidates ...map[string]any) string {
	t.Helper()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "api.go"), []byte("package api\nfunc Handle(x string) {\n\tdo(x)\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(target, "deploy"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "deploy", "net.conf"), []byte("deny output to 10.0.0.0/8\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	prior := filepath.Join(t.TempDir(), "prior-run")
	if err := os.MkdirAll(prior, 0o700); err != nil {
		t.Fatal(err)
	}
	priorFindings, _ := json.Marshal([]map[string]any{confirmedRecordFor(fpCarriedConfirmed), leadRecordFor(fpCarriedLead)})
	if err := os.WriteFile(filepath.Join(prior, "findings.json"), priorFindings, 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "run")
	initResp, err := engine.Init(engine.InitRequest{
		Target: target, OutputDir: out, Profile: "quick",
		ScopePaths: []string{"api.go"}, PriorRunDirs: []string{prior},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(initResp.PriorCarryovers) != 1 || len(initResp.PriorCarryovers[0].CarriedConfirmed) != 1 ||
		len(initResp.PriorCarryovers[0].CarriedNeedsValidation) != 1 {
		t.Fatalf("init should carry one confirmed and one lead, got %+v", initResp.PriorCarryovers)
	}
	if _, err := engine.WriteArchitecture(out, "# Arch\nOne handler, one firewall file."); err != nil {
		t.Fatal(err)
	}
	block := "ATTACK-CLASSES.md#Injection"
	units, err := engine.SeedLedger(out, []engine.SeedUnitInput{{
		Surface: "api.go#Handle", Boundary: "api.go#Handle", Subsystem: "api", AttackClass: block,
		StartingPaths: []string{"api.go"}, OrdinaryAttackClassBlock: &block,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: out, Role: "hunter", AgentID: "hunter-1", CoverageIDs: []string{units[0].CoverageID},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.SubmitHunter(out, "hunter-1", engine.HunterStructuredResult{
		Units: []engine.HunterUnitResult{{
			CoverageID: units[0].CoverageID, Disposition: "covered", ReviewedPaths: []string{"api.go"},
			Checks: []validator.LocalCheck{{
				AgentID: "hunter-1", ReviewedPaths: []string{"api.go"},
				Invariant: "Input reaches no sink unchecked", Method: "source", Result: "carried finding still present",
			}},
		}},
		Candidates: extraCandidates,
	}); err != nil {
		t.Fatal(err)
	}
	closeCoverage(t, out, "quick", "critic-1")
	return out
}

func verify(t *testing.T, out, agentID, fp, decision string, record map[string]any) {
	t.Helper()
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: out, Role: "verifier", AgentID: agentID, Fingerprint: fp,
	}); err != nil {
		t.Fatalf("AssignAgent %s: %v", agentID, err)
	}
	if _, err := engine.SubmitVerifier(engine.VerifierSubmitRequest{
		OutputDir: out, AgentID: agentID, Fingerprint: fp, Decision: decision, Record: record,
	}); err != nil {
		t.Fatalf("SubmitVerifier %s: %v", agentID, err)
	}
}

// Regression (run6): carried fingerprints decided by Phase 3 verifiers but
// listed by no unit made ValidateCrossFileConsistency refuse every render.
// Removing the carried exemption in ValidateCrossFileConsistency or
// ValidateRunWithGate makes this test fail with "is not referenced by any
// coverage unit result_fingerprints".
func TestCarriedFingerprintsDecidedByVerifiersRender(t *testing.T) {
	out := carriedRun(t)

	// The gate for undecided carried candidates stays: status asks for a
	// verifier for each one and render refuses until they are decided.
	st, err := engine.Status(engine.StatusRequest{OutputDir: out})
	if err != nil {
		t.Fatal(err)
	}
	if st.ReadyToRender || len(st.UnvalidatedCandidates) != 2 {
		t.Fatalf("status should ask for verifiers of both carried fingerprints, got %+v", st)
	}
	if _, err := engine.Render(engine.RenderRequest{OutputDir: out}); err == nil ||
		!strings.Contains(err.Error(), "unvalidated candidates") {
		t.Fatalf("render before the verifiers must refuse on unvalidated candidates, got %v", err)
	}

	verify(t, out, "verifier-confirmed", fpCarriedConfirmed, "confirmed", confirmedRecordFor(fpCarriedConfirmed))
	verify(t, out, "verifier-lead", fpCarriedLead, "rejected", rejectedRecordFor(leadRecordFor(fpCarriedLead)))

	val, err := engine.ValidateRun(out)
	if err != nil {
		t.Fatal(err)
	}
	if valid, _ := val["valid"].(bool); !valid {
		t.Fatalf("a run whose carried fingerprints were decided by verifiers must validate, got %v", val)
	}
	st, err = engine.Status(engine.StatusRequest{OutputDir: out})
	if err != nil || !st.ReadyToRender {
		t.Fatalf("status should be ready to render, got %+v err=%v", st, err)
	}
	r, err := engine.Render(engine.RenderRequest{OutputDir: out})
	if err != nil {
		t.Fatalf("render after the verifiers decided every carried fingerprint: %v", err)
	}
	if r.RunStatus != "complete" || r.ConfirmedCount != 1 || r.RejectedCount != 1 {
		t.Fatalf("expected a complete run with 1 confirmed and 1 rejected, got %+v", r)
	}

	rep, err := os.ReadFile(r.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	report := string(rep)
	for _, want := range []string{
		"### Carried From Prior Runs",
		"| `" + fpCarriedConfirmed + "` |",
		"| `confirmed` | `confirmed` | `verifier-confirmed` | no |",
		"| `" + fpCarriedLead + "` |",
		"| `needs_validation` | `rejected` | `verifier-lead` | no |",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("REPORT.md should contain %q, got:\n%s", want, report)
		}
	}
}

// A fingerprint first found in this run must still be listed by a unit. A
// hunter that submits a candidate without putting it on any unit leaves a
// finding that validate and render refuse, even beside carried findings that
// pass, and the error names only that fingerprint.
func TestFingerprintOfThisRunNotOnAUnitStillFails(t *testing.T) {
	orphan := confirmedRecordFor(fpThisRunOrphan)
	delete(orphan, "verdict")
	orphan["proposed_verdict"] = "confirmed"
	out := carriedRun(t, orphan)

	verify(t, out, "verifier-confirmed", fpCarriedConfirmed, "confirmed", confirmedRecordFor(fpCarriedConfirmed))
	verify(t, out, "verifier-lead", fpCarriedLead, "rejected", rejectedRecordFor(leadRecordFor(fpCarriedLead)))
	verify(t, out, "verifier-orphan", fpThisRunOrphan, "confirmed", confirmedRecordFor(fpThisRunOrphan))

	val, err := engine.ValidateRun(out)
	if err != nil {
		t.Fatal(err)
	}
	errs, _ := val["finding_errors"].([]string)
	if valid, _ := val["valid"].(bool); valid || len(errs) != 1 ||
		!strings.Contains(errs[0], fpThisRunOrphan) ||
		!strings.Contains(errs[0], "is not referenced by any coverage unit result_fingerprints") {
		t.Fatalf("only the fingerprint of this run on no unit must fail validation, got %v", val)
	}
	if _, err := engine.Render(engine.RenderRequest{OutputDir: out}); err == nil ||
		!strings.Contains(err.Error(), fpThisRunOrphan) {
		t.Fatalf("render must refuse a fingerprint of this run on no unit, got %v", err)
	}
}
