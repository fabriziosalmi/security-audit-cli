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

// seedTwoUnits prepares a run with two planned units and returns their ids.
func seedTwoUnits(t *testing.T) (outDir string, ids []string) {
	t.Helper()
	target := t.TempDir()
	for _, f := range []string{"a.go", "b.go"} {
		if err := os.WriteFile(filepath.Join(target, f), []byte("package main\nfunc F() {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outDir = filepath.Join(t.TempDir(), "run")
	if _, err := engine.Init(engine.InitRequest{Target: target, OutputDir: outDir, Profile: "quick"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := engine.WriteArchitecture(outDir, "# Arch\nTwo files."); err != nil {
		t.Fatalf("WriteArchitecture: %v", err)
	}
	atk := "ATTACK-CLASSES.md#Injection"
	var seed []engine.SeedUnitInput
	for _, f := range []string{"a.go", "b.go"} {
		seed = append(seed, engine.SeedUnitInput{
			CanonicalRefs:            validator.CanonicalRefs{Surface: f + "#F", Boundary: f + "#F", Subsystem: "core", AttackClass: atk},
			Surface:                  f,
			Boundary:                 f,
			Subsystem:                "core",
			AttackClass:              "Injection",
			StartingPaths:            []string{f},
			OrdinaryAttackClassBlock: &atk,
			SelectedCompanionBlocks:  []string{},
			ExcludedBlocks:           []validator.ExcludedBlock{},
		})
	}
	units, err := engine.SeedLedger(outDir, seed)
	if err != nil {
		t.Fatalf("SeedLedger: %v", err)
	}
	for _, u := range units {
		ids = append(ids, u.CoverageID)
	}
	return outDir, ids
}

// The example the hunter prompt shows must be accepted by SubmitHunter as
// is: prompt contract and validator cannot drift apart.
func TestHunterPromptExampleSubmitsAsIs(t *testing.T) {
	outDir, ids := seedTwoUnits(t)
	resp, err := engine.AssignAgent(engine.AssignAgentRequest{OutputDir: outDir, Role: "hunter", AgentID: "hunter-x", CoverageIDs: ids})
	if err != nil {
		t.Fatalf("AssignAgent: %v", err)
	}
	p := resp.Prompt
	for _, want := range []string{
		"proposed_verdict",                     // the candidate verdict field
		"`disposition`",                        // not the ledger's status
		"`candidate_fingerprints`",             // not result_fingerprints
		"the first item has kind `entrypoint`", // trace order
		"no leading or trailing whitespace",    // text rules
		"Every path in the unit's",             // check ownership
	} {
		if !strings.Contains(p, want) {
			t.Errorf("hunter prompt does not state %q", want)
		}
	}
	marker := "Example with every assigned unit covered by one source check"
	i := strings.Index(p, marker)
	if i < 0 {
		t.Fatal("hunter prompt has no example result")
	}
	rest := p[i:]
	start := strings.Index(rest, "```json\n")
	end := strings.Index(rest[start+8:], "\n```")
	if start < 0 || end < 0 {
		t.Fatal("example result is not a fenced json block")
	}
	var res engine.HunterStructuredResult
	dec := json.NewDecoder(strings.NewReader(rest[start+8 : start+8+end]))
	dec.DisallowUnknownFields() // every key in the example must exist in the submit type
	if err := dec.Decode(&res); err != nil {
		t.Fatalf("example does not decode into HunterStructuredResult: %v", err)
	}
	if _, err := engine.SubmitHunter(outDir, "hunter-x", res); err != nil {
		t.Fatalf("the example from the prompt is rejected by SubmitHunter: %v", err)
	}
}

func TestTextErrorsSayWhy(t *testing.T) {
	cases := map[string]string{
		"":                        "is empty",
		" padded":                 "has leading or trailing whitespace",
		"trailing\n":              "has leading or trailing whitespace",
		strings.Repeat("x", 5000): "is 5000 bytes, the limit is 4096",
		"​":                       "has no visible character",
		"bad \xff":                "is not valid UTF-8",
	}
	for in, want := range cases {
		if got := validator.TextProblem(in, 0); got != want {
			t.Errorf("TextProblem(%q) = %q, want %q", in, got, want)
		}
		if validator.IsVisibleText(in, 0) {
			t.Errorf("IsVisibleText(%q) is true, TextProblem says %q", in, want)
		}
	}
	if got := validator.TextProblem("fine text", 0); got != "" {
		t.Errorf("valid text reported as %q", got)
	}
	// and the reason reaches the submit error
	outDir, ids := seedTwoUnits(t)
	assign := engine.AssignAgentRequest{OutputDir: outDir, Role: "hunter", AgentID: "hunter-y", CoverageIDs: ids}
	if _, err := engine.AssignAgent(assign); err != nil {
		t.Fatal(err)
	}
	var units []engine.HunterUnitResult
	for i, id := range ids {
		f := []string{"a.go", "b.go"}[i]
		units = append(units, engine.HunterUnitResult{CoverageID: id, Disposition: "covered", ReviewedPaths: []string{f},
			Checks: []validator.LocalCheck{{
				AgentID: "hunter-y", ReviewedPaths: []string{f},
				Invariant: "ends with a newline\n", Method: "source", Result: "ok",
			}}})
	}
	_, err := engine.SubmitHunter(outDir, "hunter-y", engine.HunterStructuredResult{Units: units})
	if err == nil || !strings.Contains(err.Error(), "invariant: invalid text: has leading or trailing whitespace") {
		t.Fatalf("submit error does not say why: %v", err)
	}
}

func TestCandidateWithVerdictInsteadOfProposedVerdictGetsAHint(t *testing.T) {
	raw := map[string]any{"verdict": "confirmed", "fingerprint": "x:y"}
	var f validator.Finding
	b, _ := json.Marshal(raw)
	json.Unmarshal(b, &f)
	errs := validator.ValidateSingleFinding(f, raw, "candidates[0]", "", true)
	joined := strings.Join(errs, "; ")
	if !strings.Contains(joined, "names its verdict field proposed_verdict, not verdict") {
		t.Fatalf("no hint in: %s", joined)
	}
}
