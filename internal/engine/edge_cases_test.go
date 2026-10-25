package engine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/engine"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

func TestBudgetGatesScopeAndCatalog(t *testing.T) {
	// 1. CatalogQuery all 3 modes + error cases
	allFiles, err := engine.CatalogQuery("", "")
	if err != nil || allFiles == nil {
		t.Fatalf("CatalogQuery all failed: %v", err)
	}
	oneFile, err := engine.CatalogQuery("WEB-PROTOCOL-AND-AUTH.md", "")
	if err != nil || oneFile == nil {
		t.Fatalf("CatalogQuery file failed: %v", err)
	}
	oneBlock, err := engine.CatalogQuery("", "ATTACK-CLASSES.md#Injection")
	if err != nil || oneBlock == nil {
		t.Fatalf("CatalogQuery block failed: %v", err)
	}
	if _, err := engine.CatalogQuery("NONEXISTENT.md", ""); err == nil {
		t.Fatalf("expected error on unknown companion file")
	}
	if _, err := engine.CatalogQuery("", "ATTACK-CLASSES.md#Nonexistent"); err == nil {
		t.Fatalf("expected error on unknown block ref")
	}

	// 2. Target containment check (output_dir inside target without gitignore must fail)
	target := t.TempDir()
	_ = os.MkdirAll(filepath.Join(target, "src"), 0o755)
	_ = os.WriteFile(filepath.Join(target, "src", "a.go"), []byte("package src\n"), 0o644)
	_ = os.WriteFile(filepath.Join(target, "other.go"), []byte("package main\n"), 0o644)

	if _, err := engine.Init(engine.InitRequest{
		Target:    target,
		OutputDir: filepath.Join(target, "audit-out"),
	}); err == nil {
		t.Fatalf("expected output_dir inside unignored target to fail")
	}

	// 3. Pre-recon budget gate: budget=3 on standard profile marks run incomplete
	lowBudget := 3
	lowOut := t.TempDir()
	initLow, err := engine.Init(engine.InitRequest{
		Target:    target,
		OutputDir: lowOut,
		Profile:   "standard",
		Budget:    &lowBudget,
	})
	if err != nil {
		t.Fatalf("Init low budget failed: %v", err)
	}
	if initLow.Metadata.RunStatus != "incomplete" ||
		initLow.Metadata.IncompleteReason != "budget_cannot_fund_reconnaissance_and_reserves" {
		t.Fatalf("expected incomplete run from pre-recon budget gate, got %+v", initLow.Metadata)
	}
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: lowOut,
		Role:      "recon",
		AgentID:   "recon-1",
	}); err == nil {
		t.Fatalf("expected AssignAgent on incomplete run to fail")
	}

	// 4. Scoped run + hunter budget reserve deferral + critic missing units
	tightBudget := 7
	scopedOut := t.TempDir()
	if _, err := engine.Init(engine.InitRequest{
		Target:     target,
		OutputDir:  scopedOut,
		Profile:    "standard",
		ScopePaths: []string{"src"},
		Companions: []string{"WEB-PROTOCOL-AND-AUTH.md"},
		Budget:     &tightBudget,
	}); err != nil {
		t.Fatalf("Init scoped failed: %v", err)
	}
	if _, err := engine.WriteArchitecture(scopedOut, "# Scoped Architecture\nOnly src is in scope."); err != nil {
		t.Fatalf("WriteArchitecture: %v", err)
	}

	block := "ATTACK-CLASSES.md#Injection"
	if _, err := engine.SeedLedger(scopedOut, []engine.SeedUnitInput{
		{
			Surface: "A", Boundary: "A", Subsystem: "src", AttackClass: block,
			StartingPaths:            []string{"src/a.go"},
			OrdinaryAttackClassBlock: &block,
			SelectedCompanionBlocks:  []string{"AI-AND-LLM.md#Prompt and instruction boundaries"},
		},
	}); err == nil {
		t.Fatalf("expected SeedLedger to reject companion block from unselected companion file")
	}

	units, err := engine.SeedLedger(scopedOut, []engine.SeedUnitInput{
		{
			CanonicalRefs: validator.CanonicalRefs{
				Surface: "src/a.go#A", Boundary: "src/a.go#A", Subsystem: "src", AttackClass: block,
			},
			Surface: "A", Boundary: "A", Subsystem: "src", AttackClass: "Injection",
			StartingPaths: []string{"src/a.go"}, OrdinaryAttackClassBlock: &block,
		},
		{
			CanonicalRefs: validator.CanonicalRefs{
				Surface: "other.go#B", Boundary: "other.go#B", Subsystem: "root", AttackClass: block,
			},
			Surface: "B", Boundary: "B", Subsystem: "root", AttackClass: "Injection",
			StartingPaths: []string{"other.go"}, OrdinaryAttackClassBlock: &block,
		},
	})
	if err != nil || len(units) != 2 {
		t.Fatalf("SeedLedger scoped failed: %v", err)
	}

	for i := 1; i <= 4; i++ {
		if _, err := engine.AssignAgent(engine.AssignAgentRequest{
			OutputDir: scopedOut,
			Role:      "recon",
			AgentID:   "recon-" + string(rune('0'+i)),
		}); err != nil {
			t.Fatalf("AssignAgent recon-%d: %v", i, err)
		}
	}

	var plannedID string
	for _, u := range units {
		if u.Status == "planned" {
			plannedID = u.CoverageID
		}
	}
	deferRes, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir:   scopedOut,
		Role:        "hunter",
		AgentID:     "hunter-deferred",
		CoverageIDs: []string{plannedID},
	})
	if err != nil || len(deferRes.DeferredIDs) != 1 {
		t.Fatalf("expected hunter assignment to defer planned unit, got %+v err=%v", deferRes, err)
	}

	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: scopedOut,
		Role:      "critic",
		AgentID:   "critic-1",
	}); err != nil {
		t.Fatalf("AssignAgent critic-1: %v", err)
	}
	cRes, err := engine.SubmitCritic(scopedOut, "critic-1", "post_wave", engine.CriticResult{
		MissingUnits: []engine.CriticMissingUnit{
			{
				Surface:       "src/a.go#New",
				Boundary:      "src/a.go#New",
				Subsystem:     "src",
				AttackClass:   "ATTACK-CLASSES.md#Access control",
				StartingPaths: []string{"src/a.go"},
				Reason:        "Newly discovered endpoint",
			},
		},
		Stop: true,
	})
	if err != nil || cRes["added_units"] != 1 {
		t.Fatalf("SubmitCritic missing units failed: %+v err=%v", cRes, err)
	}

	if h, err := engine.FileHashSHA256(filepath.Join(target, "other.go")); err != nil || len(h) != 64 {
		t.Fatalf("FileHashSHA256 failed: %v", err)
	}

	incRender, err := engine.Render(engine.RenderRequest{
		OutputDir:        scopedOut,
		IncompleteReason: "budget_exhausted_in_scoped_run",
	})
	if err != nil || incRender.RunStatus != "incomplete" {
		t.Fatalf("Render incomplete run failed: %+v err=%v", incRender, err)
	}

	quickOut := t.TempDir()
	if _, err := engine.Init(engine.InitRequest{
		Target:    target,
		OutputDir: quickOut,
		Profile:   "quick",
	}); err != nil {
		t.Fatalf("Init quick: %v", err)
	}
	_, _ = engine.WriteArchitecture(quickOut, "# Quick Arch\nSummary.")
	qUnits, err := engine.SeedLedger(quickOut, []engine.SeedUnitInput{
		{
			CanonicalRefs: validator.CanonicalRefs{
				Surface: "src/a.go#A", Boundary: "src/a.go#A", Subsystem: "src", AttackClass: block,
			},
			Surface: "A", Boundary: "A", Subsystem: "src", AttackClass: "Injection",
			StartingPaths: []string{"src/a.go"}, OrdinaryAttackClassBlock: &block,
		},
	})
	if err != nil {
		t.Fatalf("SeedLedger quick: %v", err)
	}
	qCID := qUnits[0].CoverageID
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: quickOut, Role: "hunter", AgentID: "q-hunter", CoverageIDs: []string{qCID},
	}); err != nil {
		t.Fatalf("AssignAgent q-hunter: %v", err)
	}
	// Break-test: hunter omitting starting_path from reviewed_paths must fail
	if _, err := engine.SubmitHunter(quickOut, "q-hunter", engine.HunterStructuredResult{
		Units: []engine.HunterUnitResult{
			{
				CoverageID:    qCID,
				Disposition:   "covered",
				ReviewedPaths: []string{"other.go"},
				Checks: []validator.LocalCheck{{
					AgentID: "q-hunter", ReviewedPaths: []string{"other.go"}, Invariant: "inv", Method: "source", Result: "res",
				}},
			},
		},
	}); err == nil {
		t.Fatalf("expected SubmitHunter to reject reviewed_paths missing starting_path src/a.go")
	}
	// Break-test: hunter submitting check with wrong agent_id must fail
	if _, err := engine.SubmitHunter(quickOut, "q-hunter", engine.HunterStructuredResult{
		Units: []engine.HunterUnitResult{
			{
				CoverageID:    qCID,
				Disposition:   "covered",
				ReviewedPaths: []string{"src/a.go"},
				Checks: []validator.LocalCheck{{
					AgentID: "other-hunter", ReviewedPaths: []string{"src/a.go"}, Invariant: "inv", Method: "source", Result: "res",
				}},
			},
		},
	}); err == nil {
		t.Fatalf("expected SubmitHunter to reject check.agent_id != submitting hunter")
	}
	qCheck := validator.LocalCheck{
		AgentID: "q-hunter", ReviewedPaths: []string{"src/a.go"}, Invariant: "inv", Method: "source", Result: "res",
	}
	qTrace := []map[string]any{
		{"kind": "entrypoint", "file": "src/a.go", "line": 1, "scope": "A", "description": "d"},
	}
	if _, err := engine.SubmitHunter(quickOut, "q-hunter", engine.HunterStructuredResult{
		Units: []engine.HunterUnitResult{
			{
				CoverageID:            qCID,
				Disposition:           "candidate",
				ReviewedPaths:         []string{"src/a.go"},
				Checks:                []validator.LocalCheck{qCheck},
				CandidateFingerprints: []string{"FIND-Q1"},
			},
		},
		Candidates: []map[string]any{
			{
				"proposed_verdict":   "needs_validation",
				"fingerprint":        "FIND-Q1",
				"title":              "Lead",
				"description":        "Desc",
				"claimed_root_cause": "Root",
				"trace":              qTrace,
				"evidence":           []map[string]any{{"file": "src/a.go", "line": 1, "description": "e"}},
				"blockers":           []string{"Need env"},
				"validation_plan":    map[string]any{"local": "Check env"},
			},
		},
		Hardening: []string{"Enable strict headers"},
		Uncovered: []engine.UncoveredEntry{
			{
				Surface: "other.go#B", Boundary: "other.go#B", Subsystem: "root",
				AttackClass: block, StartingPaths: []string{"other.go"}, Reason: "new",
			},
		},
	}); err != nil {
		t.Fatalf("SubmitHunter quick: %v", err)
	}
	// Break-test: duplicate hunter submission must fail
	if _, err := engine.SubmitHunter(quickOut, "q-hunter", engine.HunterStructuredResult{}); err == nil {
		t.Fatalf("expected duplicate SubmitHunter from same agent_id to fail")
	}
	// Break-test: Render while UncoveredQueue is non-empty must fail until a critic processes it
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: quickOut, Role: "verifier", AgentID: "q-verifier", Fingerprint: "FIND-Q1",
	}); err != nil {
		t.Fatalf("AssignAgent q-verifier: %v", err)
	}
	if _, err := engine.SubmitVerifier(engine.VerifierSubmitRequest{
		OutputDir:   quickOut,
		AgentID:     "q-verifier",
		Fingerprint: "FIND-Q1",
		Decision:    "rejected",
		Record: map[string]any{
			"verdict":            "rejected",
			"fingerprint":        "FIND-Q1",
			"title":              "Lead",
			"description":        "Desc",
			"claimed_root_cause": "Root",
			"trace":              qTrace,
			"evidence":           []map[string]any{{"file": "src/a.go", "line": 1, "description": "e"}},
			"reason":             "Sanitized upstream",
		},
		Check: &validator.LocalCheck{
			ReviewedPaths: []string{"src/a.go"},
			Invariant:     "Verifier check",
			Method:        "invalid_method",
			Result:        "Refuted",
		},
	}); err == nil {
		t.Fatalf("expected SubmitVerifier to reject malformed local check with invalid method")
	}
	if _, err := engine.SubmitVerifier(engine.VerifierSubmitRequest{
		OutputDir:   quickOut,
		AgentID:     "q-verifier",
		Fingerprint: "FIND-Q1",
		Decision:    "rejected",
		Record: map[string]any{
			"verdict":            "rejected",
			"fingerprint":        "FIND-Q1",
			"title":              "Lead",
			"description":        "Desc",
			"claimed_root_cause": "Root",
			"trace":              qTrace,
			"evidence":           []map[string]any{{"file": "src/a.go", "line": 1, "description": "e"}},
			"reason":             "Sanitized upstream",
		},
		Check: &validator.LocalCheck{
			ReviewedPaths: []string{"src/a.go"},
			Invariant:     "Verifier check",
			Method:        "source",
			Result:        "Refuted",
		},
	}); err != nil {
		t.Fatalf("SubmitVerifier quick rejected: %v", err)
	}
	// Break-test: duplicate verifier submission must be rejected
	if _, err := engine.SubmitVerifier(engine.VerifierSubmitRequest{
		OutputDir:   quickOut,
		AgentID:     "q-verifier",
		Fingerprint: "FIND-Q1",
		Decision:    "rejected",
		Record:      map[string]any{},
	}); err == nil {
		t.Fatalf("expected duplicate SubmitVerifier from same agent_id to fail")
	}
	// Break-test: Render with unprocessed UncoveredQueue must fail before critic clears it
	if _, err := engine.Render(engine.RenderRequest{OutputDir: quickOut}); err == nil {
		t.Fatalf("expected Render to fail while UncoveredQueue has unprocessed hunter entries")
	}
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: quickOut, Role: "critic", AgentID: "q-critic",
	}); err != nil {
		t.Fatalf("AssignAgent q-critic: %v", err)
	}
	if _, err := engine.SubmitCritic(quickOut, "q-critic", "post_wave", engine.CriticResult{Stop: true}); err != nil {
		t.Fatalf("SubmitCritic q-critic: %v", err)
	}
	if _, err := engine.SubmitCritic(quickOut, "q-critic", "post_wave", engine.CriticResult{Stop: true}); err == nil {
		t.Fatalf("expected duplicate SubmitCritic from same agent_id to fail")
	}
	qRender, err := engine.Render(engine.RenderRequest{OutputDir: quickOut})
	if err != nil || qRender.RejectedCount != 1 || qRender.RunStatus != "complete" {
		t.Fatalf("Render quick complete failed: %+v err=%v", qRender, err)
	}

	// 5. Exhaustively test IsMaterialReplacement across all material vs non-material fields
	baseF := validator.Finding{
		Verdict:   "confirmed",
		Title:     "Original title",
		RootCause: "Missing tenant filter",
		Trace: []validator.TraceEntry{
			{Kind: "entrypoint", File: "a.go", Line: 1, Scope: "H", Description: "In"},
			{Kind: "sink", File: "a.go", Line: 2, Scope: "Q", Description: "Out"},
		},
		Execution: &validator.ExecutionBlock{
			Payloads:       []string{"p1"},
			ObservedResult: "leaked row",
		},
		Severity: &validator.SeverityBlock{
			Impact:          validator.ScoreReason{Score: "high", Reason: "r"},
			OverallSeverity: "high",
		},
	}
	nonMat := baseF
	nonMat.Title = "Clarified wording in title only"
	if engine.IsMaterialReplacement(baseF, nonMat) {
		t.Fatalf("expected title-only change to be non-material")
	}

	cRoot := baseF
	cRoot.RootCause = "Different root cause"
	if !engine.IsMaterialReplacement(baseF, cRoot) {
		t.Fatalf("expected RootCause change to be material")
	}

	cTraceLen := baseF
	cTraceLen.Trace = baseF.Trace[:1]
	if !engine.IsMaterialReplacement(baseF, cTraceLen) {
		t.Fatalf("expected Trace length change to be material")
	}
	cTraceElem := baseF
	cTraceElem.Trace = []validator.TraceEntry{
		baseF.Trace[0],
		{Kind: "sink", File: "a.go", Line: 99, Scope: "Q", Description: "Out"},
	}
	if !engine.IsMaterialReplacement(baseF, cTraceElem) {
		t.Fatalf("expected Trace line change to be material")
	}

	cExec := baseF
	cExec.Execution = &validator.ExecutionBlock{Payloads: []string{"p2"}, ObservedResult: "leaked row"}
	if !engine.IsMaterialReplacement(baseF, cExec) {
		t.Fatalf("expected Execution payload change to be material")
	}
	cExecNil := baseF
	cExecNil.Execution = nil
	if !engine.IsMaterialReplacement(baseF, cExecNil) {
		t.Fatalf("expected Execution nil change to be material")
	}

	cSev := baseF
	cSev.Severity = &validator.SeverityBlock{
		Impact:          validator.ScoreReason{Score: "critical", Reason: "r"},
		OverallSeverity: "critical",
	}
	if !engine.IsMaterialReplacement(baseF, cSev) {
		t.Fatalf("expected Severity change to be material")
	}
	cSevNil := baseF
	cSevNil.Severity = nil
	if !engine.IsMaterialReplacement(baseF, cSevNil) {
		t.Fatalf("expected Severity nil change to be material")
	}
}
