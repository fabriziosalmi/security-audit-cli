package engine_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/engine"
	"github.com/fabriziosalmi/security-audit-cli/internal/mcp"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

func createDummyRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustWrite := func(rel, content string) {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("go.mod", "module example.com/webapp\n\ngo 1.23\n")
	mustWrite(
		"src/router.go",
		"package src\n\nfunc HandleUpdateUser(userID string, body string) {\n"+
			"\tRequireAuth(userID)\n\tExecUpdate(userID, body)\n}\n",
	)
	mustWrite(
		"src/auth.go",
		"package src\n\nfunc RequireAuth(userID string) bool {\n"+
			"\t// BUG: checks token presence but not resource owner\n"+
			"\treturn userID != \"\"\n}\n\nfunc ExecUpdate(userID, body string) {}\n",
	)
	return dir
}

func TestEndToEndAndBreakTests(t *testing.T) {
	repoDir := createDummyRepo(t)
	outDir := filepath.Join(t.TempDir(), "run-1")

	// 1. Test Pre-Reconnaissance Strict Budget Gate (Break-test: insufficient budget)
	lowBudget := 3
	lowOutDir := filepath.Join(t.TempDir(), "run-low-budget")
	lowResp, err := engine.Init(engine.InitRequest{
		Target:    repoDir,
		OutputDir: lowOutDir,
		Profile:   "standard",
		Budget:    &lowBudget,
	})
	if err != nil {
		t.Fatalf("Init with low budget failed: %v", err)
	}
	if lowResp.Metadata.RunStatus != "incomplete" || lowResp.Metadata.IncompleteReason != "budget_cannot_fund_reconnaissance_and_reserves" {
		t.Fatalf(
			"expected incomplete budget_cannot_fund_reconnaissance_and_reserves, got status=%q reason=%q",
			lowResp.Metadata.RunStatus, lowResp.Metadata.IncompleteReason,
		)
	}

	// 2. Normal Init
	initResp, err := engine.Init(engine.InitRequest{
		Target:    repoDir,
		OutputDir: outDir,
		Profile:   "standard",
	})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if initResp.Metadata.RunStatus != "in_progress" {
		t.Fatalf("expected in_progress, got %q", initResp.Metadata.RunStatus)
	}
	if initResp.RepoBrief.Languages["go"] != 2 {
		t.Fatalf("expected 2 go files in RepoBrief, got %v", initResp.RepoBrief.Languages)
	}

	// 3. Write Architecture (Break-test: >1100 words must fail)
	tooLong := strings.Repeat("word ", 1150)
	if _, err := engine.WriteArchitecture(outDir, tooLong); err == nil {
		t.Fatalf("expected WriteArchitecture to reject >1100 words")
	}
	archText := "# Architecture\n\nGo HTTP service with `src/router.go` entrypoint and `src/auth.go` authorization check."
	if _, err := engine.WriteArchitecture(outDir, archText); err != nil {
		t.Fatalf("WriteArchitecture failed: %v", err)
	}

	// 4. Seed Ledger (Break-test: non-existent starting_path must fail)
	badBlock := "ATTACK-CLASSES.md#Access control"
	_, err = engine.SeedLedger(outDir, []engine.SeedUnitInput{
		{
			CanonicalRefs: validator.CanonicalRefs{
				Surface:     "src/router.go#HandleUpdateUser",
				Boundary:    "src/auth.go#RequireAuth",
				Subsystem:   "src",
				AttackClass: "ATTACK-CLASSES.md#Access control",
			},
			Surface:                  "POST /users/:id",
			Boundary:                 "RequireAuth owner check",
			Subsystem:                "src",
			AttackClass:              "Access control",
			StartingPaths:            []string{"src/does-not-exist.go"},
			OrdinaryAttackClassBlock: &badBlock,
		},
	})
	if err == nil {
		t.Fatalf("expected SeedLedger to reject non-existent starting_path")
	}

	// Valid SeedLedger
	units, err := engine.SeedLedger(outDir, []engine.SeedUnitInput{
		{
			CanonicalRefs: validator.CanonicalRefs{
				Surface:     "src/router.go#HandleUpdateUser",
				Boundary:    "src/auth.go#RequireAuth",
				Subsystem:   "src",
				AttackClass: "ATTACK-CLASSES.md#Access control",
			},
			Surface:                  "POST /users/:id",
			Boundary:                 "RequireAuth owner check",
			Subsystem:                "src",
			AttackClass:              "Access control",
			StartingPaths:            []string{"src/router.go", "src/auth.go"},
			OrdinaryAttackClassBlock: &badBlock,
			SelectedCompanionBlocks:  []string{"WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF"},
			ExcludedBlocks: []validator.ExcludedBlock{
				{Block: "WEB-PROTOCOL-AND-AUTH.md#SAML signed-object and assertion binding", Reason: "No SAML used in repo"},
			},
		},
	})
	if err != nil {
		t.Fatalf("SeedLedger failed: %v", err)
	}
	if len(units) != 1 {
		t.Fatalf("expected 1 seeded unit, got %d", len(units))
	}
	covID := units[0].CoverageID

	// 5. Assign Hunter & Compile Prompt
	hunterAssign, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir:   outDir,
		Role:        "hunter",
		AgentID:     "hunter-wave1-a",
		CoverageIDs: []string{covID},
	})
	if err != nil {
		t.Fatalf("AssignAgent hunter failed: %v", err)
	}
	if !strings.Contains(hunterAssign.Prompt, "Artifact promotion procedure") ||
		!strings.Contains(hunterAssign.Prompt, "WEB-PROTOCOL-AND-AUTH.md#Core discipline") {
		t.Fatalf("hunter prompt missing required verbatim blocks")
	}

	// 6. Test OS Race-Safe Promotion (Break-test: symlink in scratch must be rejected!)
	symlinkPath := filepath.Join(hunterAssign.ScratchDir, "evil-link.txt")
	if err := os.Symlink("/etc/passwd", symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	realFile := filepath.Join(hunterAssign.ScratchDir, "repro-output.txt")
	if err := os.WriteFile(realFile, []byte("IDOR reproduced on dummy user B\n"), 0o600); err != nil {
		t.Fatalf("write scratch file: %v", err)
	}

	promRes, err := engine.PromoteArtifacts(outDir, "hunter-wave1-a", []string{"evil-link.txt", "repro-output.txt"}, 1024, 4096)
	if err != nil {
		t.Fatalf("PromoteArtifacts error: %v", err)
	}
	if promRes[0].Promoted {
		t.Fatalf("Break-test failed: symlink evil-link.txt was promoted!")
	}
	if !promRes[1].Promoted || promRes[1].ArtifactPath != "agents/hunter-wave1-a/artifacts/repro-output.txt" {
		t.Fatalf("expected repro-output.txt to be promoted, got %+v", promRes[1])
	}

	// 7. Hunter Submit (Break-test: hallucinated line 999 must fail!)
	artPath := promRes[1].ArtifactPath
	badCandidate := map[string]any{
		"proposed_verdict":  "confirmed",
		"fingerprint":       "idor.user-update.missing-owner-check",
		"title":             "Missing owner check in HandleUpdateUser",
		"description":       "Any authenticated user can update another user record.",
		"root_cause":        "RequireAuth only checks non-empty userID.",
		"intended_behavior": "RequireAuth must bind authenticated session to target userID.",
		"trace": []map[string]any{
			{"kind": "entrypoint", "file": "src/router.go", "line": 999, "scope": "HandleUpdateUser", "description": "Entry"},
		},
		"evidence": []map[string]any{
			{"file": "src/auth.go", "line": 4, "description": "Missing owner check"},
		},
		"conditions": []map[string]any{
			{"kind": "authentication_level", "description": "Authenticated lower-trust user"},
		},
		"execution": map[string]any{
			"attacker_perspective": "Authenticated user A targeting user B",
			"payloads":             []string{"userID=user-b"},
			"instructions":         []string{"Call HandleUpdateUser with user-b"},
			"observed_result":      "User B updated by User A",
		},
		"remediation": map[string]any{
			"strategy": "Compare session principal ID with target userID in RequireAuth.",
		},
		"severity": map[string]any{
			"likelihood":       map[string]any{"score": "high", "reason": "Direct call"},
			"impact":           map[string]any{"score": "high", "reason": "Cross-tenant write"},
			"overall_severity": "high",
		},
		"confidence": map[string]any{"score": "high", "reason": "Verified locally"},
	}

	_, err = engine.SubmitHunter(outDir, "hunter-wave1-a", engine.HunterStructuredResult{
		Units: []engine.HunterUnitResult{
			{
				CoverageID:    covID,
				Disposition:   "candidate",
				ReviewedPaths: []string{"src/router.go", "src/auth.go"},
				Checks: []validator.LocalCheck{{
					AgentID:       "hunter-wave1-a",
					ReviewedPaths: []string{"src/router.go", "src/auth.go"},
					Invariant:     "Owner check",
					Method:        "local",
					Result:        "Bypassed",
					Artifact:      &artPath,
				}},
				CandidateFingerprints: []string{"idor.user-update.missing-owner-check"},
				Unresolved:            []string{},
			},
		},
		Candidates: []map[string]any{badCandidate},
	})
	if err == nil {
		t.Fatalf("Break-test failed: SubmitHunter accepted hallucinated line 999 in src/router.go!")
	}

	// Fix line number to valid line 3 in src/router.go
	badCandidate["trace"] = []map[string]any{
		{"kind": "entrypoint", "file": "src/router.go", "line": 3, "scope": "HandleUpdateUser", "description": "Receives userID"},
		{"kind": "propagation", "file": "src/auth.go", "line": 3, "scope": "RequireAuth", "description": "Checks only non-empty"},
		{"kind": "sink", "file": "src/router.go", "line": 5, "scope": "ExecUpdate", "description": "Mutates target user"},
	}
	if _, err := engine.SubmitHunter(outDir, "hunter-wave1-a", engine.HunterStructuredResult{
		Units: []engine.HunterUnitResult{
			{
				CoverageID:    covID,
				Disposition:   "candidate",
				ReviewedPaths: []string{"src/router.go", "src/auth.go"},
				Checks: []validator.LocalCheck{{
					AgentID:       "hunter-wave1-a",
					ReviewedPaths: []string{"src/router.go", "src/auth.go"},
					Invariant:     "Owner check",
					Method:        "local",
					Result:        "Bypassed",
					Artifact:      &artPath,
				}},
				CandidateFingerprints: []string{"idor.user-update.missing-owner-check"},
				Unresolved:            []string{},
			},
		},
		Candidates: []map[string]any{badCandidate},
		Hardening:  []string{"Add structured audit logging on failed auth checks."},
	}); err != nil {
		t.Fatalf("SubmitHunter with valid candidate failed: %v", err)
	}

	// 8. Break-test: Phase 3 Verifier with same agent_id as Hunter MUST fail!
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir:   outDir,
		Role:        "verifier",
		AgentID:     "hunter-wave1-a",
		Fingerprint: "idor.user-update.missing-owner-check",
	}); err == nil {
		t.Fatalf("Break-test failed: AssignAgent allowed verifier_id == hunter_id!")
	}

	// Valid Phase 3 Verifier assignment
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir:   outDir,
		Role:        "verifier",
		AgentID:     "verifier-p3-1",
		Fingerprint: "idor.user-update.missing-owner-check",
	}); err != nil {
		t.Fatalf("AssignAgent verifier failed: %v", err)
	}

	// Break-test: overall_severity > impact.score MUST fail!
	confirmedRec := make(map[string]any)
	for k, v := range badCandidate {
		if k != "proposed_verdict" {
			confirmedRec[k] = v
		}
	}
	confirmedRec["verdict"] = "confirmed"
	confirmedRec["severity"] = map[string]any{
		"likelihood":       map[string]any{"score": "high", "reason": "Direct call"},
		"impact":           map[string]any{"score": "medium", "reason": "Limited scope"},
		"overall_severity": "critical", // Exceeds impact "medium"!
	}
	if _, err := engine.SubmitVerifier(engine.VerifierSubmitRequest{
		OutputDir:   outDir,
		AgentID:     "verifier-p3-1",
		Fingerprint: "idor.user-update.missing-owner-check",
		Decision:    "confirmed",
		Record:      confirmedRec,
	}); err == nil {
		t.Fatalf("Break-test failed: SubmitVerifier allowed overall_severity > impact.score!")
	}

	// Restore valid severity (overall_severity: "high" <= impact: "high")
	confirmedRec["severity"] = map[string]any{
		"likelihood":       map[string]any{"score": "high", "reason": "Direct call"},
		"impact":           map[string]any{"score": "high", "reason": "Cross-user write"},
		"overall_severity": "high",
	}
	if _, err := engine.SubmitVerifier(engine.VerifierSubmitRequest{
		OutputDir:   outDir,
		AgentID:     "verifier-p3-1",
		Fingerprint: "idor.user-update.missing-owner-check",
		Decision:    "confirmed",
		Record:      confirmedRec,
	}); err != nil {
		t.Fatalf("SubmitVerifier failed: %v", err)
	}

	// 9. Break-test: Render before Phase 5 record verification in standard profile MUST fail!
	if _, err := engine.Render(engine.RenderRequest{OutputDir: outDir}); err == nil {
		t.Fatalf("Break-test failed: Render succeeded before Phase 5 independent verification!")
	}

	// 10. Phase 5 Independent Record Verification (with material replacement gate!)
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir:   outDir,
		Role:        "record_verifier",
		AgentID:     "verifier-p3-1", // Same as Phase 3 verifier -> MUST fail!
		Fingerprint: "idor.user-update.missing-owner-check",
	}); err == nil {
		t.Fatalf("Break-test failed: AssignAgent allowed record_verifier == phase3_verifier!")
	}

	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir:   outDir,
		Role:        "record_verifier",
		AgentID:     "rec-verifier-p5-1",
		Fingerprint: "idor.user-update.missing-owner-check",
	}); err != nil {
		t.Fatalf("AssignAgent record_verifier failed: %v", err)
	}

	// Submit a material replacement (changing root_cause) -> must require ANOTHER fresh verifier!
	replacedRec := make(map[string]any)
	for k, v := range confirmedRec {
		replacedRec[k] = v
	}
	replacedRec["root_cause"] = "RequireAuth checks userID != empty string without comparing caller session principal."
	p5Res, err := engine.SubmitRecordVerifier(engine.RecordVerifySubmitRequest{
		OutputDir:   outDir,
		AgentID:     "rec-verifier-p5-1",
		Fingerprint: "idor.user-update.missing-owner-check",
		Decision:    "replace",
		Reason:      "Clarified root cause wording",
		Record:      replacedRec,
	})
	if err != nil {
		t.Fatalf("SubmitRecordVerifier replace failed: %v", err)
	}
	if reqFresh, _ := p5Res["requires_another_fresh_verify"].(bool); !reqFresh {
		t.Fatalf("Break-test failed: material Phase 5 replacement did not require another fresh verifier!")
	}

	// Assign second fresh Phase 5 verifier to confirm the material replacement
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir:   outDir,
		Role:        "record_verifier",
		AgentID:     "rec-verifier-p5-2",
		Fingerprint: "idor.user-update.missing-owner-check",
	}); err != nil {
		t.Fatalf("AssignAgent second record_verifier failed: %v", err)
	}
	if _, err := engine.SubmitRecordVerifier(engine.RecordVerifySubmitRequest{
		OutputDir:   outDir,
		AgentID:     "rec-verifier-p5-2",
		Fingerprint: "idor.user-update.missing-owner-check",
		Decision:    "verified",
	}); err != nil {
		t.Fatalf("second SubmitRecordVerifier failed: %v", err)
	}

	// 11. Render Phase 6 Reports and SARIF
	renderRes, err := engine.Render(engine.RenderRequest{OutputDir: outDir})
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}
	if renderRes.RunStatus != "complete" || renderRes.ConfirmedCount != 1 {
		t.Fatalf("unexpected RenderResponse: %+v", renderRes)
	}
	for _, p := range []string{renderRes.ReportPath, renderRes.FindingsDetailPath, renderRes.NeedsValidationPath, renderRes.SarifPath} {
		st, err := os.Stat(p)
		if err != nil || st.Size() == 0 {
			t.Fatalf("expected non-empty rendered artifact %s", p)
		}
	}

	// 12. Test MCP JSON-RPC 2.0 Stdio Parity (tools/list and tools/call)
	var inBuf, outBuf bytes.Buffer
	inBuf.WriteString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	valArgs, _ := json.Marshal(map[string]any{"output_dir": outDir})
	callReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "sec_audit_validate",
			"arguments": json.RawMessage(valArgs),
		},
	})
	inBuf.Write(append(callReq, '\n'))

	if err := mcp.ServeStdio(&inBuf, &outBuf); err != nil {
		t.Fatalf("MCP ServeStdio failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON-RPC responses, got %d: %s", len(lines), outBuf.String())
	}
	if !strings.Contains(lines[0], `"sec_audit_init"`) || !strings.Contains(lines[1], `\"valid\": true`) {
		t.Fatalf("unexpected MCP responses:\n%s", outBuf.String())
	}

	// 13. Test Critic Reassignment & Attempt Archiving
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: outDir,
		Role:      "critic",
		AgentID:   "critic-wave1",
	}); err != nil {
		t.Fatalf("AssignAgent critic failed: %v", err)
	}
	criticRes, err := engine.SubmitCritic(outDir, "critic-wave1", "post_wave", engine.CriticResult{
		ReassignIDs:        []string{covID},
		ReassignmentReason: "Verify sibling batch update path in src/router.go",
		Stop:               false,
	})
	if err != nil {
		t.Fatalf("SubmitCritic failed: %v", err)
	}
	if criticRes["reassigned_units"] != 1 || criticRes["current_wave"] != 2 {
		t.Fatalf("expected 1 reassigned unit and wave 2, got %+v", criticRes)
	}
	// Break-test: Reassigning wave 2 unit to the wave 1 hunter MUST fail!
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir:   outDir,
		Role:        "hunter",
		AgentID:     "hunter-wave1-a",
		CoverageIDs: []string{covID},
	}); err == nil {
		t.Fatalf("Break-test failed: AssignAgent allowed reusing wave 1 hunter on wave 2 reassigned unit!")
	}
}
