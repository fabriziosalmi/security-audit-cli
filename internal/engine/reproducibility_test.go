package engine_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/engine"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

func TestBitForBitReproducibility(t *testing.T) {
	target := t.TempDir()
	_ = os.MkdirAll(filepath.Join(target, "src"), 0o755)
	_ = os.WriteFile(filepath.Join(target, "src", "auth.go"), []byte("package src\nfunc Login() {}\n"), 0o644)

	priorDir := t.TempDir()
	mkPrior := func(fp, title, root string) string {
		return `{"verdict":"confirmed","fingerprint":"` + fp + `","title":"` + title + `",` +
			`"description":"D","root_cause":"` + root + `","intended_behavior":"I",` +
			`"trace":[{"kind":"sink","file":"src/auth.go","line":1,"scope":"S","description":"D"}],` +
			`"evidence":[{"file":"src/auth.go","line":1,"description":"E"}],"conditions":[],` +
			`"execution":{"attacker_perspective":"A","payloads":["p"],"instructions":["i"],"observed_result":"o"},` +
			`"remediation":{"strategy":"s","code_changes":[]},` +
			`"severity":{"likelihood":{"score":"low","reason":"r"},"impact":{"score":"low","reason":"r"},` +
			`"overall_severity":"low"},"confidence":{"score":"high","reason":"r"}}`
	}
	priorFindings := "[" + mkPrior("FIND-C", "T3", "R3") + "," +
		mkPrior("FIND-A", "T1", "R1") + "," +
		mkPrior("FIND-B", "T2", "R2") + "]"
	_ = os.WriteFile(filepath.Join(priorDir, "findings.json"), []byte(priorFindings), 0o600)

	runDeterministicPass := func(outDir string) (*engine.RenderResponse, string) {
		if _, err := engine.Init(engine.InitRequest{
			Target:       target,
			OutputDir:    outDir,
			Profile:      "quick",
			PriorRunDirs: []string{priorDir},
		}); err != nil {
			t.Fatalf("Init: %v", err)
		}
		if _, err := engine.WriteArchitecture(outDir, "# Deterministic Architecture\nZero variance."); err != nil {
			t.Fatalf("WriteArchitecture: %v", err)
		}
		block := "ATTACK-CLASSES.md#Access control"
		units, err := engine.SeedLedger(outDir, []engine.SeedUnitInput{
			{
				CanonicalRefs: validator.CanonicalRefs{
					Surface: "src/auth.go#Login", Boundary: "src/auth.go#Login",
					Subsystem: "src", AttackClass: block,
				},
				Surface: "Login", Boundary: "Login", Subsystem: "src", AttackClass: "Access control",
				StartingPaths: []string{"src/auth.go"}, OrdinaryAttackClassBlock: &block,
			},
		})
		if err != nil {
			t.Fatalf("SeedLedger: %v", err)
		}
		cid := units[0].CoverageID
		assignRes, err := engine.AssignAgent(engine.AssignAgentRequest{
			OutputDir: outDir, Role: "hunter", AgentID: "hunter-1", CoverageIDs: []string{cid},
		})
		if err != nil {
			t.Fatalf("AssignAgent: %v", err)
		}
		normPrompt := strings.ReplaceAll(assignRes.Prompt, outDir, "<OUT>")

		hCheck := validator.LocalCheck{
			AgentID: "hunter-1", ReviewedPaths: []string{"src/auth.go"},
			Invariant: "Auth check", Method: "source", Result: "Enforced",
		}
		if _, err := engine.SubmitHunter(outDir, "hunter-1", engine.HunterStructuredResult{
			Units: []engine.HunterUnitResult{
				{
					CoverageID:            cid,
					Disposition:           "candidate",
					ReviewedPaths:         []string{"src/auth.go"},
					Checks:                []validator.LocalCheck{hCheck},
					CandidateFingerprints: []string{"FIND-A", "FIND-B", "FIND-C"},
				},
			},
		}); err != nil {
			t.Fatalf("SubmitHunter: %v", err)
		}
		for _, fp := range []string{"FIND-A", "FIND-B", "FIND-C"} {
			vid := "verifier-" + strings.ToLower(fp)
			if _, err := engine.AssignAgent(engine.AssignAgentRequest{
				OutputDir: outDir, Role: "verifier", AgentID: vid, Fingerprint: fp,
			}); err != nil {
				t.Fatalf("AssignAgent %s: %v", vid, err)
			}
			trace := []map[string]any{
				{"kind": "sink", "file": "src/auth.go", "line": 1, "scope": "S", "description": "D"},
			}
			if _, err := engine.SubmitVerifier(engine.VerifierSubmitRequest{
				OutputDir: outDir, AgentID: vid, Fingerprint: fp, Decision: "rejected",
				Record: map[string]any{
					"verdict": "rejected", "fingerprint": fp, "title": "Fixed", "description": "D",
					"claimed_root_cause": "R",
					"trace":              trace,
					"evidence":           []map[string]any{{"file": "src/auth.go", "line": 1, "description": "E"}},
					"reason":             "Patched in current commit",
				},
			}); err != nil {
				t.Fatalf("SubmitVerifier %s: %v", vid, err)
			}
		}
		rRes, err := engine.Render(engine.RenderRequest{OutputDir: outDir})
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		return rRes, normPrompt
	}

	resA, promptA := runDeterministicPass(filepath.Join(t.TempDir(), "run-deterministic"))
	resB, promptB := runDeterministicPass(filepath.Join(t.TempDir(), "run-deterministic"))

	if promptA != promptB {
		t.Fatalf("Reproducibility failure: compiled hunter prompts differ across identical runs!")
	}
	for _, artifact := range []string{
		"architecture.md",
		"coverage-ledger.json",
		"findings.json",
		"REPORT.md",
		"FINDINGS-DETAIL.md",
		"NEEDS-VALIDATION.md",
		"findings.sarif",
	} {
		hashA := resA.ArtifactHashes[artifact]
		hashB := resB.ArtifactHashes[artifact]
		if hashA == "" || hashA != hashB {
			t.Fatalf("Reproducibility failure on %s: %s vs %s", artifact, hashA, hashB)
		}
	}
}

func TestDraconianAdversarialMatrixAndManifestTamper(t *testing.T) {
	target := t.TempDir()
	_ = os.MkdirAll(filepath.Join(target, "src"), 0o755)
	_ = os.WriteFile(filepath.Join(target, "src", "api.go"), []byte("package src\nfunc Handle() {}\nfunc Sink() {}\n"), 0o644)

	outDir := filepath.Join(t.TempDir(), "run-adv")
	if _, err := engine.Init(engine.InitRequest{
		Target:     target,
		OutputDir:  outDir,
		Profile:    "standard",
		Companions: []string{"WEB-PROTOCOL-AND-AUTH.md"},
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := engine.WriteArchitecture(outDir, "# Arch\nBoundaries."); err != nil {
		t.Fatalf("WriteArchitecture: %v", err)
	}
	block := "ATTACK-CLASSES.md#Injection"
	units, err := engine.SeedLedger(outDir, []engine.SeedUnitInput{
		{
			Surface: "src/api.go#Handle", Boundary: "src/api.go#Handle",
			Subsystem: "src", AttackClass: block,
			StartingPaths: []string{"src/api.go"}, OrdinaryAttackClassBlock: &block,
		},
	})
	if err != nil {
		t.Fatalf("SeedLedger: %v", err)
	}
	cid := units[0].CoverageID

	// 1. Assign hunter-1, promote valid artifact, submit 2 candidates (FIND-CONF and FIND-NV)
	hAssign, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: outDir, Role: "hunter", AgentID: "hunter-1", CoverageIDs: []string{cid},
	})
	if err != nil {
		t.Fatalf("AssignAgent hunter-1: %v", err)
	}
	_ = os.WriteFile(filepath.Join(hAssign.ScratchDir, "poc.txt"), []byte("local sandbox trace output\n"), 0o600)
	prom, err := engine.PromoteArtifacts(outDir, "hunter-1", []string{"poc.txt"}, 0, 0)
	if err != nil || !prom[0].Promoted {
		t.Fatalf("PromoteArtifacts: %+v err=%v", prom, err)
	}
	artRel := prom[0].ArtifactPath

	trace := []map[string]any{
		{"kind": "entrypoint", "file": "src/api.go", "line": 2, "scope": "Handle", "description": "In"},
		{"kind": "sink", "file": "src/api.go", "line": 3, "scope": "Sink", "description": "Out"},
	}
	ev := []map[string]any{{"file": "src/api.go", "line": 3, "description": "Sink call"}}

	candConf := map[string]any{
		"proposed_verdict":  "confirmed",
		"fingerprint":       "FIND-CONF",
		"title":             "Confirmed Injection",
		"description":       "Desc",
		"root_cause":        "Unescaped input",
		"intended_behavior": "Escaped input",
		"trace":             trace,
		"evidence":          ev,
		"conditions":        []map[string]any{{"kind": "authentication_level", "description": "Anon"}},
		"execution": map[string]any{
			"attacker_perspective": "Client",
			"payloads":             []string{"p1"},
			"instructions":         []string{"run"},
			"observed_result":      "injected",
		},
		"remediation": map[string]any{
			"strategy":     "Escape",
			"code_changes": []map[string]any{{"file_name": "src/api.go", "fixed_code": "func Sink() {}"}},
		},
		"severity": map[string]any{
			"likelihood":       map[string]any{"score": "high", "reason": "r"},
			"impact":           map[string]any{"score": "high", "reason": "r"},
			"overall_severity": "high",
		},
		"confidence": map[string]any{"score": "high", "reason": "r"},
	}
	candNV := map[string]any{
		"proposed_verdict":   "needs_validation",
		"fingerprint":        "FIND-NV",
		"title":              "Blocked Lead",
		"description":        "Desc",
		"claimed_root_cause": "Missing WAF header",
		"trace":              trace,
		"evidence":           ev,
		"blockers":           []string{"Needs prod proxy config"},
		"validation_plan":    map[string]any{"deployment": "Inspect edge config"},
	}

	if _, err := engine.SubmitHunter(outDir, "hunter-1", engine.HunterStructuredResult{
		Units: []engine.HunterUnitResult{
			{
				CoverageID:    cid,
				Disposition:   "candidate",
				ReviewedPaths: []string{"src/api.go"},
				Checks: []validator.LocalCheck{
					{
						AgentID: "hunter-1", ReviewedPaths: []string{"src/api.go"},
						Invariant: "inv", Method: "local", Result: "ok", Artifact: &artRel,
					},
				},
				CandidateFingerprints: []string{"FIND-CONF", "FIND-NV"},
			},
		},
		Candidates: []map[string]any{candConf, candNV},
	}); err != nil {
		t.Fatalf("SubmitHunter: %v", err)
	}

	// 2. Break-test: Phase 3 Verifier assigned to FIND-CONF cannot submit decision for FIND-NV
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: outDir, Role: "verifier", AgentID: "ver-conf", Fingerprint: "FIND-CONF",
	}); err != nil {
		t.Fatalf("AssignAgent ver-conf: %v", err)
	}
	nvRec := make(map[string]any)
	for k, v := range candNV {
		if k != "proposed_verdict" {
			nvRec[k] = v
		}
	}
	nvRec["verdict"] = "needs_validation"
	if _, err := engine.SubmitVerifier(engine.VerifierSubmitRequest{
		OutputDir: outDir, AgentID: "ver-conf", Fingerprint: "FIND-NV", Decision: "needs_validation", Record: nvRec,
	}); err == nil {
		t.Fatalf("expected verifier assigned to FIND-CONF to be rejected when submitting for FIND-NV")
	}

	// Valid Phase 3 submissions for FIND-CONF and FIND-NV
	confRec := make(map[string]any)
	for k, v := range candConf {
		if k != "proposed_verdict" {
			confRec[k] = v
		}
	}
	confRec["verdict"] = "confirmed"
	if _, err := engine.SubmitVerifier(engine.VerifierSubmitRequest{
		OutputDir: outDir, AgentID: "ver-conf", Fingerprint: "FIND-CONF", Decision: "confirmed", Record: confRec,
	}); err != nil {
		t.Fatalf("SubmitVerifier FIND-CONF: %v", err)
	}
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: outDir, Role: "verifier", AgentID: "ver-nv", Fingerprint: "FIND-NV",
	}); err != nil {
		t.Fatalf("AssignAgent ver-nv: %v", err)
	}
	if _, err := engine.SubmitVerifier(engine.VerifierSubmitRequest{
		OutputDir: outDir, AgentID: "ver-nv", Fingerprint: "FIND-NV", Decision: "needs_validation", Record: nvRec,
	}); err != nil {
		t.Fatalf("SubmitVerifier FIND-NV: %v", err)
	}

	// 3. Phase 5: Test Promotion from needs_validation -> confirmed (material replacement!)
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: outDir, Role: "record_verifier", AgentID: "rec-nv-1", Fingerprint: "FIND-NV",
	}); err != nil {
		t.Fatalf("AssignAgent rec-nv-1: %v", err)
	}
	// Break-test: rec-nv-1 assigned to FIND-NV cannot verify FIND-CONF
	if _, err := engine.SubmitRecordVerifier(engine.RecordVerifySubmitRequest{
		OutputDir: outDir, AgentID: "rec-nv-1", Fingerprint: "FIND-CONF", Decision: "verified",
	}); err == nil {
		t.Fatalf("expected record_verifier assigned to FIND-NV to be rejected on FIND-CONF")
	}
	// Promote FIND-NV to confirmed -> must set requires_another_fresh_verify = true
	promotedNV := make(map[string]any)
	for k, v := range confRec {
		promotedNV[k] = v
	}
	promotedNV["fingerprint"] = "FIND-NV"
	p5Prom, err := engine.SubmitRecordVerifier(engine.RecordVerifySubmitRequest{
		OutputDir: outDir, AgentID: "rec-nv-1", Fingerprint: "FIND-NV",
		Decision: "replace", Reason: "Reproduced locally in wave 2", Record: promotedNV,
	})
	if err != nil {
		t.Fatalf("SubmitRecordVerifier promote: %v", err)
	}
	if reqFresh, _ := p5Prom["requires_another_fresh_verify"].(bool); !reqFresh {
		t.Fatalf("expected promotion from needs_validation to confirmed to require another fresh verifier")
	}
	// Break-test: reusing rec-nv-1 as the second Phase 5 verifier must fail
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: outDir, Role: "record_verifier", AgentID: "rec-nv-1", Fingerprint: "FIND-NV",
	}); err == nil {
		t.Fatalf("expected reusing rec-nv-1 to fail")
	}
	// Fresh rec-nv-2 verifies FIND-NV, and rec-conf-1 verifies FIND-CONF
	for _, pair := range [][2]string{{"rec-nv-2", "FIND-NV"}, {"rec-conf-1", "FIND-CONF"}} {
		if _, err := engine.AssignAgent(engine.AssignAgentRequest{
			OutputDir: outDir, Role: "record_verifier", AgentID: pair[0], Fingerprint: pair[1],
		}); err != nil {
			t.Fatalf("AssignAgent %s: %v", pair[0], err)
		}
		if _, err := engine.SubmitRecordVerifier(engine.RecordVerifySubmitRequest{
			OutputDir: outDir, AgentID: pair[0], Fingerprint: pair[1], Decision: "verified",
		}); err != nil {
			t.Fatalf("SubmitRecordVerifier %s: %v", pair[0], err)
		}
	}

	// Render and verify manifest.sha256 entries (8 base files + 2 GHSA advisories = 10) against on-disk SHA-256 digests
	stBeforeRender, err := engine.Status(engine.StatusRequest{OutputDir: outDir})
	if err != nil || !stBeforeRender.ReadyToRender {
		t.Fatalf("expected Status ReadyToRender=true, got %+v err=%v", stBeforeRender, err)
	}
	rRes, err := engine.Render(engine.RenderRequest{OutputDir: outDir, FailOn: "high"})
	if err != nil || rRes.ConfirmedCount != 2 || len(rRes.AdvisoryPaths) != 2 {
		t.Fatalf("Render failed: %+v err=%v", rRes, err)
	}
	if rRes.GatePassed {
		t.Fatalf("expected FailOn=high to set GatePassed=false when 2 high findings exist")
	}
	manifestBytes, err := os.ReadFile(rRes.ManifestPath)
	if err != nil {
		t.Fatalf("read manifest.sha256: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(manifestBytes)), "\n")
	if len(lines) != 10 {
		t.Fatalf("expected 10 lines in manifest.sha256 (8 base + 2 GHSA advisories), got %d", len(lines))
	}
	for _, line := range lines {
		parts := strings.Split(line, "  ")
		if len(parts) != 2 {
			t.Fatalf("malformed manifest line %q", line)
		}
		actualHash, herr := engine.FileHashSHA256(filepath.Join(outDir, parts[1]))
		if herr != nil || actualHash != parts[0] {
			t.Fatalf("manifest hash mismatch for %s: want %s got %s", parts[1], parts[0], actualHash)
		}
	}

	// Break-test: mutating a pinned source file after review must trigger source_drift_detected in ValidateRun and Status
	if err := os.WriteFile(filepath.Join(target, "src/api.go"), []byte("package api\nfunc Handle() { /* tampered */ }\n"), 0o600); err != nil {
		t.Fatalf("tamper src/api.go: %v", err)
	}
	valAfterDrift, err := engine.ValidateRunWithGate(outDir, "critical")
	if err != nil {
		t.Fatalf("ValidateRunWithGate error: %v", err)
	}
	if valid, _ := valAfterDrift["valid"].(bool); valid {
		t.Fatalf("expected ValidateRunWithGate to fail after source file SHA-256 drift")
	}
	stAfterDrift, err := engine.Status(engine.StatusRequest{OutputDir: outDir})
	if err != nil || stAfterDrift.ReadyToRender ||
		len(stAfterDrift.SourceDriftFiles) != 1 || stAfterDrift.SourceDriftFiles[0] != "src/api.go" {
		t.Fatalf("expected Status to report source drift on src/api.go, got %+v err=%v", stAfterDrift, err)
	}

	// Break-test FIND-0009: replacing intermediate directory src/ with a symlink must be caught by DetectSourceDrift
	extDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(extDir, "api.go"), []byte("package api\nfunc Handle() {}\n"), 0o600)
	_ = os.RemoveAll(filepath.Join(target, "src"))
	_ = os.Symlink(extDir, filepath.Join(target, "src"))
	stAfterSymlink, err := engine.Status(engine.StatusRequest{OutputDir: outDir})
	if err != nil || len(stAfterSymlink.SourceDriftFiles) != 1 || stAfterSymlink.SourceDriftFiles[0] != "src/api.go" {
		t.Fatalf("expected intermediate directory symlink to trigger source drift on src/api.go, got %+v err=%v", stAfterSymlink, err)
	}

	// Break-test FIND-0008: deleting .sec-audit-state.json must cause ValidateRunWithGate to fail closed with an error
	_ = os.Remove(filepath.Join(outDir, ".sec-audit-state.json"))
	if _, err := engine.ValidateRunWithGate(outDir, ""); err == nil {
		t.Fatalf("expected ValidateRunWithGate to fail closed when .sec-audit-state.json is deleted")
	}
}
