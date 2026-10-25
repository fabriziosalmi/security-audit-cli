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

func BenchmarkEndToEndWorkflow(b *testing.B) {
	target := b.TempDir()
	_ = os.MkdirAll(filepath.Join(target, "src"), 0o755)
	_ = os.WriteFile(filepath.Join(target, "src", "api.go"), []byte("package src\nfunc Handle() {}\n"), 0o644)
	block := "ATTACK-CLASSES.md#Injection"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outDir := filepath.Join(b.TempDir(), "run")
		if _, err := engine.Init(engine.InitRequest{Target: target, OutputDir: outDir, Profile: "quick"}); err != nil {
			b.Fatal(err)
		}
		if _, err := engine.WriteArchitecture(outDir, "# Arch\nBoundaries."); err != nil {
			b.Fatal(err)
		}
		units, err := engine.SeedLedger(outDir, []engine.SeedUnitInput{
			{
				CanonicalRefs: validator.CanonicalRefs{
					Surface: "src/api.go#Handle", Boundary: "src/api.go#Handle",
					Subsystem: "src", AttackClass: block,
				},
				Surface: "Handle", Boundary: "Handle", Subsystem: "src", AttackClass: "Injection",
				StartingPaths: []string{"src/api.go"}, OrdinaryAttackClassBlock: &block,
			},
		})
		if err != nil {
			b.Fatal(err)
		}
		cid := units[0].CoverageID
		if _, err := engine.AssignAgent(engine.AssignAgentRequest{
			OutputDir: outDir, Role: "hunter", AgentID: "hunter-1", CoverageIDs: []string{cid},
		}); err != nil {
			b.Fatal(err)
		}
		hCheck := validator.LocalCheck{
			AgentID: "hunter-1", ReviewedPaths: []string{"src/api.go"},
			Invariant: "SQL", Method: "source", Result: "Safe",
		}
		if _, err := engine.SubmitHunter(outDir, "hunter-1", engine.HunterStructuredResult{
			Units: []engine.HunterUnitResult{
				{
					CoverageID:    cid,
					Disposition:   "covered",
					ReviewedPaths: []string{"src/api.go"},
					Checks:        []validator.LocalCheck{hCheck},
				},
			},
		}); err != nil {
			b.Fatal(err)
		}
		if _, err := engine.Render(engine.RenderRequest{OutputDir: outDir}); err != nil {
			b.Fatal(err)
		}
	}
}
