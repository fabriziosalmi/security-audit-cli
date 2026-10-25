package engine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/engine"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

func TestCarryoverUnchangedUnitsAndFailOnGates(t *testing.T) {
	target := t.TempDir()
	srcContent := []byte("package main\nfunc Clean() {}\n")
	if err := os.WriteFile(filepath.Join(target, "clean.go"), srcContent, 0o600); err != nil {
		t.Fatalf("write clean.go: %v", err)
	}

	// Run 1: cleanly cover clean.go
	run1Dir := filepath.Join(t.TempDir(), "run-1")
	if _, err := engine.Init(engine.InitRequest{Target: target, OutputDir: run1Dir, Profile: "quick"}); err != nil {
		t.Fatalf("Init run1: %v", err)
	}
	if _, err := engine.WriteArchitecture(run1Dir, "# Arch\nClean."); err != nil {
		t.Fatalf("WriteArchitecture run1: %v", err)
	}
	atk := "ATTACK-CLASSES.md#Injection"
	seedInput := []engine.SeedUnitInput{
		{
			CanonicalRefs: validator.CanonicalRefs{
				Surface: "clean.go#Clean", Boundary: "clean.go#Clean",
				Subsystem: "core", AttackClass: atk,
			},
			Surface:                  "Clean",
			Boundary:                 "Clean",
			Subsystem:                "core",
			AttackClass:              "Injection",
			StartingPaths:            []string{"clean.go"},
			OrdinaryAttackClassBlock: &atk,
			SelectedCompanionBlocks:  []string{},
			ExcludedBlocks:           []validator.ExcludedBlock{},
		},
	}
	units1, err := engine.SeedLedger(run1Dir, seedInput)
	if err != nil {
		t.Fatalf("SeedLedger run1: %v", err)
	}
	cid := units1[0].CoverageID
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: run1Dir, Role: "hunter", AgentID: "hunt-1", CoverageIDs: []string{cid},
	}); err != nil {
		t.Fatalf("AssignAgent hunt-1: %v", err)
	}
	if _, err := engine.SubmitHunter(run1Dir, "hunt-1", engine.HunterStructuredResult{
		Units: []engine.HunterUnitResult{
			{
				CoverageID:    cid,
				Disposition:   "covered",
				ReviewedPaths: []string{"clean.go"},
				Checks: []validator.LocalCheck{
					{
						AgentID: "hunt-1", ReviewedPaths: []string{"clean.go"},
						Invariant: "No untrusted input reaches sink", Method: "source", Result: "clean",
					},
				},
			},
		},
	}); err != nil {
		t.Fatalf("SubmitHunter hunt-1: %v", err)
	}

	// Run 2: initialize with prior_run_dirs=[run1Dir] and seed with CarryoverUnchanged=true
	run2Dir := filepath.Join(t.TempDir(), "run-2")
	if _, err := engine.Init(engine.InitRequest{
		Target: target, OutputDir: run2Dir, Profile: "quick", PriorRunDirs: []string{run1Dir},
	}); err != nil {
		t.Fatalf("Init run2: %v", err)
	}
	if _, err := engine.WriteArchitecture(run2Dir, "# Arch\nIncremental."); err != nil {
		t.Fatalf("WriteArchitecture run2: %v", err)
	}
	units2, err := engine.SeedLedgerWithOptions(run2Dir, seedInput, true)
	if err != nil {
		t.Fatalf("SeedLedgerWithOptions run2: %v", err)
	}
	if units2[0].Status != "covered" || units2[0].PriorStatus != "prior_covered_same_source" {
		t.Fatalf(
			"expected SHA-256 unchanged unit to be carried over as covered/prior_covered_same_source, got status=%s prior_status=%s",
			units2[0].Status, units2[0].PriorStatus,
		)
	}
	// Run 2 can immediately render without invoking a single hunter!
	r2, err := engine.Render(engine.RenderRequest{OutputDir: run2Dir, FailOn: "any"})
	if err != nil || !r2.GatePassed || r2.RunStatus != "complete" {
		t.Fatalf("expected immediate complete render on carried-over clean run, got %+v err=%v", r2, err)
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
