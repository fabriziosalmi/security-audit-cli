package engine_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/engine"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// closeCoverage runs the coverage critic a complete run needs: post_wave for
// the quick profile, final_clean for standard and deep.
func closeCoverage(tb testing.TB, outDir, profile, agentID string) {
	tb.Helper()
	kind := "final_clean"
	if profile == "quick" {
		kind = "post_wave"
	}
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{OutputDir: outDir, Role: "critic", AgentID: agentID}); err != nil {
		tb.Fatalf("AssignAgent %s: %v", agentID, err)
	}
	if _, err := engine.SubmitCritic(outDir, agentID, kind, engine.CriticResult{Stop: true}); err != nil {
		tb.Fatalf("SubmitCritic %s: %v", agentID, err)
	}
}

// coveredRun returns a standard-profile run whose only unit is covered, so
// the coverage critic is the last thing between it and a complete render.
func coveredRun(t *testing.T) (string, string) {
	t.Helper()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "api.go"), []byte("package api\nfunc Handle() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "run")
	if _, err := engine.Init(engine.InitRequest{Target: target, OutputDir: out, Profile: "standard"}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.WriteArchitecture(out, "# Arch\nOne handler."); err != nil {
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
				Invariant: "No input reaches a sink", Method: "source", Result: "clean",
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	return out, units[0].CoverageID
}

// Break-test: without the final_clean critic a standard run must not render
// as complete, and status must name the missing critic.
func TestRenderRequiresFinalCleanCritic(t *testing.T) {
	out, _ := coveredRun(t)

	_, err := engine.Render(engine.RenderRequest{OutputDir: out})
	if err == nil || !strings.Contains(err.Error(), "final_clean coverage critic") {
		t.Fatalf("render without final_clean: want refusal, got %v", err)
	}
	st, err := engine.Status(engine.StatusRequest{OutputDir: out})
	if err != nil || st.ReadyToRender || len(st.NextRequiredActions) != 1 ||
		!strings.Contains(st.NextRequiredActions[0], "final_clean") {
		t.Fatalf("status should ask for the final_clean critic, got %+v err=%v", st, err)
	}

	// A post_wave critic is not enough for the standard profile.
	if _, err := engine.AssignAgent(engine.AssignAgentRequest{OutputDir: out, Role: "critic", AgentID: "critic-w1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.SubmitCritic(out, "critic-w1", "post_wave", engine.CriticResult{Stop: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Render(engine.RenderRequest{OutputDir: out}); err == nil {
		t.Fatal("a post_wave critic must not satisfy the standard profile")
	}

	// An incomplete run may still render without it.
	inc := filepath.Join(t.TempDir(), "copy")
	if err := os.CopyFS(inc, os.DirFS(out)); err != nil {
		t.Fatal(err)
	}
	if r, err := engine.Render(engine.RenderRequest{OutputDir: inc, IncompleteReason: "budget_exhausted"}); err != nil ||
		r.RunStatus != "incomplete" {
		t.Fatalf("incomplete render should pass, got %+v err=%v", r, err)
	}

	closeCoverage(t, out, "standard", "critic-final")
	if r, err := engine.Render(engine.RenderRequest{OutputDir: out}); err != nil || r.RunStatus != "complete" {
		t.Fatalf("render after final_clean: %+v err=%v", r, err)
	}
}

// A critic that reopens units after a clean final pass invalidates it.
func TestReopeningAfterFinalCleanRequiresAnotherPass(t *testing.T) {
	out, cid := coveredRun(t)
	closeCoverage(t, out, "standard", "critic-final-1")

	if _, err := engine.AssignAgent(engine.AssignAgentRequest{OutputDir: out, Role: "critic", AgentID: "critic-late"}); err != nil {
		t.Fatal(err)
	}
	res, err := engine.SubmitCritic(out, "critic-late", "post_wave", engine.CriticResult{
		ReassignIDs: []string{cid}, ReassignmentReason: "Check the sibling handler too",
	})
	if err != nil {
		t.Fatal(err)
	}
	if done, _ := res["final_clean_done"].(bool); done {
		t.Fatal("final_clean_done must reset when a critic reopens a unit")
	}
}
