package prompt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/spec"
	"github.com/fabriziosalmi/security-audit-cli/internal/store"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

func TestCompileAllRolePrompts(t *testing.T) {
	cat, err := spec.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	outDir := t.TempDir()

	// Recon
	rp := CompileRecon("/repo/target")
	if !strings.Contains(rp, "/repo/target") {
		t.Fatalf("unexpected recon prompt: %s", rp)
	}

	// Missing architecture.md should fail hunter prompt compilation
	blockRef := "ATTACK-CLASSES.md#Injection"
	unit1 := validator.CoverageUnit{
		CoverageID:               "u1",
		OrdinaryAttackClassBlock: &blockRef,
		SelectedCompanionBlocks:  []string{"WEB-PROTOCOL-AND-AUTH.md#Core discipline"},
		ExcludedBlocks:           []validator.ExcludedBlock{{Block: "WEB-PROTOCOL-AND-AUTH.md#OAuth / OIDC / SAML", Reason: "no SSO"}},
	}
	unit2 := validator.CoverageUnit{CoverageID: "u2"}
	st := &store.InternalState{
		Candidates: map[string]*store.CandidateEnvelope{
			"FIND-0001": {
				Fingerprint:     "FIND-0001",
				HunterID:        "prior-run-carryover",
				ProposedVerdict: "confirmed",
				CandidateRecord: validator.Finding{Title: "Old SQLi", RootCause: "raw concat"},
			},
		},
	}

	allU := []validator.CoverageUnit{unit1, unit2}
	if _, err := CompileHunter(outDir, "hunter-1", []validator.CoverageUnit{unit1}, allU, st, cat); err == nil {
		t.Fatalf("expected error when architecture.md is missing")
	}

	_ = os.WriteFile(filepath.Join(outDir, "architecture.md"), []byte("# Architecture\nTrust boundaries."), 0o600)
	hp, err := CompileHunter(outDir, "hunter-1", []validator.CoverageUnit{unit1}, []validator.CoverageUnit{unit1, unit2}, st, cat)
	if err != nil {
		t.Fatalf("CompileHunter: %v", err)
	}
	for _, want := range []string{
		"## Architecture Summary",
		"ATTACK-CLASSES.md#Injection",
		"WEB-PROTOCOL-AND-AUTH.md#OAuth / OIDC / SAML",
		"Peer coverage_id (do not duplicate): `u2`",
		"Carried prior confirmed exclusion: `FIND-0001`",
	} {
		if !strings.Contains(hp, want) {
			t.Fatalf("hunter prompt missing %q", want)
		}
	}

	// Critic
	cp, err := CompileCritic(outDir, []validator.CoverageUnit{unit1})
	if err != nil || !strings.Contains(cp, "## Coverage Ledger") {
		t.Fatalf("CompileCritic failed: %v", err)
	}

	// Verifier
	env := &store.CandidateEnvelope{
		Fingerprint:  "FIND-0009",
		CandidateRaw: map[string]any{"fingerprint": "FIND-0009", "title": "Auth bypass"},
		FinalRecord:  &validator.Finding{Fingerprint: "FIND-0009", Title: "Auth bypass"},
	}
	vp, err := CompileVerifier(outDir, "verifier-1", env, cat)
	if err != nil || !strings.Contains(vp, "You did not write this candidate") {
		t.Fatalf("CompileVerifier failed: %v", err)
	}

	// RecordVerifier
	rvp := CompileRecordVerifier(env)
	if !strings.Contains(rvp, "FIND-0009") {
		t.Fatalf("CompileRecordVerifier missing fingerprint: %s", rvp)
	}
}
