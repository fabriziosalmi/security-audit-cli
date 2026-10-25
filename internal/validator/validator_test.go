package validator_test

import (
	"encoding/json"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

func TestDeriveCoverageIDEncoding(t *testing.T) {
	refs := validator.CanonicalRefs{
		Surface:     "src/router.ts#POST /users/:id",
		Boundary:    "src/authz.ts#requireOwner",
		Subsystem:   "packages/api",
		AttackClass: "ATTACK-CLASSES.md#Access control",
	}
	got, err := validator.DeriveCoverageID(refs)
	if err != nil {
		t.Fatalf("DeriveCoverageID error: %v", err)
	}
	want := "src%2Frouter.ts%23POST%20%2Fusers%2F%3Aid::src%2Fauthz.ts%23requireOwner::packages%2Fapi::ATTACK-CLASSES.md%23Access%20control"
	if got != want {
		t.Fatalf("DeriveCoverageID mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestValidateLedgerAndFindingsInvariants(t *testing.T) {
	refs := validator.CanonicalRefs{
		Surface:     "src/api.go#ServeHTTP",
		Boundary:    "src/auth.go#VerifyToken",
		Subsystem:   "src",
		AttackClass: "ATTACK-CLASSES.md#Injection",
	}
	cid, _ := validator.DeriveCoverageID(refs)
	block := "ATTACK-CLASSES.md#Injection"
	owner := "hunter-1"

	validUnit := validator.CoverageUnit{
		CoverageID:               cid,
		CanonicalRefs:            refs,
		Surface:                  "ServeHTTP",
		Boundary:                 "VerifyToken",
		Subsystem:                "src",
		AttackClass:              "Injection",
		StartingPaths:            []string{"src/api.go"},
		OrdinaryAttackClassBlock: &block,
		SelectedCompanionBlocks:  []string{},
		ExcludedBlocks:           []validator.ExcludedBlock{},
		PriorStatus:              "none",
		Attempts:                 []validator.ArchivedAttempt{},
		Wave:                     1,
		Status:                   "covered",
		AgentID:                  &owner,
		ReviewedPaths:            []string{"src/api.go"},
		LocalChecks: []validator.LocalCheck{
			{
				AgentID:       "hunter-1",
				ReviewedPaths: []string{"src/api.go"},
				Invariant:     "Parameterized SQL",
				Method:        "source",
				Result:        "No string concatenation",
				Artifact:      nil,
			},
		},
		ResultFingerprints: []string{},
		Unresolved:         []string{},
	}

	raw, _ := json.Marshal([]validator.CoverageUnit{validUnit})
	if errs := validator.ValidateCoverageLedgerBytes(raw, "", "", nil); len(errs) != 0 {
		t.Fatalf("expected valid ledger, got errors: %v", errs)
	}

	// Break-test: reviewed_paths mismatch with local_checks[].reviewed_paths MUST fail
	badUnit := validUnit
	badUnit.ReviewedPaths = []string{"src/api.go", "src/unowned.go"}
	rawBad, _ := json.Marshal([]validator.CoverageUnit{badUnit})
	if errs := validator.ValidateCoverageLedgerBytes(rawBad, "", "", nil); len(errs) == 0 {
		t.Fatalf("Break-test failed: unowned reviewed_path was accepted!")
	}

	// Break-test: needs_validation with severity field MUST fail
	nvWithSeverity := `[{
		"verdict": "needs_validation",
		"fingerprint": "auth.missing-idp-config",
		"title": "IdP audience check depends on env var",
		"description": "Audience check uses runtime env.",
		"claimed_root_cause": "Env var may be empty in prod",
		"trace": [{"kind": "entrypoint", "file": "src/auth.go", "line": 10, "scope": "Verify", "description": "Reads env"}],
		"evidence": [{"file": "src/auth.go", "line": 12, "description": "os.Getenv call"}],
		"blockers": ["Production env not in repo"],
		"validation_plan": {"deployment": "Inspect OIDC_AUDIENCE in production deployment"},
		"severity": {"overall_severity": "medium"}
	}]`
	if errs := validator.ValidateFindingsBytes([]byte(nvWithSeverity), ""); len(errs) == 0 {
		t.Fatalf("Break-test failed: needs_validation with severity was accepted!")
	}
}
