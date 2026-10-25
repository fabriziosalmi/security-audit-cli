package validator_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

func TestJSONPreflightDuplicateKeyAndDepthBreakTests(t *testing.T) {
	// Break-test 1: Duplicate key smuggling in findings.json MUST be rejected before json.Unmarshal!
	smuggled := `[{
		"verdict": "rejected",
		"verdict": "confirmed",
		"fingerprint": "FIND-0001",
		"title": "Smuggled",
		"description": "Smuggled",
		"claimed_root_cause": "None",
		"trace": [{"kind": "sink", "file": "a.go", "line": 1, "scope": "S", "description": "D"}],
		"evidence": [{"file": "a.go", "line": 1, "description": "D"}],
		"reason": "Safe"
	}]`
	errs := validator.ValidateFindingsBytes([]byte(smuggled), "")
	if len(errs) == 0 || !strings.Contains(errs[0], `duplicate JSON object key "verdict"`) {
		t.Fatalf("Break-test failed: duplicate JSON key smuggling was not caught! got: %v", errs)
	}

	// Break-test 2: Nested duplicate key inside severity object MUST be rejected!
	nestedDup := `[{"verdict": "confirmed", "severity": {"overall_severity": "low", "overall_severity": "critical"}}]`
	if err := validator.ValidateJSONPreflight([]byte(nestedDup)); err == nil || !strings.Contains(err.Error(), `duplicate JSON object key "overall_severity"`) {
		t.Fatalf("Break-test failed: nested duplicate JSON key not caught! got: %v", err)
	}

	// Break-test 3: Nesting depth > 64 MUST be rejected!
	deep := strings.Repeat("[", 66) + strings.Repeat("]", 66)
	if err := validator.ValidateJSONPreflight([]byte(deep)); err == nil || !strings.Contains(err.Error(), "nesting depth exceeds 64") {
		t.Fatalf("Break-test failed: deep JSON >64 was not rejected! got: %v", err)
	}

	// Break-test 4: Trailing garbage after root JSON value MUST be rejected!
	if err := validator.ValidateJSONPreflight([]byte(`[] {}`)); err == nil {
		t.Fatalf("Break-test failed: trailing JSON value was accepted")
	}
}

func BenchmarkDeriveCoverageID(b *testing.B) {
	lc := "token-refresh"
	refs := validator.CanonicalRefs{
		Surface:     "internal/auth/router.go#POST /v1/oauth/token",
		Boundary:    "internal/auth/jwt.go#VerifyRefreshToken",
		Subsystem:   "internal/auth",
		AttackClass: "WEB-PROTOCOL-AND-AUTH.md#OAuth / OIDC / SAML",
		Lifecycle:   &lc,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := validator.DeriveCoverageID(refs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateCoverageLedger(b *testing.B) {
	refs := validator.CanonicalRefs{
		Surface:     "src/api.go#ServeHTTP",
		Boundary:    "src/auth.go#VerifyToken",
		Subsystem:   "src",
		AttackClass: "ATTACK-CLASSES.md#Injection",
	}
	cid, _ := validator.DeriveCoverageID(refs)
	block := "ATTACK-CLASSES.md#Injection"
	owner := "hunter-1"
	u := validator.CoverageUnit{
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
				AgentID:       owner,
				ReviewedPaths: []string{"src/api.go"},
				Invariant:     "Parameterized SQL",
				Method:        "source",
				Result:        "Safe",
			},
		},
		ResultFingerprints: []string{},
		Unresolved:         []string{},
	}
	raw, _ := json.Marshal([]validator.CoverageUnit{u})
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if errs := validator.ValidateCoverageLedgerBytes(raw, "", "", nil); len(errs) != 0 {
			b.Fatal(errs)
		}
	}
}

func BenchmarkValidateFindings(b *testing.B) {
	raw := []byte(`[{
		"verdict": "confirmed",
		"fingerprint": "FIND-0001",
		"title": "Confirmed SQLi",
		"description": "Raw SQL",
		"root_cause": "Fmt Sprintf",
		"intended_behavior": "Parameterized",
		"trace": [
			{"kind": "entrypoint", "file": "src/api.go", "line": 1, "scope": "H", "description": "In"},
			{"kind": "propagation", "file": "src/api.go", "line": 2, "scope": "P", "description": "Pass"},
			{"kind": "sink", "file": "src/db.go", "line": 3, "scope": "Q", "description": "Exec"}
		],
		"evidence": [{"file": "src/db.go", "line": 3, "description": "Sprintf"}],
		"conditions": [{"kind": "authentication_level", "description": "Anonymous"}],
		"execution": {
			"attacker_perspective": "Remote HTTP",
			"payloads": ["' OR 1=1--"],
			"instructions": ["Send GET"],
			"observed_result": "Rows dumped"
		},
		"remediation": {
			"strategy": "Bind params",
			"code_changes": [{"file_name": "src/db.go", "fixed_code": "db.Query(q, arg)"}]
		},
		"severity": {
			"likelihood": {"score": "high", "reason": "Public"},
			"impact": {"score": "high", "reason": "Full DB"},
			"overall_severity": "high"
		},
		"confidence": {"score": "high", "reason": "Reproduced"}
	}]`)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if errs := validator.ValidateFindingsBytes(raw, ""); len(errs) != 0 {
			b.Fatal(errs)
		}
	}
}

func FuzzValidateFindingsBytes(f *testing.F) {
	f.Add([]byte(`[{"verdict":"rejected","fingerprint":"F-1","title":"t","description":"d","claimed_root_cause":"c","trace":[{"kind":"sink","file":"a.go","line":1,"scope":"s","description":"d"}],"evidence":[{"file":"a.go","line":1,"description":"d"}],"reason":"r"}]`))
	f.Add([]byte(`[{"verdict":"rejected","verdict":"confirmed"}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = validator.ValidateFindingsBytes(data, "")
	})
}
