package validator_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

func TestDeriveCoverageIDAndCommonPrimitives(t *testing.T) {
	lc := "rotate-key"
	refs := validator.CanonicalRefs{
		Surface:     "src/router.ts#POST /users/:id",
		Boundary:    "src/authz.ts#requireOwner",
		Subsystem:   "packages/api",
		AttackClass: "ATTACK-CLASSES.md#Access control",
		Lifecycle:   &lc,
	}
	got, err := validator.DeriveCoverageID(refs)
	if err != nil {
		t.Fatalf("DeriveCoverageID error: %v", err)
	}
	want := "src%2Frouter.ts%23POST%20%2Fusers%2F%3Aid::src%2Fauthz.ts%23requireOwner::" +
		"packages%2Fapi::ATTACK-CLASSES.md%23Access%20control::rotate-key"
	if got != want {
		t.Fatalf("DeriveCoverageID mismatch:\n got: %s\nwant: %s", got, want)
	}

	// Reject NFD combining diacritical mark or default-ignorable Unicode in canonical ref
	if validator.IsCanonicalRef("cafe\u0301") {
		t.Fatalf("expected NFD combining mark to be rejected by IsCanonicalRef")
	}
	if validator.IsCanonicalRef("zero\u200Bwidth") {
		t.Fatalf("expected zero-width space to be rejected by IsCanonicalRef")
	}
	if _, err := validator.EncodeCanonicalRef(" leadingspace"); err == nil {
		t.Fatalf("expected leading space to fail EncodeCanonicalRef")
	}

	// Path & AgentID checks
	for _, badPath := range []string{
		"", "/abs", "~/home", `win\path`, "c:drive", "a//b", "a/../b", "a/./b",
		"trailing. ", "trailing.", "con.txt", "nul", "zero\u200Bwidth",
	} {
		if validator.IsSafeRelativePath(badPath) {
			t.Fatalf("expected IsSafeRelativePath(%q) == false", badPath)
		}
	}
	if !validator.IsSafeRelativePath("internal/validator/common.go") {
		t.Fatalf("expected valid relative path to pass")
	}

	for _, badID := range []string{"", "UPPER", "-dash", "con", "nul", "com1"} {
		if validator.IsSafeAgentID(badID) {
			t.Fatalf("expected IsSafeAgentID(%q) == false", badID)
		}
	}
	if !validator.IsOwnedArtifactPath("agents/hunter-1/artifacts/out.txt", "hunter-1") {
		t.Fatalf("expected valid owned artifact path")
	}
	if validator.IsOwnedArtifactPath("agents/hunter-2/artifacts/out.txt", "hunter-1") {
		t.Fatalf("expected cross-agent artifact path to be rejected")
	}

	// VerifyRepoFileAndLine + ReadFileNoFollow with kernel *os.Root
	repo := t.TempDir()
	srcDir := filepath.Join(repo, "src")
	_ = os.MkdirAll(srcDir, 0o755)
	apiFile := filepath.Join(srcDir, "api.go")
	_ = os.WriteFile(apiFile, []byte("package src\nfunc Handler() {}\n"), 0o644)
	emptyFile := filepath.Join(srcDir, "empty.go")
	_ = os.WriteFile(emptyFile, nil, 0o644)

	if err := validator.VerifyRepoFileAndLine(repo, "src/api.go", 2); err != nil {
		t.Fatalf("expected line 2 to pass, got %v", err)
	}
	if err := validator.VerifyRepoFileAndLine(repo, "src/api.go", 99); err == nil {
		t.Fatalf("expected line 99 to fail")
	}
	if err := validator.VerifyRepoFileAndLine(repo, "src/empty.go", 1); err == nil {
		t.Fatalf("expected line 1 on empty file to fail")
	}
	if err := validator.VerifyRepoFileAndLine(repo, "src", 1); err == nil {
		t.Fatalf("expected citing line on directory to fail")
	}

	// Symlink file & symlink parent dir inside repo must be rejected by *os.Root + Lstat
	symFile := filepath.Join(srcDir, "symlink.go")
	_ = os.Symlink(apiFile, symFile)
	if err := validator.VerifyRepoFileAndLine(repo, "src/symlink.go", 1); err == nil {
		t.Fatalf("expected symlink file inside repo to be rejected")
	}
	symDir := filepath.Join(repo, "symdir")
	_ = os.Symlink(srcDir, symDir)
	if err := validator.VerifyRepoFileAndLine(repo, "symdir/api.go", 1); err == nil {
		t.Fatalf("expected symlink parent dir inside repo to be rejected")
	}

	// ReadFileNoFollow tests
	if _, err := validator.ReadFileNoFollow(symFile); err == nil {
		t.Fatalf("expected ReadFileNoFollow to reject symlink")
	}
	if _, err := validator.ReadFileNoFollow(srcDir); err == nil {
		t.Fatalf("expected ReadFileNoFollow to reject directory")
	}
	data, err := validator.ReadFileNoFollow(apiFile)
	if err != nil || !strings.Contains(string(data), "Handler") {
		t.Fatalf("ReadFileNoFollow valid file failed: %v", err)
	}
}

func TestValidateLedgerStateTableAndAttempts(t *testing.T) {
	refs := validator.CanonicalRefs{
		Surface:     "src/api.go#ServeHTTP",
		Boundary:    "src/auth.go#VerifyToken",
		Subsystem:   "src",
		AttackClass: "ATTACK-CLASSES.md#Injection",
	}
	cid, _ := validator.DeriveCoverageID(refs)
	block := "ATTACK-CLASSES.md#Injection"
	owner1 := "hunter-1"
	owner2 := "hunter-2"
	art1 := "agents/hunter-1/artifacts/check1.txt"

	outDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(outDir, "agents", "hunter-1", "artifacts"), 0o700)
	_ = os.WriteFile(filepath.Join(outDir, art1), []byte("ok"), 0o600)

	repo := t.TempDir()
	_ = os.MkdirAll(filepath.Join(repo, "src"), 0o755)
	_ = os.WriteFile(filepath.Join(repo, "src", "api.go"), []byte("package src\n"), 0o644)

	unit := validator.CoverageUnit{
		CoverageID:               cid,
		CanonicalRefs:            refs,
		Surface:                  "ServeHTTP",
		Boundary:                 "VerifyToken",
		Subsystem:                "src",
		AttackClass:              "Injection",
		StartingPaths:            []string{"src/api.go"},
		OrdinaryAttackClassBlock: &block,
		SelectedCompanionBlocks:  []string{"WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF"},
		ExcludedBlocks: []validator.ExcludedBlock{{
			Block:  "WEB-PROTOCOL-AND-AUTH.md#Cookie scope and transport",
			Reason: "stateless token",
		}},
		PriorStatus: "none",
		Attempts: []validator.ArchivedAttempt{
			{
				Wave:          1,
				Status:        "blocked",
				AgentID:       &owner1,
				ReviewedPaths: []string{"src/api.go"},
				LocalChecks: []validator.LocalCheck{
					{
						AgentID:       owner1,
						ReviewedPaths: []string{"src/api.go"},
						Invariant:     "SQL bind",
						Method:        "local",
						Result:        "Observed query log",
						Artifact:      &art1,
					},
				},
				ResultFingerprints: []string{},
				Unresolved:         []string{"need second wave"},
				ReassignmentReason: "critic reopened",
			},
		},
		Wave:          2,
		Status:        "candidate",
		AgentID:       &owner2,
		ReviewedPaths: []string{"src/api.go"},
		LocalChecks: []validator.LocalCheck{
			{
				AgentID:       owner2,
				ReviewedPaths: []string{"src/api.go"},
				Invariant:     "SQL bind",
				Method:        "source",
				Result:        "Found concat",
				Artifact:      nil,
			},
		},
		ResultFingerprints: []string{"FIND-0001"},
		Unresolved:         []string{},
	}

	validBlocks := map[string]bool{
		"ATTACK-CLASSES.md#Injection":            true,
		"WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF": true,
	}

	raw, _ := json.Marshal([]validator.CoverageUnit{unit})
	if errs := validator.ValidateCoverageLedgerBytes(raw, repo, outDir, validBlocks); len(errs) != 0 {
		t.Fatalf("expected valid wave-2 candidate unit, got errors: %v", errs)
	}

	// Break-test: Symlinked parent directory or symlinked artifact inside outputDir must be rejected by VerifyOutputRegularFile
	symArtOut := t.TempDir()
	realArtDir := filepath.Join(t.TempDir(), "real-artifacts")
	_ = os.MkdirAll(realArtDir, 0o700)
	_ = os.WriteFile(filepath.Join(realArtDir, "check1.txt"), []byte("ok"), 0o600)
	_ = os.MkdirAll(filepath.Join(symArtOut, "agents", "hunter-1"), 0o700)
	_ = os.Symlink(realArtDir, filepath.Join(symArtOut, "agents", "hunter-1", "artifacts"))
	if errs := validator.ValidateCoverageLedgerBytes(raw, repo, symArtOut, validBlocks); len(errs) == 0 {
		t.Fatalf("expected VerifyOutputRegularFile to reject symlinked artifacts directory inside outputDir")
	}

	// Test all status state-table invariants: planned, deferred, in_progress
	for _, st := range []string{"planned", "deferred", "in_progress"} {
		u := unit
		u.Status = st
		b, _ := json.Marshal([]validator.CoverageUnit{u})
		if errs := validator.ValidateCoverageLedgerBytes(b, repo, outDir, validBlocks); len(errs) == 0 {
			t.Fatalf("expected status %q with candidate fields populated to fail state invariants", st)
		}
	}

	// Break-test: Reusing owner1 in wave 2 after owner1 owned wave 1 attempt must fail
	reusedOwnerUnit := unit
	reusedOwnerUnit.AgentID = &owner1
	reusedOwnerUnit.LocalChecks = []validator.LocalCheck{
		{
			AgentID:       owner1,
			ReviewedPaths: []string{"src/api.go"},
			Invariant:     "SQL bind",
			Method:        "source",
			Result:        "Found concat",
		},
	}
	bReuse, _ := json.Marshal([]validator.CoverageUnit{reusedOwnerUnit})
	if errs := validator.ValidateCoverageLedgerBytes(bReuse, repo, outDir, validBlocks); len(errs) == 0 {
		t.Fatalf("expected reused attempt owner to fail")
	}

	// Break-test: Unexpected top-level field on unit must fail
	if errs := validator.ValidateCoverageLedgerBytes([]byte(`[{"unknown_field": 123}]`), "", "", nil); len(errs) == 0 {
		t.Fatalf("expected unknown field on coverage unit to fail")
	}

	// Cross-file consistency check
	crossErrs := validator.ValidateCrossFileConsistency(
		[]validator.CoverageUnit{unit},
		[]validator.Finding{{Fingerprint: "FIND-0001"}, {Fingerprint: "ORPHAN-999"}},
	)
	if len(crossErrs) != 1 || !strings.Contains(crossErrs[0], "ORPHAN-999") {
		t.Fatalf("expected orphan finding to fail cross-file consistency, got %v", crossErrs)
	}

	// ValidateCoverageLedgerFile on disk + non-array JSON + invalid syntax + duplicate/unsorted units + bad checks
	ledgerFile := filepath.Join(outDir, "coverage-ledger.json")
	_ = os.WriteFile(ledgerFile, raw, 0o600)
	if fErrs, ferr := validator.ValidateCoverageLedgerFile(ledgerFile, repo, outDir, validBlocks); ferr != nil || len(fErrs) != 0 {
		t.Fatalf("ValidateCoverageLedgerFile failed: %v %v", fErrs, ferr)
	}
	if _, ferr := validator.ValidateCoverageLedgerFile(filepath.Join(outDir, "missing.json"), repo, outDir, validBlocks); ferr == nil {
		t.Fatalf("expected missing ledger file to return error")
	}
	if errs := validator.ValidateCoverageLedgerBytes([]byte(`{"not":"array"}`), "", "", nil); len(errs) == 0 {
		t.Fatalf("expected non-array ledger to fail")
	}
	if errs := validator.ValidateCoverageLedgerBytes([]byte(`{invalid`), "", "", nil); len(errs) == 0 {
		t.Fatalf("expected invalid JSON ledger to fail")
	}

	// Duplicate/unsorted units & bad local check fields
	unitB := unit
	unitB.LocalChecks = []validator.LocalCheck{
		{
			AgentID:       "BAD_AGENT",
			ReviewedPaths: []string{"../bad"},
			Invariant:     "",
			Method:        "local",
			Result:        "",
			Artifact:      nil,
		},
		{
			AgentID:       owner2,
			ReviewedPaths: []string{"src/api.go"},
			Invariant:     "ok",
			Method:        "source",
			Result:        "ok",
			Artifact:      &art1, // source check must not have artifact
		},
	}
	bChecks, _ := json.Marshal([]validator.CoverageUnit{unitB, unit})
	if errs := validator.ValidateCoverageLedgerBytes(bChecks, repo, outDir, validBlocks); len(errs) < 4 {
		t.Fatalf("expected multiple check/duplicate errors, got %v", errs)
	}
}

func TestValidateFindingsAllVerdictsAndNestedAdditionalProps(t *testing.T) {
	// 1. Valid confirmed finding + valid needs_validation + valid rejected (sorted lexicographically by fingerprint)
	validJSON := `[
		{
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
		},
		{
			"verdict": "needs_validation",
			"fingerprint": "FIND-0002",
			"title": "Blocked lead",
			"description": "Missing IdP config",
			"claimed_root_cause": "Unverified aud",
			"trace": [{"kind": "entrypoint", "file": "src/auth.go", "line": 1, "scope": "V", "description": "Token"}],
			"evidence": [{"file": "src/auth.go", "line": 1, "description": "Getenv"}],
			"blockers": ["Prod env missing"],
			"validation_plan": {"deployment": "Check OIDC_AUD"}
		},
		{
			"verdict": "rejected",
			"fingerprint": "FIND-0003",
			"title": "Refuted lead",
			"description": "Safe path",
			"claimed_root_cause": "Assumed missing check",
			"trace": [{"kind": "sink", "file": "src/auth.go", "line": 1, "scope": "V", "description": "Check"}],
			"evidence": [{"file": "src/auth.go", "line": 1, "description": "Enforced"}],
			"reason": "Middleware enforces check at line 1"
		}
	]`
	if errs := validator.ValidateFindingsBytes([]byte(validJSON), ""); len(errs) != 0 {
		t.Fatalf("expected valid findings across all 3 verdicts, got: %v", errs)
	}

	fPath := filepath.Join(t.TempDir(), "findings.json")
	_ = os.WriteFile(fPath, []byte(validJSON), 0o600)
	if fErrs, ferr := validator.ValidateFindingsFile(fPath, ""); ferr != nil || len(fErrs) != 0 {
		t.Fatalf("ValidateFindingsFile failed: %v %v", fErrs, ferr)
	}
	if _, ferr := validator.ValidateFindingsFile(filepath.Join(t.TempDir(), "missing.json"), ""); ferr == nil {
		t.Fatalf("expected missing findings file to return error")
	}
	if errs := validator.ValidateFindingsBytes([]byte(`{"not":"array"}`), ""); len(errs) == 0 {
		t.Fatalf("expected non-array findings to fail")
	}
	if errs := validator.ValidateFindingsBytes([]byte(`{invalid`), ""); len(errs) == 0 {
		t.Fatalf("expected invalid JSON findings to fail")
	}

	// Duplicate/unsorted findings & invalid multi-line trace ordering & empty blockers/validation_plan/reason
	badMulti := `[
		{
			"verdict": "needs_validation",
			"fingerprint": "FIND-0009",
			"title": "",
			"description": "",
			"claimed_root_cause": "",
			"trace": [
				{"kind": "sink", "file": "../bad", "line": 0, "scope": "", "description": ""},
				{"kind": "entrypoint", "file": "../bad", "line": 0, "scope": "", "description": ""},
				{"kind": "entrypoint", "file": "../bad", "line": 0, "scope": "", "description": ""}
			],
			"evidence": [
				{"file": "../bad", "line": 0, "description": ""},
				{"file": "../bad", "line": 0, "description": ""}
			],
			"blockers": ["dup", "dup", ""],
			"validation_plan": {"extra": 1}
		},
		{
			"verdict": "rejected",
			"fingerprint": "FIND-0001",
			"title": "Unsorted",
			"description": "Unsorted",
			"claimed_root_cause": "",
			"trace": [],
			"evidence": [],
			"reason": ""
		}
	]`
	if errs := validator.ValidateFindingsBytes([]byte(badMulti), ""); len(errs) < 10 {
		t.Fatalf("expected >=10 validation errors on badMulti, got %d: %v", len(errs), errs)
	}

	// 2. Break-test: overall_severity > impact.score OR nested extra property in severity/trace
	badConfirmed := `[{
		"verdict": "confirmed",
		"fingerprint": "FIND-0001",
		"title": "Bad",
		"description": "Bad",
		"root_cause": "Bad",
		"intended_behavior": "Good",
		"trace": [{"kind": "propagation", "file": "src/api.go", "line": 1, "scope": "H", "description": "In", "extra_trace_prop": 1}],
		"evidence": [{"file": "src/db.go", "line": 3, "description": "Sprintf", "extra_ev": 1}],
		"conditions": [{"kind": "invalid_kind", "description": "Anon", "extra_cond": 1}],
		"execution": {
			"attacker_perspective": "Remote",
			"payloads": [],
			"instructions": [],
			"observed_result": "   ",
			"extra_exec": true
		},
		"remediation": {"strategy": "Fix", "extra_rem": true, "code_changes": [{"file_name": "../bad", "fixed_code": "ok", "extra_cc": 1}]},
		"severity": {
			"likelihood": {"score": "high", "reason": "Public", "extra_l": 1},
			"impact": {"score": "low", "reason": "Minor"},
			"overall_severity": "critical",
			"cvss": 9.9
		},
		"confidence": {"score": "invalid", "reason": "Reproduced", "extra_conf": 1}
	}]`
	errs := validator.ValidateFindingsBytes([]byte(badConfirmed), "")
	for _, wantSubstr := range []string{
		"trace[0]: unexpected field \"extra_trace_prop\"",
		"trace[0].kind: a one-line trace must be \"entrypoint\" or \"sink\"",
		"evidence[0]: unexpected field \"extra_ev\"",
		"conditions[0]: unexpected field \"extra_cond\"",
		"execution: unexpected field \"extra_exec\"",
		"remediation: unexpected field \"extra_rem\"",
		"severity: unexpected field \"cvss\"",
		"cannot exceed demonstrated impact \"low\"",
		"confidence: unexpected field \"extra_conf\"",
	} {
		found := false
		for _, e := range errs {
			if strings.Contains(e, wantSubstr) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected error containing %q, got:\n%s", wantSubstr, strings.Join(errs, "\n"))
		}
	}

	// Oversized file in VerifyRepoFileAndLine with line > 0 must be rejected
	oversizedRepo := t.TempDir()
	bigBuf := make([]byte, validator.MaxInputBytes+128)
	for i := range bigBuf {
		bigBuf[i] = 'a'
	}
	_ = os.WriteFile(filepath.Join(oversizedRepo, "huge.go"), bigBuf, 0o600)
	if err := validator.VerifyRepoFileAndLine(oversizedRepo, "huge.go", 1); err == nil {
		t.Fatalf("expected VerifyRepoFileAndLine to reject file exceeding MaxInputBytes")
	}
}
