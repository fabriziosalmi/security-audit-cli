package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

func TestScanRepositoryAndPriorCarryover(t *testing.T) {
	repo := t.TempDir()
	files := map[string]string{
		"go.mod":                       "module example.com/test\n",
		"Dockerfile":                   "FROM alpine\n",
		"cmd/server/main.go":           "package main\nfunc main() {}\n",
		"internal/auth/jwt.go":         "package auth\n",
		"internal/mcp/agent_prompt.go": "package mcp\n",
		"internal/db/store.go":         "package db\n",
		"native/codec.c":               "int main() { return 0; }\n",
		"ui/App.tsx":                   "export const App = () => null;\n",
		"proto/service.proto":          "syntax = \"proto3\";\n",
		"ipc/unix_socket.go":           "package ipc\n",
		".github/workflows/ci.yml":     "name: CI\n",
		"scripts/run.py":               "print(1)\n",
		"web/index.js":                 "export default 1;\n",
		"rust/lib.rs":                  "pub fn f() {}\n",
		"java/Main.java":               "class Main {}\n",
		"infra/main.tf":                "resource \"null\" \"x\" {}\n",
		"node_modules/ignored.js":      "console.log(1);\n",
	}
	for rel, content := range files {
		full := filepath.Join(repo, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	brief := ScanRepository(repo)
	if brief.TotalFiles != 16 { // node_modules is skipped
		t.Fatalf("expected 16 scanned files (skipping node_modules), got %d", brief.TotalFiles)
	}
	if brief.Languages["go"] != 5 || brief.Languages["c_cpp"] != 1 || brief.Languages["typescript"] != 1 || brief.Languages["idl"] != 1 {
		t.Fatalf("unexpected language counts: %+v", brief.Languages)
	}
	if len(brief.RecommendedCompanions) < 8 {
		t.Fatalf("expected at least 8 recommended companions, got %d: %+v", len(brief.RecommendedCompanions), brief.RecommendedCompanions)
	}

	// Test AnyPathInScope & IsSubpath & NextRunDir
	if !AnyPathInScope([]string{"internal/auth/jwt.go"}, []string{"internal/auth"}) {
		t.Fatalf("expected AnyPathInScope to match directory prefix")
	}
	if AnyPathInScope([]string{"cmd/server/main.go"}, []string{"internal/auth"}) {
		t.Fatalf("expected AnyPathInScope to reject disjoint path")
	}
	if !IsSubpath(repo, filepath.Join(repo, "cmd")) {
		t.Fatalf("expected IsSubpath true")
	}
	if IsSubpath(repo, filepath.Dir(repo)) {
		t.Fatalf("expected IsSubpath false for parent")
	}
	r1 := NextRunDir(repo)
	if filepath.Base(r1) != "run-1" {
		t.Fatalf("expected run-1, got %s", r1)
	}

	// Test EvaluatePriorRuns
	priorDir := t.TempDir()
	priorFindings := []validator.Finding{
		{
			Verdict:     "confirmed",
			Fingerprint: "FIND-0001",
			Title:       "Valid carryover",
			Trace:       []validator.TraceEntry{{Kind: "entrypoint", File: "cmd/server/main.go", Line: 1}},
			Evidence:    []validator.EvidenceEntry{{File: "cmd/server/main.go", Line: 2}},
		},
		{
			Verdict:     "confirmed",
			Fingerprint: "FIND-0002",
			Title:       "Changed source line",
			Trace:       []validator.TraceEntry{{Kind: "entrypoint", File: "cmd/server/main.go", Line: 999}},
		},
		{
			Verdict:     "needs_validation",
			Fingerprint: "FIND-0003",
			Title:       "Needs val carryover",
			Trace:       []validator.TraceEntry{{Kind: "entrypoint", File: "internal/auth/jwt.go", Line: 1}},
		},
		{
			Verdict:     "rejected",
			Fingerprint: "FIND-0004",
			Title:       "Rejected carryover",
			Trace:       []validator.TraceEntry{{Kind: "entrypoint", File: "internal/auth/jwt.go", Line: 1}},
		},
	}
	raw, _ := json.Marshal(priorFindings)
	_ = os.WriteFile(filepath.Join(priorDir, "findings.json"), raw, 0o600)

	cos, carried := EvaluatePriorRuns(repo, []string{priorDir})
	if len(cos) != 1 {
		t.Fatalf("expected 1 carryover summary, got %d", len(cos))
	}
	if len(cos[0].CarriedConfirmed) != 1 || len(cos[0].ChangedConfirmed) != 1 || len(cos[0].CarriedNeedsValidation) != 1 || len(cos[0].SuppressedRejected) != 1 {
		t.Fatalf("unexpected carryover classification: %+v", cos[0])
	}
	if len(carried) != 2 {
		t.Fatalf("expected 2 carried candidate envelopes, got %d", len(carried))
	}

	// Test FileHashSHA256, ResolveGitRef, IsGitIgnored
	h, err := FileHashSHA256(filepath.Join(repo, "go.mod"))
	if err != nil || len(h) != 64 {
		t.Fatalf("FileHashSHA256 failed: h=%q err=%v", h, err)
	}
	if _, err := FileHashSHA256(filepath.Join(repo, "missing.txt")); err == nil {
		t.Fatalf("expected error on missing file hash")
	}
	ref, _ := ResolveGitRef(repo)
	if ref != "unversioned" {
		t.Fatalf("expected unversioned ref on non-git dir, got %s", ref)
	}
	_ = IsGitIgnored(repo, filepath.Join(repo, "node_modules"))
}
