package demo

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDemoRunsEndToEndAndBlocksEveryLie(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "demo")
	var buf bytes.Buffer
	s, err := Run(Options{Dir: dir}, &buf)
	if err != nil {
		t.Fatalf("demo failed: %v\n%s", err, buf.String())
	}
	if s.BlockedLies != 4 || s.Confirmed != 2 || s.Rejected != 1 || s.Advisories != 2 {
		t.Fatalf("unexpected summary %+v", s)
	}
	// 8 base artifacts + 2 advisories
	if s.ManifestEntries != 10 {
		t.Fatalf("expected 10 manifest entries, got %d", s.ManifestEntries)
	}
	report, err := os.ReadFile(s.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{fpIDOR, fpTraversal} {
		if !strings.Contains(string(report), want) {
			t.Fatalf("REPORT.md does not mention %s", want)
		}
	}
	out := buf.String()
	if strings.Count(out, "BLOCKED") != 4 {
		t.Fatalf("expected 4 BLOCKED lines, got:\n%s", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Fatalf("Color=false output contains ANSI escapes")
	}
	// The source file was restored after the drift step.
	got, err := os.ReadFile(filepath.Join(s.TargetDir, filepath.FromSlash(handlerPath)))
	if err != nil || string(got) != fixtureHandler {
		t.Fatalf("handler.go was not restored after the drift step")
	}
}

func TestDemoRefusesNonEmptyDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Options{Dir: dir}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected demo to refuse a non-empty directory")
	}
}

func TestFixtureCitationsResolve(t *testing.T) {
	// lineOf panics on a missing or ambiguous needle; building every record
	// exercises every citation.
	for _, c := range []map[string]any{idorCandidate(), traversalCandidate(), sqliCandidate(), rejectedSQLiRecord()} {
		if c["trace"] == nil {
			t.Fatal("record without trace")
		}
	}
}
