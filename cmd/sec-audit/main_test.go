package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIRunner(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// 1. No args -> exit 1 + usage
	code := run(nil, strings.NewReader(""), &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("expected usage and exit 1, got code=%d", code)
	}

	// 2. --help -> exit 0
	stdout.Reset()
	code = run([]string{"--help"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "record-verify-submit") {
		t.Fatalf("expected help and exit 0, got code=%d", code)
	}

	// 3. Unknown subcommand -> exit 1
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"unknown-sub"}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "unknown subcommand") {
		t.Fatalf("expected unknown subcommand error, got code=%d stderr=%s", code, stderr.String())
	}

	// 4. catalog --file ATTACK-CLASSES.md -> exit 0
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"catalog", "--file", "ATTACK-CLASSES.md"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "ATTACK-CLASSES.md#Injection") {
		t.Fatalf("catalog CLI failed: code=%d err=%s out=%s", code, stderr.String(), stdout.String())
	}

	// 5. catalog --json - (from stdin)
	stdout.Reset()
	code = run([]string{"catalog", "--json", "-"}, strings.NewReader(`{"block":"ATTACK-CLASSES.md#Injection"}`), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), `"name": "Injection"`) {
		t.Fatalf("catalog --json - failed: code=%d out=%s", code, stdout.String())
	}

	// 6. init + architecture via --file
	target := t.TempDir()
	_ = os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\nfunc main(){}\n"), 0o644)
	outDir := t.TempDir()
	stdout.Reset()
	code = run([]string{"init", "--target", target, "--output-dir", outDir, "--profile", "quick", "--budget", "10"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init CLI failed: %s", stderr.String())
	}

	archFile := filepath.Join(t.TempDir(), "arch.md")
	_ = os.WriteFile(archFile, []byte("# Arch\nSummary of boundaries."), 0o600)
	stdout.Reset()
	code = run([]string{"architecture", "--output-dir", outDir, "--file", archFile}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), `"word_count": 5`) {
		t.Fatalf("architecture --file failed: code=%d err=%s out=%s", code, stderr.String(), stdout.String())
	}

	// 7. mcp mode via CLI
	stdout.Reset()
	code = run([]string{"mcp"}, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`+"\n"), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), `"protocolVersion":"2024-11-05"`) {
		t.Fatalf("mcp CLI failed: code=%d out=%s", code, stdout.String())
	}
}
