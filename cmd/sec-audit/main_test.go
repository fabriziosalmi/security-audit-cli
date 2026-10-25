package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

func TestCLIRunnerAndFlagParsing(t *testing.T) {
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

	// 5. catalog --json - (from stdin) and inline --json
	stdout.Reset()
	code = run([]string{"catalog", "--json", "-"}, strings.NewReader(`{"block":"ATTACK-CLASSES.md#Injection"}`), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), `"name": "Injection"`) {
		t.Fatalf("catalog --json - failed: code=%d out=%s", code, stdout.String())
	}
	stdout.Reset()
	code = run([]string{"catalog", "--json", `{"block":"ATTACK-CLASSES.md#Injection"}`}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), `"name": "Injection"`) {
		t.Fatalf("catalog --json inline failed: code=%d out=%s", code, stdout.String())
	}

	// 6. init + architecture via --file and --content + ledger-seed via --input array
	target := t.TempDir()
	_ = os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\nfunc main(){}\n"), 0o644)
	outDir := t.TempDir()
	stdout.Reset()
	initArgs := []string{
		"init", "--target", target, "--output-dir", outDir,
		"--profile", "quick", "--budget", "10", "--scope-paths", "main.go",
	}
	code = run(initArgs, strings.NewReader(""), &stdout, &stderr)
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
	stdout.Reset()
	archInline := []string{"architecture", "--output-dir", outDir, "--content", "# Arch\nInline content."}
	code = run(archInline, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("architecture --content failed: %s", stderr.String())
	}

	// Test parseSubcommandFlags --input wrappers (ledger-seed array, hunter-submit result, verifier-submit record)
	tmpInputDir := t.TempDir()
	unitsFile := filepath.Join(tmpInputDir, "units.json")
	_ = os.WriteFile(unitsFile, []byte(`[{"surface":"main"}]`), 0o600)
	rawU, err := parseSubcommandFlags("ledger-seed", []string{"--output-dir", outDir, "--input", unitsFile}, strings.NewReader(""))
	if err != nil || !strings.Contains(string(rawU), `"units"`) {
		t.Fatalf("ledger-seed --input array wrapper failed: %v %s", err, string(rawU))
	}

	objFile := filepath.Join(tmpInputDir, "obj.json")
	_ = os.WriteFile(objFile, []byte(`{"stop":true}`), 0o600)
	cArgs := []string{
		"--output-dir", outDir, "--agent-id", "critic-1",
		"--critic-kind", "final_clean", "--input", objFile,
	}
	rawC, err := parseSubcommandFlags("critic-submit", cArgs, strings.NewReader(""))
	if err != nil || !strings.Contains(string(rawC), `"result"`) || !strings.Contains(string(rawC), `"final_clean"`) {
		t.Fatalf("critic-submit --input wrapper failed: %v %s", err, string(rawC))
	}

	vArgs := []string{
		"--output-dir", outDir, "--agent-id", "ver-1", "--fingerprint", "F-1",
		"--decision", "rejected", "--reason", "r", "--input", objFile,
	}
	rawV, err := parseSubcommandFlags("verifier-submit", vArgs, strings.NewReader(""))
	if err != nil || !strings.Contains(string(rawV), `"record"`) {
		t.Fatalf("verifier-submit --input wrapper failed: %v %s", err, string(rawV))
	}

	pArgs := []string{
		"--output-dir", outDir, "--agent-id", "h-1", "--files", "a.txt,b.txt",
		"--max-file-bytes", "100", "--max-total-bytes", "500",
	}
	rawP, err := parseSubcommandFlags("artifact-promote", pArgs, strings.NewReader(""))
	if err != nil || !strings.Contains(string(rawP), `"max_file_bytes":100`) {
		t.Fatalf("artifact-promote flags failed: %v %s", err, string(rawP))
	}

	// Verify critic-submit preserves critic_kind from --input JSON when --critic-kind flag is omitted
	criticInputFile := filepath.Join(tmpInputDir, "critic-final.json")
	criticPayload := `{"output_dir":"/tmp/x","agent_id":"c-1","critic_kind":"final_clean","result":{"stop":true}}`
	_ = os.WriteFile(criticInputFile, []byte(criticPayload), 0o600)
	rawCriticJSON, err := parseSubcommandFlags("critic-submit", []string{"--input", criticInputFile}, strings.NewReader(""))
	if err != nil || !strings.Contains(string(rawCriticJSON), `"critic_kind":"final_clean"`) {
		t.Fatalf("expected critic-submit to preserve critic_kind=final_clean from --input JSON, got: %v %s", err, string(rawCriticJSON))
	}

	// Verify --prior-run-dirs flag is parsed into prior_run_dirs slice
	priorArgs := []string{"--target", target, "--prior-run-dirs", "/tmp/r1,/tmp/r2"}
	rawInitPrior, err := parseSubcommandFlags("init", priorArgs, strings.NewReader(""))
	if err != nil || !strings.Contains(string(rawInitPrior), `"/tmp/r1"`) || !strings.Contains(string(rawInitPrior), `"/tmp/r2"`) {
		t.Fatalf("expected init --prior-run-dirs to populate prior_run_dirs, got: %v %s", err, string(rawInitPrior))
	}

	// Validate returning valid: false should exit with code 1
	badLedger := filepath.Join(tmpInputDir, "bad-ledger.json")
	_ = os.WriteFile(badLedger, []byte(`[{"bad":1}]`), 0o600)
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"validate", "--ledger", badLedger, "--target", target}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 when validate returns valid=false, got %d", code)
	}

	// 7. mcp mode via CLI
	stdout.Reset()
	var mcpResp map[string]any
	code = run([]string{"mcp"}, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`+"\n"), &stdout, &stderr)
	if code != 0 || json.Unmarshal(stdout.Bytes(), &mcpResp) != nil {
		t.Fatalf("mcp CLI failed: code=%d out=%s", code, stdout.String())
	}

	// 8. Break-tests for FIND-0002 & FIND-0003: symlink --input, duplicate-key --input, and oversized --json -
	symlinkInput := filepath.Join(tmpInputDir, "symlink-input.json")
	_ = os.Symlink(objFile, symlinkInput)
	if _, err := parseSubcommandFlags("critic-submit", []string{"--input", symlinkInput}, strings.NewReader("")); err == nil {
		t.Fatalf("expected parseSubcommandFlags to reject symlink --input file")
	}
	archSymArgs := []string{"--output-dir", outDir, "--file", symlinkInput}
	if _, err := parseSubcommandFlags("architecture", archSymArgs, strings.NewReader("")); err == nil {
		t.Fatalf("expected parseSubcommandFlags to reject symlink --file on architecture")
	}

	dupInputFile := filepath.Join(tmpInputDir, "dup-input.json")
	_ = os.WriteFile(dupInputFile, []byte(`{"stop":false,"stop":true}`), 0o600)
	if _, err := parseSubcommandFlags("critic-submit", []string{"--input", dupInputFile}, strings.NewReader("")); err == nil {
		t.Fatalf("expected parseSubcommandFlags to reject duplicate JSON keys in --input file")
	}

	oversizedReader := bytes.NewReader(bytes.Repeat([]byte("a"), validator.MaxInputBytes+10))
	if _, err := parseSubcommandFlags("catalog", []string{"--json", "-"}, oversizedReader); err == nil {
		t.Fatalf("expected parseSubcommandFlags to reject stdin exceeding MaxInputBytes")
	}

	// 9. Merging CLI flags (--output-dir) with --json object
	mergedJSON, err := parseSubcommandFlags("ledger-seed", []string{"--output-dir", outDir, "--json", `{"units":[]}`}, strings.NewReader(""))
	if err != nil || !strings.Contains(string(mergedJSON), outDir) {
		t.Fatalf("expected --output-dir to merge into --json payload, got err=%v raw=%s", err, string(mergedJSON))
	}

	// 10. Break-test: verifier-submit record containing "output_dir" inside prose must still be wrapped in "record"
	proseFile := filepath.Join(tmpInputDir, "prose-record.json")
	_ = os.WriteFile(proseFile, []byte(`{"verdict":"rejected","description":"Fixes bug in output_dir handling"}`), 0o600)
	rawProse, err := parseSubcommandFlags("verifier-submit", []string{"--output-dir", outDir, "--input", proseFile}, strings.NewReader(""))
	if err != nil || !strings.Contains(string(rawProse), `"record":{`) {
		t.Fatalf("expected record with 'output_dir' in description to still wrap under 'record', got err=%v raw=%s", err, string(rawProse))
	}

	// 11. version / --version / -v -> exit 0
	for _, vArg := range []string{"version", "--version", "-v"} {
		stdout.Reset()
		code = run([]string{vArg}, strings.NewReader(""), &stdout, &stderr)
		if code != 0 || !strings.Contains(stdout.String(), `"version":`) {
			t.Fatalf("expected %s to exit 0 with version JSON, got code=%d out=%s", vArg, code, stdout.String())
		}
	}

	// 12. status --output-dir -> exit 0
	stdout.Reset()
	code = run([]string{"status", "--output-dir", outDir}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), `"next_required_actions"`) {
		t.Fatalf("expected status CLI to succeed, got code=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}

	// 13. --carryover-unchanged and --fail-on flag parsing
	carryArgs := []string{"--output-dir", outDir, "--carryover-unchanged", "--input", unitsFile}
	rawCarry, err := parseSubcommandFlags("ledger-seed", carryArgs, strings.NewReader(""))
	if err != nil || !strings.Contains(string(rawCarry), `"carryover_unchanged":true`) {
		t.Fatalf("expected --carryover-unchanged to set carryover_unchanged=true, got err=%v raw=%s", err, string(rawCarry))
	}
	rawFailOn, err := parseSubcommandFlags("render", []string{"--output-dir", outDir, "--fail-on", "high"}, strings.NewReader(""))
	if err != nil || !strings.Contains(string(rawFailOn), `"fail_on":"high"`) {
		t.Fatalf("expected --fail-on high to set fail_on=high, got err=%v raw=%s", err, string(rawFailOn))
	}
}
