package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The MCP server must report the same version as the CLI. Break-test: drop
// the mcp.Version assignment in run() and serverInfo.version becomes "dev".
func TestMCPServerVersionMatchesCLI(t *testing.T) {
	old := Version
	Version = "9.8.7-test"
	defer func() { Version = old }()

	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}` + "\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"mcp"}, in, &out, &errBuf); code != 0 {
		t.Fatalf("mcp exited %d: %s", code, errBuf.String())
	}
	var resp struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			Instructions    string `json:"instructions"`
			ServerInfo      struct {
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", out.String(), err)
	}
	if resp.Result.ServerInfo.Version != "9.8.7-test" {
		t.Fatalf("serverInfo.version = %q, want the CLI version", resp.Result.ServerInfo.Version)
	}
	if resp.Result.ProtocolVersion != "2025-06-18" || resp.Result.Instructions == "" {
		t.Fatalf("unexpected initialize result %+v", resp.Result)
	}
}

func TestFormatSelection(t *testing.T) {
	var out, errBuf bytes.Buffer
	// A bytes.Buffer is not a terminal: auto means JSON.
	if code := run([]string{"version"}, nil, &out, &errBuf); code != 0 || !strings.HasPrefix(out.String(), "{") {
		t.Fatalf("auto on a pipe should print JSON, got %q", out.String())
	}
	out.Reset()
	if code := run([]string{"version", "--format", "text"}, nil, &out, &errBuf); code != 0 ||
		!strings.HasPrefix(out.String(), "sec-audit ") {
		t.Fatalf("--format text should print a line, got %q", out.String())
	}
	out.Reset()
	if code := run([]string{"version", "--format=yaml"}, nil, &out, &errBuf); code != 1 {
		t.Fatalf("an invalid --format must fail, got %d", code)
	}

	target := t.TempDir()
	_ = os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\nfunc main(){}\n"), 0o644)
	runDir := filepath.Join(t.TempDir(), "run")
	out.Reset()
	if code := run([]string{"init", "--target", target, "--output-dir", runDir, "--format", "text"}, nil, &out, &errBuf); code != 0 {
		t.Fatalf("init failed: %s", errBuf.String())
	}
	if !strings.Contains(out.String(), "sec-audit init") || strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("text init output unexpected (or colored on a non-terminal):\n%s", out.String())
	}
	out.Reset()
	if code := run([]string{"status", "--output-dir", runDir, "--format", "text"}, nil, &out, &errBuf); code != 0 ||
		!strings.Contains(out.String(), "write architecture.md") {
		t.Fatalf("text status output unexpected:\n%s", out.String())
	}
	out.Reset()
	if code := run([]string{"status", "--output-dir", runDir}, nil, &out, &errBuf); code != 0 {
		t.Fatalf("status failed")
	}
	var st map[string]any
	if err := json.Unmarshal(out.Bytes(), &st); err != nil || st["next_required_actions"] == nil {
		t.Fatalf("default status on a pipe must stay JSON: %v %q", err, out.String())
	}
}

func TestDemoCommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	dir := filepath.Join(t.TempDir(), "d")
	if code := run([]string{"demo", "--dir", dir}, nil, &out, &errBuf); code != 0 {
		t.Fatalf("demo exited %d: %s\n%s", code, errBuf.String(), out.String())
	}
	if !strings.Contains(out.String(), "4 of 4 bad agent submissions blocked") {
		t.Fatalf("demo summary missing:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "REPORT.md")); err != nil {
		t.Fatalf("demo did not leave REPORT.md: %v", err)
	}
}

func withFakes(t *testing.T, bin string) *[][]string {
	t.Helper()
	oldLook, oldRun, oldExe := lookPath, runCmd, executable
	t.Cleanup(func() { lookPath, runCmd, executable = oldLook, oldRun, oldExe })
	var calls [][]string
	lookPath = func(string) (string, error) { return "/usr/bin/claude", nil }
	runCmd = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return []byte("ok"), nil
	}
	executable = func() (string, error) { return bin, nil }
	return &calls
}

func TestSetupClaudeRunsMCPAdd(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "sec-audit")
	_ = os.WriteFile(bin, []byte("x"), 0o755)
	calls := withFakes(t, bin)
	var out, errBuf bytes.Buffer
	if code := run([]string{"setup", "claude"}, nil, &out, &errBuf); code != 0 {
		t.Fatalf("setup claude exited %d: %s", code, errBuf.String())
	}
	resolved, _ := filepath.EvalSymlinks(bin)
	want := []string{"claude", "mcp", "add", "--scope", "user", "sec-audit", "--", resolved, "mcp"}
	if len(*calls) != 1 || strings.Join((*calls)[0], " ") != strings.Join(want, " ") {
		t.Fatalf("calls = %v, want %v", *calls, want)
	}

	runCmd = func(string, ...string) ([]byte, error) {
		return []byte("MCP server sec-audit already exists in user config"), errors.New("exit status 1")
	}
	out.Reset()
	if code := run([]string{"setup", "claude"}, nil, &out, &errBuf); code != 0 || !strings.Contains(out.String(), "already registered") {
		t.Fatalf("an existing registration should be reported, got %d %q", code, out.String())
	}

	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	errBuf.Reset()
	if code := run([]string{"setup", "claude"}, nil, &out, &errBuf); code != 1 || !strings.Contains(errBuf.String(), "claude mcp add") {
		t.Fatalf("missing claude CLI should print the command, got %d %q", code, errBuf.String())
	}
}

func TestSetupCursorMergesAndBacksUp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := filepath.Join(t.TempDir(), "sec-audit")
	_ = os.WriteFile(bin, []byte("x"), 0o755)
	withFakes(t, bin)

	cfgPath := filepath.Join(home, ".cursor", "mcp.json")
	_ = os.MkdirAll(filepath.Dir(cfgPath), 0o700)
	orig := `{"mcpServers":{"other":{"command":"/bin/other","args":[]}},"theme":"dark"}`
	_ = os.WriteFile(cfgPath, []byte(orig), 0o600)

	var out, errBuf bytes.Buffer
	if code := run([]string{"setup", "cursor", "--print"}, nil, &out, &errBuf); code != 0 {
		t.Fatalf("--print failed: %s", errBuf.String())
	}
	if b, _ := os.ReadFile(cfgPath); string(b) != orig {
		t.Fatal("--print changed the config file")
	}

	if code := run([]string{"setup", "cursor"}, nil, &out, &errBuf); code != 0 {
		t.Fatalf("setup cursor failed: %s", errBuf.String())
	}
	var cfg map[string]any
	b, _ := os.ReadFile(cfgPath)
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	servers := cfg["mcpServers"].(map[string]any)
	if servers["other"] == nil || cfg["theme"] != "dark" {
		t.Fatalf("existing settings were lost: %s", b)
	}
	if sa, _ := servers["sec-audit"].(map[string]any); sa == nil || sa["args"].([]any)[0] != "mcp" {
		t.Fatalf("sec-audit entry missing: %s", b)
	}
	if bak, _ := os.ReadFile(cfgPath + ".bak"); string(bak) != orig {
		t.Fatal("backup does not hold the previous file")
	}

	out.Reset()
	if code := run([]string{"setup", "cursor"}, nil, &out, &errBuf); code != 0 || !strings.Contains(out.String(), "already configured") {
		t.Fatalf("second run should be a no-op, got %q", out.String())
	}

	_ = os.WriteFile(cfgPath, []byte("{not json"), 0o600)
	if code := run([]string{"setup", "cursor"}, nil, &out, &errBuf); code != 1 {
		t.Fatal("invalid JSON config must not be overwritten")
	}
	if b, _ := os.ReadFile(cfgPath); string(b) != "{not json" {
		t.Fatal("invalid JSON config was modified")
	}
}
