package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// lookPath and runCmd are replaced in tests.
var (
	lookPath = exec.LookPath
	runCmd   = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}
	executable = os.Executable
)

const setupUsage = `Usage: sec-audit setup <client> [--print]

Registers sec-audit as an MCP server so your agent can run audits.

Clients:
  claude          Claude Code (runs: claude mcp add --scope user sec-audit -- <binary> mcp)
  cursor          Cursor (~/.cursor/mcp.json)
  claude-desktop  Claude Desktop (claude_desktop_config.json)
  print           Show the configuration for every client and change nothing

--print shows what would change without changing it.
`

func runSetup(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, setupUsage)
		if len(args) == 0 {
			return 1
		}
		return 0
	}
	client := args[0]
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dry := fs.Bool("print", false, "show the change without applying it")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	bin, err := executable()
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot locate the sec-audit binary: %v\n", err)
		return 1
	}
	if resolved, rerr := filepath.EvalSymlinks(bin); rerr == nil {
		bin = resolved
	}

	switch client {
	case "print":
		printAllConfigs(stdout, bin)
		return 0
	case "claude":
		return setupClaudeCode(stdout, stderr, bin, *dry)
	case "cursor", "claude-desktop":
		path, err := clientConfigPath(client)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		return setupJSONClient(stdout, stderr, client, path, bin, *dry)
	default:
		fmt.Fprintf(stderr, "unknown client %q\n\n%s", client, setupUsage)
		return 1
	}
}

func setupClaudeCode(stdout, stderr io.Writer, bin string, dry bool) int {
	args := []string{"mcp", "add", "--scope", "user", "sec-audit", "--", bin, "mcp"}
	if dry {
		fmt.Fprintf(stdout, "would run: claude %s\n", shellJoin(args))
		return 0
	}
	if _, err := lookPath("claude"); err != nil {
		fmt.Fprintf(stderr, "the claude CLI is not on PATH. Run this once it is installed:\n  claude %s\n", shellJoin(args))
		return 1
	}
	out, err := runCmd("claude", args...)
	if err != nil {
		if bytes.Contains(bytes.ToLower(out), []byte("already exists")) {
			fmt.Fprintf(stdout, "sec-audit is already registered in Claude Code.\n"+
				"To point it at this binary: claude mcp remove --scope user sec-audit && sec-audit setup claude\n")
			return 0
		}
		fmt.Fprintf(stderr, "claude mcp add failed: %v\n%s", err, out)
		return 1
	}
	fmt.Fprintf(stdout, "Registered sec-audit in Claude Code (user scope) -> %s mcp\n\n", bin)
	fmt.Fprintf(stdout, "Next: start a new Claude Code session in any repository and run\n"+
		"  /mcp__sec-audit__audit <absolute path of the repository>\n"+
		"or ask: \"audit this repository with sec-audit\".\n")
	return 0
}

func clientConfigPath(client string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch client {
	case "cursor":
		return filepath.Join(home, ".cursor", "mcp.json"), nil
	case "claude-desktop":
		switch runtime.GOOS {
		case "darwin":
			return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
		case "linux":
			return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), nil
		}
		return "", fmt.Errorf("claude-desktop setup is supported on macOS and Linux; use 'sec-audit setup print'")
	}
	return "", fmt.Errorf("unknown client %q", client)
}

func serverEntry(bin string) map[string]any {
	return map[string]any{"command": bin, "args": []any{"mcp"}}
}

// setupJSONClient adds mcpServers["sec-audit"] to a JSON config file, keeping
// every other key, and writes a .bak copy of the previous file first.
func setupJSONClient(stdout, stderr io.Writer, client, path, bin string, dry bool) int {
	cfg := map[string]any{}
	orig, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		orig = nil
	case err != nil:
		fmt.Fprintf(stderr, "error: read %s: %v\n", path, err)
		return 1
	case len(bytes.TrimSpace(orig)) > 0:
		if err := json.Unmarshal(orig, &cfg); err != nil {
			fmt.Fprintf(stderr, "error: %s is not valid JSON (%v); fix it or run 'sec-audit setup print'\n", path, err)
			return 1
		}
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		if _, exists := cfg["mcpServers"]; exists {
			fmt.Fprintf(stderr, "error: mcpServers in %s is not an object\n", path)
			return 1
		}
		servers = map[string]any{}
	}
	want := serverEntry(bin)
	if cur, ok := servers["sec-audit"]; ok {
		a, _ := json.Marshal(cur)
		b, _ := json.Marshal(want)
		if bytes.Equal(a, b) {
			fmt.Fprintf(stdout, "sec-audit is already configured in %s\n", path)
			return 0
		}
	}
	servers["sec-audit"] = want
	cfg["mcpServers"] = servers
	next, _ := json.MarshalIndent(cfg, "", "  ")
	next = append(next, '\n')
	if dry {
		fmt.Fprintf(stdout, "would write %s:\n%s", path, next)
		return 0
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if orig != nil {
		if err := os.WriteFile(path+".bak", orig, 0o600); err != nil {
			fmt.Fprintf(stderr, "error: backup %s.bak: %v\n", path, err)
			return 1
		}
	}
	if err := os.WriteFile(path, next, 0o600); err != nil {
		fmt.Fprintf(stderr, "error: write %s: %v\n", path, err)
		return 1
	}
	fmt.Fprintf(stdout, "Added sec-audit to %s", path)
	if orig != nil {
		fmt.Fprintf(stdout, " (previous file saved as %s.bak)", filepath.Base(path))
	}
	fmt.Fprintf(stdout, "\nRestart %s, then ask it to \"audit <repository path> with sec-audit\".\n", client)
	return 0
}

func printAllConfigs(w io.Writer, bin string) {
	snippet, _ := json.MarshalIndent(map[string]any{"mcpServers": map[string]any{"sec-audit": serverEntry(bin)}}, "", "  ")
	fmt.Fprintf(w, "Claude Code:\n  claude mcp add --scope user sec-audit -- %s mcp\n\n", shellQuote(bin))
	fmt.Fprintf(w, "Cursor, Claude Desktop, Windsurf, Antigravity and other JSON-configured clients:\n%s\n\n", snippet)
	fmt.Fprintf(w, "Codex (~/.codex/config.toml):\n  [mcp_servers.sec-audit]\n  command = %q\n  args = [\"mcp\"]\n", bin)
}

func shellQuote(s string) string {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '/' || c == '.' || c == '_' || c == '-') {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

func shellJoin(args []string) string {
	var b bytes.Buffer
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(shellQuote(a))
	}
	return b.String()
}
