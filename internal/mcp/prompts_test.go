package mcp

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/registry"
)

func TestPromptsListAndGet(t *testing.T) {
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"audit","arguments":{"target":"/src/app"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"audit","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"nope","arguments":{"target":"/x"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"prompts/get","params":{"name":"audit","arguments":{"target":"/x","profile":"turbo"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"ping"}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := ServeStdio(strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected 6 responses, got %d:\n%s", len(lines), out.String())
	}
	if !strings.Contains(lines[0], `"name":"audit"`) {
		t.Fatalf("prompts/list: %s", lines[0])
	}
	var got struct {
		Result struct {
			Messages []struct {
				Content struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"messages"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &got); err != nil || len(got.Result.Messages) != 1 {
		t.Fatalf("prompts/get: %v %s", err, lines[1])
	}
	text := got.Result.Messages[0].Content.Text
	if !strings.Contains(text, "target=/src/app") || !strings.Contains(text, "output_dir=/src/app-sec-audit") ||
		!strings.Contains(text, "profile=standard") || strings.Contains(text, "{{") {
		t.Fatalf("placeholders not filled:\n%s", text)
	}
	for i, want := range map[int]string{2: "target is required", 3: "unknown prompt", 4: "profile must be"} {
		if !strings.Contains(lines[i], want) || !strings.Contains(lines[i], `"error"`) {
			t.Fatalf("line %d: want error %q, got %s", i, want, lines[i])
		}
	}
	if !strings.Contains(lines[5], `"result":{}`) {
		t.Fatalf("ping: %s", lines[5])
	}
}

// Every tool the playbook or the instructions name must exist, so the text
// cannot drift from the registry.
func TestPlaybookNamesOnlyRealTools(t *testing.T) {
	re := regexp.MustCompile(`sec_audit_[a-z_]+`)
	seen := 0
	for _, name := range re.FindAllString(auditPlaybook+Instructions, -1) {
		if _, ok := registry.ByToolName(name); !ok {
			t.Errorf("playbook names %s, which is not a registered tool", name)
		}
		seen++
	}
	if seen < 10 {
		t.Fatalf("expected the playbook to reference the tools, found %d references", seen)
	}
}

func TestNegotiateProtocol(t *testing.T) {
	for in, want := range map[string]string{
		`{"protocolVersion":"2025-03-26"}`: "2025-03-26",
		`{"protocolVersion":"2099-01-01"}`: "2024-11-05",
		`{}`:                               "2024-11-05",
	} {
		if got := negotiateProtocol(json.RawMessage(in)); got != want {
			t.Errorf("negotiateProtocol(%s) = %s, want %s", in, got, want)
		}
	}
}
