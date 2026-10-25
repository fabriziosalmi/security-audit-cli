package mcp

import (
	"bytes"
	"strings"
	"testing"
)

func TestServeStdioJSONRPC(t *testing.T) {
	input := strings.Join([]string{
		`not-valid-json`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sec_audit_catalog","arguments":{"file":"ATTACK-CLASSES.md"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sec_audit_unknown","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"unknown/method","params":{}}`,
	}, "\n") + "\n"

	var out bytes.Buffer
	if err := ServeStdio(strings.NewReader(input), &out); err != nil {
		t.Fatalf("ServeStdio failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 6 { // 1 parse error + 5 responses (notification skipped)
		t.Fatalf("expected 6 JSON-RPC responses, got %d:\n%s", len(lines), out.String())
	}
	if !strings.Contains(lines[0], "Parse error") {
		t.Fatalf("expected Parse error on line 0, got %s", lines[0])
	}
	if !strings.Contains(lines[1], `"protocolVersion":"2024-11-05"`) {
		t.Fatalf("unexpected initialize response: %s", lines[1])
	}
	if !strings.Contains(lines[2], `"sec_audit_render"`) {
		t.Fatalf("tools/list missing sec_audit_render: %s", lines[2])
	}
	if !strings.Contains(lines[3], `"isError":false`) {
		t.Fatalf("expected catalog tool call to succeed: %s", lines[3])
	}
	if !strings.Contains(lines[4], `"isError":true`) {
		t.Fatalf("expected unknown tool call to return isError=true: %s", lines[4])
	}
	if !strings.Contains(lines[5], "Method not found") {
		t.Fatalf("expected Method not found on line 5: %s", lines[5])
	}
}
