package registry

import (
	"encoding/json"
	"testing"
)

func TestRegistryOneToOneParity(t *testing.T) {
	all := All()
	if len(all) != 12 {
		t.Fatalf("expected 12 registered commands, got %d", len(all))
	}
	defs := ToolDefs()
	if len(defs) != len(all) {
		t.Fatalf("ToolDefs count mismatch: %d vs %d", len(defs), len(all))
	}

	seenSub := make(map[string]bool)
	seenTool := make(map[string]bool)
	for i, c := range all {
		expectedTool := SubcommandToToolName(c.Subcommand)
		if c.ToolName != expectedTool {
			t.Fatalf("command[%d] 1:1 naming mismatch: sub=%q tool=%q expected=%q", i, c.Subcommand, c.ToolName, expectedTool)
		}
		if c.Summary == "" || c.Description == "" || c.InputSchema == nil || c.Invoke == nil {
			t.Fatalf("command[%d] (%s) has incomplete descriptor", i, c.Subcommand)
		}
		if seenSub[c.Subcommand] || seenTool[c.ToolName] {
			t.Fatalf("duplicate command registration: %s / %s", c.Subcommand, c.ToolName)
		}
		seenSub[c.Subcommand] = true
		seenTool[c.ToolName] = true

		if _, ok := BySubcommand(c.Subcommand); !ok {
			t.Fatalf("BySubcommand(%q) failed", c.Subcommand)
		}
		if _, ok := ByToolName(c.ToolName); !ok {
			t.Fatalf("ByToolName(%q) failed", c.ToolName)
		}
	}

	// Verify DispatchSubcommand and DispatchTool on catalog
	res1, err := DispatchSubcommand("catalog", json.RawMessage(`{"file":"ATTACK-CLASSES.md"}`))
	if err != nil || res1 == nil {
		t.Fatalf("DispatchSubcommand(catalog) failed: %v", err)
	}
	res2, err := DispatchTool("sec_audit_catalog", json.RawMessage(`{"file":"ATTACK-CLASSES.md"}`))
	if err != nil || res2 == nil {
		t.Fatalf("DispatchTool(sec_audit_catalog) failed: %v", err)
	}

	if _, err := DispatchSubcommand("nonexistent", nil); err == nil {
		t.Fatalf("expected error on unknown subcommand")
	}
	if _, err := DispatchTool("sec_audit_nonexistent", nil); err == nil {
		t.Fatalf("expected error on unknown tool")
	}
}
