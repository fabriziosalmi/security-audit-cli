package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryOneToOneParityAndDispatch(t *testing.T) {
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
		// Malformed JSON should fail cleanly on every bound command
		if _, err := c.Invoke(json.RawMessage(`{invalid`)); err == nil {
			t.Fatalf("command %q accepted invalid JSON", c.Subcommand)
		}
	}

	// Dispatch through registry adapters: init, architecture, ledger-seed, artifact-promote, validate (both modes)
	target := t.TempDir()
	_ = os.WriteFile(filepath.Join(target, "app.go"), []byte("package main\nfunc main() {}\n"), 0o644)
	outDir := t.TempDir()

	initPayload, _ := json.Marshal(map[string]any{"target": target, "output_dir": outDir, "profile": "quick"})
	if _, err := DispatchSubcommand("init", initPayload); err != nil {
		t.Fatalf("DispatchSubcommand(init): %v", err)
	}

	archPayload, _ := json.Marshal(map[string]any{"output_dir": outDir, "content": "# Arch\nBoundaries."})
	if _, err := DispatchTool("sec_audit_architecture", archPayload); err != nil {
		t.Fatalf("DispatchTool(sec_audit_architecture): %v", err)
	}

	seedPayload, _ := json.Marshal(map[string]any{
		"output_dir": outDir,
		"units": []map[string]any{
			{
				"canonical_refs": map[string]any{
					"surface":      "app.go#main",
					"boundary":     "app.go#main",
					"subsystem":    "root",
					"attack_class": "ATTACK-CLASSES.md#Injection",
				},
				"surface":                     "main",
				"boundary":                    "main",
				"subsystem":                   "root",
				"attack_class":                "Injection",
				"starting_paths":              []string{"app.go"},
				"ordinary_attack_class_block": "ATTACK-CLASSES.md#Injection",
				"selected_companion_blocks":   []string{},
				"excluded_blocks":             []any{},
			},
		},
	})
	if _, err := DispatchTool("sec_audit_ledger_seed", seedPayload); err != nil {
		t.Fatalf("DispatchTool(sec_audit_ledger_seed): %v", err)
	}

	// Validate via OutputDir
	valOutPayload, _ := json.Marshal(map[string]any{"output_dir": outDir})
	if _, err := DispatchTool("sec_audit_validate", valOutPayload); err != nil {
		t.Fatalf("DispatchTool(sec_audit_validate output_dir): %v", err)
	}

	// Validate via direct LedgerPath + FindingsPath
	findingsFile := filepath.Join(outDir, "findings.json")
	_ = os.WriteFile(findingsFile, []byte("[]\n"), 0o600)
	valDirectPayload, _ := json.Marshal(map[string]any{
		"ledger_path":   filepath.Join(outDir, "coverage-ledger.json"),
		"findings_path": findingsFile,
		"target_path":   target,
	})
	if _, err := DispatchSubcommand("validate", valDirectPayload); err != nil {
		t.Fatalf("DispatchSubcommand(validate direct): %v", err)
	}

	// Invoke remaining adapters (agent-assign, artifact-promote, hunter-submit, critic-submit)
	assignPayload, _ := json.Marshal(map[string]any{"output_dir": outDir, "role": "recon", "agent_id": "recon-1"})
	if _, err := DispatchTool("sec_audit_agent_assign", assignPayload); err != nil {
		t.Fatalf("DispatchTool(sec_audit_agent_assign): %v", err)
	}
	_ = os.WriteFile(filepath.Join(outDir, "agents", "recon-1", "scratch", "note.txt"), []byte("fact\n"), 0o600)
	promPayload, _ := json.Marshal(map[string]any{"output_dir": outDir, "agent_id": "recon-1", "files": []string{"note.txt"}})
	if _, err := DispatchTool("sec_audit_artifact_promote", promPayload); err != nil {
		t.Fatalf("DispatchTool(sec_audit_artifact_promote): %v", err)
	}
	_, _ = DispatchTool("sec_audit_hunter_submit", json.RawMessage(`{"output_dir":"`+outDir+`","agent_id":"recon-1","result":{}}`))
	_, _ = DispatchTool("sec_audit_critic_submit", json.RawMessage(`{"output_dir":"`+outDir+`","agent_id":"recon-1","result":{}}`))

	if _, err := DispatchSubcommand("nonexistent", nil); err == nil {
		t.Fatalf("expected error on unknown subcommand")
	}
	if _, err := DispatchTool("sec_audit_nonexistent", nil); err == nil {
		t.Fatalf("expected error on unknown tool")
	}
}
