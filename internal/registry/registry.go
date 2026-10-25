package registry

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/engine"
	"github.com/fabriziosalmi/security-audit-cli/internal/promote"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// Command defines a single operation exposed with strict 1:1 parity as both a CLI subcommand and an MCP tool.
type Command struct {
	Subcommand  string
	ToolName    string
	Summary     string
	Description string
	InputSchema map[string]any
	Invoke      func(raw json.RawMessage) (any, error)
}

// Bind wraps a strongly-typed request/response function into a generic JSON-marshaled Command handler.
func Bind[Req any, Resp any](fn func(Req) (Resp, error)) func(json.RawMessage) (any, error) {
	return func(raw json.RawMessage) (any, error) {
		var req Req
		if len(raw) > 0 {
			if err := validator.ValidateJSONPreflight(raw); err != nil {
				return nil, fmt.Errorf("json preflight failed: %w", err)
			}
			if err := json.Unmarshal(raw, &req); err != nil {
				return nil, err
			}
		}
		return fn(req)
	}
}

// SubcommandToToolName converts a CLI subcommand name (e.g. "ledger-seed") to its canonical 1:1 MCP tool name ("sec_audit_ledger_seed").
func SubcommandToToolName(sub string) string {
	return "sec_audit_" + strings.ReplaceAll(sub, "-", "_")
}

var commands = []Command{
	newCommand(
		"init",
		"Phase 1 setup, budget gate, static repo brief, prior-run carryover",
		"Phase 1 setup: initialize audit run, enforce pre-reconnaissance budget gate, "+
			"run deterministic static repo scan, and evaluate prior runs.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target":         map[string]any{"type": "string", "description": "Absolute path to target repository"},
				"output_dir":     map[string]any{"type": "string", "description": "Output directory outside target (or git-ignored inside target)"},
				"profile":        map[string]any{"type": "string", "enum": []string{"quick", "standard", "deep"}},
				"scope_paths":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"companions":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"budget":         map[string]any{"type": "integer", "description": "Optional strict total agent invocation cap"},
				"prior_run_dirs": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
			"required": []string{"target"},
		},
		Bind(engine.Init),
	),
	newCommand(
		"catalog",
		"Inspect embedded attack-class & companion playbooks and blocks",
		"Query embedded attack-class and companion Markdown files or extract verbatim "+
			"block content by canonical reference (e.g. ATTACK-CLASSES.md#Access control).",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"file":  map[string]any{"type": "string", "description": "Optional companion filename (e.g. WEB-PROTOCOL-AND-AUTH.md)"},
				"block": map[string]any{"type": "string", "description": "Optional canonical block reference (e.g. ATTACK-CLASSES.md#Injection)"},
			},
		},
		Bind(func(req engine.CatalogRequest) (any, error) {
			return engine.CatalogQuery(req.File, req.Block)
		}),
	),
	newCommand(
		"architecture",
		"Validate word cap (~1,000 words) and write architecture.md",
		"Phase 1 synthesis: validate word cap (~1,000 words) and write <output-dir>/architecture.md.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"output_dir": map[string]any{"type": "string"},
				"content":    map[string]any{"type": "string"},
			},
			"required": []string{"output_dir", "content"},
		},
		Bind(func(req engine.ArchitectureRequest) (map[string]any, error) {
			return engine.WriteArchitecture(req.OutputDir, req.Content)
		}),
	),
	newCommand(
		"ledger-seed",
		"Derive canonical RFC 3986 coverage_ids, verify paths/blocks, seed ledger",
		"Phase 1 coverage plan: derive canonical RFC 3986 coverage_ids, verify starting_paths "+
			"on disk and block references against catalog, optionally carry over SHA-256 "+
			"unchanged clean units, sort, validate, and write coverage-ledger.json.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"output_dir": map[string]any{"type": "string"},
				"units":      map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
				"carryover_unchanged": map[string]any{
					"type":        "boolean",
					"description": "Automatically promote units whose starting_paths and reviewed_paths are SHA-256 unchanged from prior_run_dirs",
				},
			},
			"required": []string{"output_dir", "units"},
		},
		Bind(func(req engine.SeedLedgerRequest) ([]validator.CoverageUnit, error) {
			return engine.SeedLedgerWithOptions(req.OutputDir, req.Units, req.CarryoverUnchanged)
		}),
	),
	newCommand(
		"agent-assign",
		"Enforce adversarial isolation & budget reserves, create scratch/artifacts, compile prompt",
		"Phases 1/2/3/5 orchestration: validate fresh canonical agent_id, enforce budget reserves "+
			"and adversarial separation (verifier != hunter, record_verifier != hunter/verifier), "+
			"create isolated scratch/ and artifacts/ directories, and compile the exact verbatim prompt.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"output_dir":   map[string]any{"type": "string"},
				"role":         map[string]any{"type": "string", "enum": []string{"recon", "hunter", "critic", "verifier", "record_verifier"}},
				"agent_id":     map[string]any{"type": "string"},
				"coverage_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"fingerprint":  map[string]any{"type": "string"},
			},
			"required": []string{"output_dir", "role", "agent_id"},
		},
		Bind(engine.AssignAgent),
	),
	newCommand(
		"artifact-promote",
		"Execute 11-step OS race-safe O_NOFOLLOW promotion from scratch/ to artifacts/",
		"Execute the 11-step OS race-safe descriptor-relative promotion from "+
			"agents/<agent-id>/scratch/ to agents/<agent-id>/artifacts/ with O_NOFOLLOW, Fstat link-count=1, and byte bounds.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"output_dir":      map[string]any{"type": "string"},
				"agent_id":        map[string]any{"type": "string"},
				"files":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"max_file_bytes":  map[string]any{"type": "integer"},
				"max_total_bytes": map[string]any{"type": "integer"},
			},
			"required": []string{"output_dir", "agent_id", "files"},
		},
		Bind(func(req engine.PromoteArtifactsRequest) ([]promote.PromotedArtifact, error) {
			return engine.PromoteArtifacts(req.OutputDir, req.AgentID, req.Files, req.MaxFileBytes, req.MaxTotalBytes)
		}),
	),
	newCommand(
		"hunter-submit",
		"Verify source file:line citations on disk and update coverage-ledger.json",
		"Phase 2 ingestion: verify hunter unit dispositions, verify all trace/evidence file:line "+
			"citations on disk in target repository, validate promoted artifacts, and update coverage-ledger.json.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"output_dir": map[string]any{"type": "string"},
				"agent_id":   map[string]any{"type": "string"},
				"result":     map[string]any{"type": "object"},
			},
			"required": []string{"output_dir", "agent_id", "result"},
		},
		Bind(func(req engine.SubmitHunterRequest) (map[string]any, error) {
			return engine.SubmitHunter(req.OutputDir, req.AgentID, req.Result)
		}),
	),
	newCommand(
		"critic-submit",
		"Archive reopened attempts, add missing units, advance hunting wave",
		"Phase 2 coverage-critic ingestion: add missing coverage units, archive reopened units "+
			"into attempts[] with reassignment_reason, increment wave, and validate coverage-ledger.json.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"output_dir":  map[string]any{"type": "string"},
				"agent_id":    map[string]any{"type": "string"},
				"critic_kind": map[string]any{"type": "string", "enum": []string{"post_wave", "final_clean"}},
				"result":      map[string]any{"type": "object"},
			},
			"required": []string{"output_dir", "agent_id", "result"},
		},
		Bind(func(req engine.SubmitCriticRequest) (map[string]any, error) {
			return engine.SubmitCritic(req.OutputDir, req.AgentID, req.CriticKind, req.Result)
		}),
	),
	newCommand(
		"verifier-submit",
		"Enforce verifier != hunter, verify source trace on disk, update findings.json",
		"Phase 3/4 candidate validation: enforce adversarial isolation (verifier != hunter), "+
			"verify all cited source files/lines on disk, update linked ledger checks, and write sorted findings.json.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"output_dir":  map[string]any{"type": "string"},
				"agent_id":    map[string]any{"type": "string"},
				"fingerprint": map[string]any{"type": "string"},
				"decision":    map[string]any{"type": "string", "enum": []string{"confirmed", "needs_validation", "rejected"}},
				"record":      map[string]any{"type": "object"},
				"check":       map[string]any{"type": "object"},
			},
			"required": []string{"output_dir", "agent_id", "fingerprint", "decision", "record"},
		},
		Bind(engine.SubmitVerifier),
	),
	newCommand(
		"record-verify-submit",
		"Enforce 3-way adversarial independence & material-replacement gate (Phase 5)",
		"Phase 5 independent record verification: enforce 3-way adversarial independence, detect "+
			"material replacements that require another fresh independent verifier, and update findings.json.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"output_dir":  map[string]any{"type": "string"},
				"agent_id":    map[string]any{"type": "string"},
				"fingerprint": map[string]any{"type": "string"},
				"decision":    map[string]any{"type": "string", "enum": []string{"verified", "replace"}},
				"reason":      map[string]any{"type": "string"},
				"record":      map[string]any{"type": "object"},
			},
			"required": []string{"output_dir", "agent_id", "fingerprint", "decision"},
		},
		Bind(engine.SubmitRecordVerifier),
	),
	newCommand(
		"validate",
		"Validate coverage-ledger.json, findings.json, source paths/hashes on disk, and optional CI gate",
		"Run deterministic validators on coverage-ledger.json and findings.json, plus "+
			"source-file, line-number, and SHA-256 drift verification against the target repository.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"output_dir":    map[string]any{"type": "string"},
				"ledger_path":   map[string]any{"type": "string"},
				"findings_path": map[string]any{"type": "string"},
				"target_path":   map[string]any{"type": "string"},
				"fail_on":       map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "needs_validation", "any"}},
			},
		},
		Bind(func(req engine.ValidateRequest) (map[string]any, error) {
			if req.OutputDir != "" {
				return engine.ValidateRunWithGate(req.OutputDir, req.FailOn)
			}
			var ledgerErrs, findingErrs []string
			if req.LedgerPath != "" {
				errs, err := validator.ValidateCoverageLedgerFile(req.LedgerPath, req.TargetPath, "", nil)
				if err != nil {
					return nil, err
				}
				ledgerErrs = errs
			}
			var findings []validator.Finding
			if req.FindingsPath != "" {
				errs, err := validator.ValidateFindingsFile(req.FindingsPath, req.TargetPath)
				if err != nil {
					return nil, err
				}
				findingErrs = errs
				if raw, rerr := validator.ReadFileNoFollow(req.FindingsPath); rerr == nil {
					_ = json.Unmarshal(raw, &findings)
				}
			}
			gatePassed, gateReason, gerr := engine.EvaluateFailOnGate(req.FailOn, findings)
			if gerr != nil {
				return nil, gerr
			}
			res := map[string]any{
				"valid":          len(ledgerErrs) == 0 && len(findingErrs) == 0,
				"gate_passed":    gatePassed,
				"ledger_errors":  ledgerErrs,
				"finding_errors": findingErrs,
			}
			if gateReason != "" {
				res["gate_failure_reason"] = gateReason
			}
			return res, nil
		}),
	),
	newCommand(
		"render",
		"Deterministically generate REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md, advisories/GHSA-*.md, findings.sarif",
		"Phase 6 deterministic reporting: enforce terminal verification gate and generate "+
			"REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md, standalone GHSA advisories, and findings.sarif.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"output_dir":        map[string]any{"type": "string"},
				"incomplete_reason": map[string]any{"type": "string"},
				"fail_on":           map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "needs_validation", "any"}},
			},
			"required": []string{"output_dir"},
		},
		Bind(engine.Render),
	),
	newCommand(
		"status",
		"Return zero-token run progress summary, source drift check, and exact next required actions",
		"Inspect an audit run directory and return a compact deterministic summary of unit counts, "+
			"unvalidated candidates, unverified Phase 5 records, source file SHA-256 drift, and the exact next required actions.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"output_dir": map[string]any{"type": "string"},
			},
			"required": []string{"output_dir"},
		},
		Bind(engine.Status),
	),
}

func newCommand(sub, summary, desc string, schema map[string]any, invoke func(json.RawMessage) (any, error)) Command {
	return Command{
		Subcommand:  sub,
		ToolName:    SubcommandToToolName(sub),
		Summary:     summary,
		Description: desc,
		InputSchema: schema,
		Invoke:      invoke,
	}
}

// All returns a copy of all registered 1:1 CLI/MCP commands in canonical phase order.
func All() []Command {
	out := make([]Command, len(commands))
	copy(out, commands)
	return out
}

// BySubcommand looks up a Command by its CLI subcommand name.
func BySubcommand(sub string) (Command, bool) {
	for _, c := range commands {
		if c.Subcommand == sub {
			return c, true
		}
	}
	return Command{}, false
}

// ByToolName looks up a Command by its MCP tool name.
func ByToolName(name string) (Command, bool) {
	for _, c := range commands {
		if c.ToolName == name {
			return c, true
		}
	}
	return Command{}, false
}

// ToolDefs generates the MCP tools/list metadata directly from the unified command registry.
func ToolDefs() []map[string]any {
	defs := make([]map[string]any, 0, len(commands))
	for _, c := range commands {
		defs = append(defs, map[string]any{
			"name":        c.ToolName,
			"description": c.Description,
			"inputSchema": c.InputSchema,
		})
	}
	return defs
}

// DispatchTool executes a command by its MCP tool name.
func DispatchTool(name string, rawArgs json.RawMessage) (any, error) {
	cmd, ok := ByToolName(name)
	if !ok {
		return nil, fmt.Errorf("unknown tool %q", name)
	}
	return cmd.Invoke(rawArgs)
}

// DispatchSubcommand executes a command by its CLI subcommand name.
func DispatchSubcommand(sub string, rawArgs json.RawMessage) (any, error) {
	cmd, ok := BySubcommand(sub)
	if !ok {
		return nil, fmt.Errorf("unknown subcommand %q", sub)
	}
	return cmd.Invoke(rawArgs)
}
