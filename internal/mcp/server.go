package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"github.com/fabriziosalmi/security-audit-cli/internal/engine"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ToolDefs returns the 12 MCP tool definitions with strict 1:1 parity to the CLI subcommands.
func ToolDefs() []map[string]any {
	return []map[string]any{
		{
			"name":        "sec_audit_init",
			"description": "Phase 1 setup: initialize audit run, enforce pre-reconnaissance budget gate, run deterministic static repo scan, and evaluate prior runs.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target":         map[string]any{"type": "string", "description": "Absolute path to target repository"},
					"output_dir":     map[string]any{"type": "string", "description": "Output directory outside target (or git-ignored inside target)"},
					"profile":        map[string]any{"type": "string", "enum": []string{"quick", "standard", "deep"}},
					"scope_paths":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"budget":         map[string]any{"type": "integer", "description": "Optional strict total agent invocation cap"},
					"prior_run_dirs": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
				"required": []string{"target"},
			},
		},
		{
			"name":        "sec_audit_catalog",
			"description": "Query embedded attack-class and companion Markdown files or extract verbatim block content by canonical reference (e.g. ATTACK-CLASSES.md#Access control).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"file":  map[string]any{"type": "string", "description": "Optional companion filename (e.g. WEB-PROTOCOL-AND-AUTH.md)"},
					"block": map[string]any{"type": "string", "description": "Optional canonical block reference (e.g. ATTACK-CLASSES.md#Injection)"},
				},
			},
		},
		{
			"name":        "sec_audit_architecture",
			"description": "Phase 1 synthesis: validate word cap (~1,000 words) and write <output-dir>/architecture.md.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"output_dir": map[string]any{"type": "string"},
					"content":    map[string]any{"type": "string"},
				},
				"required": []string{"output_dir", "content"},
			},
		},
		{
			"name":        "sec_audit_ledger_seed",
			"description": "Phase 1 coverage plan: derive canonical RFC 3986 coverage_ids, verify starting_paths on disk and block references against catalog, sort, validate, and write coverage-ledger.json.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"output_dir": map[string]any{"type": "string"},
					"units":      map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
				},
				"required": []string{"output_dir", "units"},
			},
		},
		{
			"name":        "sec_audit_agent_assign",
			"description": "Phases 1/2/3/5 orchestration: validate fresh canonical agent_id, enforce budget reserves and adversarial separation (verifier != hunter, record_verifier != hunter/verifier), create isolated scratch/ and artifacts/ directories, and compile the exact verbatim prompt.",
			"inputSchema": map[string]any{
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
		},
		{
			"name":        "sec_audit_artifact_promote",
			"description": "Execute the 11-step OS race-safe descriptor-relative promotion from agents/<agent-id>/scratch/ to agents/<agent-id>/artifacts/ with O_NOFOLLOW, Fstat link-count=1, and byte bounds.",
			"inputSchema": map[string]any{
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
		},
		{
			"name":        "sec_audit_hunter_submit",
			"description": "Phase 2 ingestion: verify hunter unit dispositions, verify all trace/evidence file:line citations on disk in target repository, validate promoted artifacts, and update coverage-ledger.json.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"output_dir": map[string]any{"type": "string"},
					"agent_id":   map[string]any{"type": "string"},
					"result":     map[string]any{"type": "object"},
				},
				"required": []string{"output_dir", "agent_id", "result"},
			},
		},
		{
			"name":        "sec_audit_critic_submit",
			"description": "Phase 2 coverage-critic ingestion: add missing coverage units, archive reopened units into attempts[] with reassignment_reason, increment wave, and validate coverage-ledger.json.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"output_dir":  map[string]any{"type": "string"},
					"agent_id":    map[string]any{"type": "string"},
					"critic_kind": map[string]any{"type": "string", "enum": []string{"post_wave", "final_clean"}},
					"result":      map[string]any{"type": "object"},
				},
				"required": []string{"output_dir", "agent_id", "result"},
			},
		},
		{
			"name":        "sec_audit_verifier_submit",
			"description": "Phase 3/4 candidate validation: enforce adversarial isolation (verifier != hunter), verify all cited source files/lines on disk, update linked ledger checks, and write sorted findings.json.",
			"inputSchema": map[string]any{
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
		},
		{
			"name":        "sec_audit_record_verify_submit",
			"description": "Phase 5 independent record verification: enforce 3-way adversarial independence, detect material replacements that require another fresh independent verifier, and update findings.json.",
			"inputSchema": map[string]any{
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
		},
		{
			"name":        "sec_audit_validate",
			"description": "Run deterministic validators on coverage-ledger.json and findings.json, plus source-file and line-number existence verification against the target repository.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"output_dir": map[string]any{"type": "string"},
				},
				"required": []string{"output_dir"},
			},
		},
		{
			"name":        "sec_audit_render",
			"description": "Phase 6 deterministic reporting: enforce terminal verification gate and generate REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md, and findings.sarif.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"output_dir":        map[string]any{"type": "string"},
					"incomplete_reason": map[string]any{"type": "string"},
				},
				"required": []string{"output_dir"},
			},
		},
	}
}

// ServeStdio runs the JSON-RPC 2.0 MCP server over r and w.
func ServeStdio(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
	enc := json.NewEncoder(w)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.Encode(jsonRPCResponse{
				JSONRPC: "2.0",
				Error:   &rpcError{Code: -32700, Message: "Parse error"},
			})
			continue
		}
		// Notifications have nil ID
		if req.ID == nil {
			continue
		}
		resp := handleRequest(req)
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func handleRequest(req jsonRPCRequest) jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
				"serverInfo": map[string]any{
					"name":    "sec-audit",
					"version": "1.0.0",
				},
			},
		}
	case "tools/list":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": ToolDefs(),
			},
		}
	case "tools/call":
		var params toolCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &rpcError{Code: -32602, Message: fmt.Sprintf("invalid params: %v", err)},
			}
		}
		out, err := DispatchTool(params.Name, params.Arguments)
		if err != nil {
			errJSON, _ := json.MarshalIndent(map[string]any{"error": err.Error()}, "", "  ")
			return jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]any{
					"isError": true,
					"content": []map[string]any{
						{"type": "text", "text": string(errJSON)},
					},
				},
			}
		}
		outJSON, _ := json.MarshalIndent(out, "", "  ")
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"isError": false,
				"content": []map[string]any{
					{"type": "text", "text": string(outJSON)},
				},
			},
		}
	default:
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32601, Message: fmt.Sprintf("Method not found: %s", req.Method)},
		}
	}
}

// DispatchTool executes one of the 12 deterministic operations by MCP tool name.
func DispatchTool(name string, rawArgs json.RawMessage) (any, error) {
	switch name {
	case "sec_audit_init":
		var req engine.InitRequest
		if err := json.Unmarshal(rawArgs, &req); err != nil {
			return nil, err
		}
		return engine.Init(req)

	case "sec_audit_catalog":
		var args struct {
			File  string `json:"file"`
			Block string `json:"block"`
		}
		if len(rawArgs) > 0 {
			if err := json.Unmarshal(rawArgs, &args); err != nil {
				return nil, err
			}
		}
		return engine.CatalogQuery(args.File, args.Block)

	case "sec_audit_architecture":
		var args struct {
			OutputDir string `json:"output_dir"`
			Content   string `json:"content"`
		}
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return nil, err
		}
		return engine.WriteArchitecture(args.OutputDir, args.Content)

	case "sec_audit_ledger_seed":
		var args struct {
			OutputDir string                 `json:"output_dir"`
			Units     []engine.SeedUnitInput `json:"units"`
		}
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return nil, err
		}
		return engine.SeedLedger(args.OutputDir, args.Units)

	case "sec_audit_agent_assign":
		var req engine.AssignAgentRequest
		if err := json.Unmarshal(rawArgs, &req); err != nil {
			return nil, err
		}
		return engine.AssignAgent(req)

	case "sec_audit_artifact_promote":
		var args struct {
			OutputDir     string   `json:"output_dir"`
			AgentID       string   `json:"agent_id"`
			Files         []string `json:"files"`
			MaxFileBytes  int64    `json:"max_file_bytes"`
			MaxTotalBytes int64    `json:"max_total_bytes"`
		}
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return nil, err
		}
		return engine.PromoteArtifacts(args.OutputDir, args.AgentID, args.Files, args.MaxFileBytes, args.MaxTotalBytes)

	case "sec_audit_hunter_submit":
		var args struct {
			OutputDir string                        `json:"output_dir"`
			AgentID   string                        `json:"agent_id"`
			Result    engine.HunterStructuredResult `json:"result"`
		}
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return nil, err
		}
		return engine.SubmitHunter(args.OutputDir, args.AgentID, args.Result)

	case "sec_audit_critic_submit":
		var args struct {
			OutputDir  string              `json:"output_dir"`
			AgentID    string              `json:"agent_id"`
			CriticKind string              `json:"critic_kind"`
			Result     engine.CriticResult `json:"result"`
		}
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return nil, err
		}
		return engine.SubmitCritic(args.OutputDir, args.AgentID, args.CriticKind, args.Result)

	case "sec_audit_verifier_submit":
		var req engine.VerifierSubmitRequest
		if err := json.Unmarshal(rawArgs, &req); err != nil {
			return nil, err
		}
		return engine.SubmitVerifier(req)

	case "sec_audit_record_verify_submit":
		var req engine.RecordVerifySubmitRequest
		if err := json.Unmarshal(rawArgs, &req); err != nil {
			return nil, err
		}
		return engine.SubmitRecordVerifier(req)

	case "sec_audit_validate":
		var args struct {
			OutputDir    string `json:"output_dir"`
			LedgerPath   string `json:"ledger_path"`
			FindingsPath string `json:"findings_path"`
			TargetPath   string `json:"target_path"`
		}
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return nil, err
		}
		if args.OutputDir != "" {
			return engine.ValidateRun(args.OutputDir)
		}
		var ledgerErrs, findingErrs []string
		if args.LedgerPath != "" {
			errs, err := validator.ValidateCoverageLedgerFile(args.LedgerPath, args.TargetPath, "", nil)
			if err != nil {
				return nil, err
			}
			ledgerErrs = errs
		}
		if args.FindingsPath != "" {
			errs, err := validator.ValidateFindingsFile(args.FindingsPath, args.TargetPath)
			if err != nil {
				return nil, err
			}
			findingErrs = errs
		}
		return map[string]any{
			"valid":          len(ledgerErrs) == 0 && len(findingErrs) == 0,
			"ledger_errors":  ledgerErrs,
			"finding_errors": findingErrs,
		}, nil

	case "sec_audit_render":
		var req engine.RenderRequest
		if err := json.Unmarshal(rawArgs, &req); err != nil {
			return nil, err
		}
		return engine.Render(req)

	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}
