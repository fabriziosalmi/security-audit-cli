package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/mcp"
)

var subcommandToTool = map[string]string{
	"init":                 "sec_audit_init",
	"catalog":              "sec_audit_catalog",
	"architecture":         "sec_audit_architecture",
	"ledger-seed":          "sec_audit_ledger_seed",
	"agent-assign":         "sec_audit_agent_assign",
	"artifact-promote":     "sec_audit_artifact_promote",
	"hunter-submit":        "sec_audit_hunter_submit",
	"critic-submit":        "sec_audit_critic_submit",
	"verifier-submit":      "sec_audit_verifier_submit",
	"record-verify-submit": "sec_audit_record_verify_submit",
	"validate":             "sec_audit_validate",
	"render":               "sec_audit_render",
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	sub := os.Args[1]
	if sub == "-h" || sub == "--help" || sub == "help" {
		printUsage()
		os.Exit(0)
	}
	if sub == "mcp" {
		if err := mcp.ServeStdio(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "mcp server error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	toolName, ok := subcommandToTool[sub]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", sub)
		printUsage()
		os.Exit(1)
	}

	rawArgs, err := parseSubcommandFlags(sub, os.Args[2:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	res, err := mcp.DispatchTool(toolName, rawArgs)
	if err != nil {
		errOut, _ := json.MarshalIndent(map[string]any{"error": err.Error()}, "", "  ")
		fmt.Fprintln(os.Stderr, string(errOut))
		os.Exit(1)
	}

	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	// Exit 1 if validate returned valid: false
	if m, isMap := res.(map[string]any); isMap {
		if v, hasValid := m["valid"].(bool); hasValid && !v {
			os.Exit(1)
		}
	}
}

func parseSubcommandFlags(sub string, args []string) (json.RawMessage, error) {
	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	jsonInput := fs.String("json", "", "Raw JSON input object (or '-' to read from stdin)")
	inputFile := fs.String("input", "", "Path to JSON input file")

	// Common convenience flags across subcommands
	target := fs.String("target", "", "Target repository path")
	outputDir := fs.String("output-dir", "", "Audit run output directory")
	profile := fs.String("profile", "", "Audit profile (quick, standard, deep)")
	budget := fs.Int("budget", -1, "Optional total agent invocation budget")
	scopePaths := fs.String("scope-paths", "", "Comma-separated repository-relative scope paths")
	fileFlag := fs.String("file", "", "Companion file name or content file path")
	blockFlag := fs.String("block", "", "Canonical block reference (e.g. ATTACK-CLASSES.md#Injection)")
	contentFlag := fs.String("content", "", "Markdown content string")
	role := fs.String("role", "", "Agent role (recon, hunter, critic, verifier, record_verifier)")
	agentID := fs.String("agent-id", "", "Canonical lowercase agent ID")
	coverageIDs := fs.String("coverage-ids", "", "Comma-separated coverage_ids")
	fingerprint := fs.String("fingerprint", "", "Finding/candidate fingerprint")
	filesList := fs.String("files", "", "Comma-separated scratch-relative files to promote")
	maxFileBytes := fs.Int64("max-file-bytes", 0, "Per-file promotion byte limit")
	maxTotalBytes := fs.Int64("max-total-bytes", 0, "Cumulative promotion byte limit")
	criticKind := fs.String("critic-kind", "post_wave", "Critic kind (post_wave or final_clean)")
	decision := fs.String("decision", "", "Verifier decision")
	reason := fs.String("reason", "", "Reason for replacement or incomplete run")
	ledgerPath := fs.String("ledger", "", "Direct path to coverage-ledger.json")
	findingsPath := fs.String("findings", "", "Direct path to findings.json")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if *jsonInput != "" {
		if *jsonInput == "-" {
			b, err := io.ReadAll(os.Stdin)
			return json.RawMessage(b), err
		}
		return json.RawMessage(*jsonInput), nil
	}

	payload := make(map[string]any)
	if *inputFile != "" {
		b, err := os.ReadFile(*inputFile)
		if err != nil {
			return nil, fmt.Errorf("read --input %q: %w", *inputFile, err)
		}
		// For ledger-seed, if input file is a JSON array, wrap it in {"units": ...}
		trimmed := strings.TrimSpace(string(b))
		if sub == "ledger-seed" && strings.HasPrefix(trimmed, "[") {
			var arr []any
			if err := json.Unmarshal(b, &arr); err != nil {
				return nil, err
			}
			payload["units"] = arr
		} else if (sub == "hunter-submit" || sub == "critic-submit") && !strings.Contains(trimmed, `"output_dir"`) {
			var obj map[string]any
			if err := json.Unmarshal(b, &obj); err != nil {
				return nil, err
			}
			payload["result"] = obj
		} else if (sub == "verifier-submit" || sub == "record-verify-submit") && !strings.Contains(trimmed, `"output_dir"`) {
			var obj map[string]any
			if err := json.Unmarshal(b, &obj); err != nil {
				return nil, err
			}
			payload["record"] = obj
		} else {
			if err := json.Unmarshal(b, &payload); err != nil {
				return nil, err
			}
		}
	}

	setIfNotEmpty := func(k, v string) {
		if v != "" {
			payload[k] = v
		}
	}
	setSliceIfNotEmpty := func(k, csv string) {
		if csv != "" {
			var parts []string
			for _, p := range strings.Split(csv, ",") {
				if trimmed := strings.TrimSpace(p); trimmed != "" {
					parts = append(parts, trimmed)
				}
			}
			payload[k] = parts
		}
	}

	setIfNotEmpty("target", *target)
	setIfNotEmpty("output_dir", *outputDir)
	setIfNotEmpty("profile", *profile)
	if *budget >= 0 {
		payload["budget"] = *budget
	}
	setSliceIfNotEmpty("scope_paths", *scopePaths)
	if sub == "catalog" {
		setIfNotEmpty("file", *fileFlag)
		setIfNotEmpty("block", *blockFlag)
	}
	if sub == "architecture" {
		if *contentFlag != "" {
			payload["content"] = *contentFlag
		} else if *fileFlag != "" {
			b, err := os.ReadFile(*fileFlag)
			if err != nil {
				return nil, err
			}
			payload["content"] = string(b)
		}
	}
	setIfNotEmpty("role", *role)
	setIfNotEmpty("agent_id", *agentID)
	setSliceIfNotEmpty("coverage_ids", *coverageIDs)
	setIfNotEmpty("fingerprint", *fingerprint)
	setSliceIfNotEmpty("files", *filesList)
	if *maxFileBytes > 0 {
		payload["max_file_bytes"] = *maxFileBytes
	}
	if *maxTotalBytes > 0 {
		payload["max_total_bytes"] = *maxTotalBytes
	}
	if sub == "critic-submit" {
		setIfNotEmpty("critic_kind", *criticKind)
	}
	setIfNotEmpty("decision", *decision)
	if sub == "render" {
		setIfNotEmpty("incomplete_reason", *reason)
	} else {
		setIfNotEmpty("reason", *reason)
	}
	setIfNotEmpty("ledger_path", *ledgerPath)
	setIfNotEmpty("findings_path", *findingsPath)
	if sub == "validate" && *target != "" {
		payload["target_path"] = *target
	}

	b, err := json.Marshal(payload)
	return json.RawMessage(b), err
}

func printUsage() {
	fmt.Println(`sec-audit — Deterministic 6-Phase Security Audit CLI & MCP Server (1:1 parity)

Usage:
  sec-audit <subcommand> [flags]
  sec-audit mcp

Subcommands (1:1 with MCP tools sec_audit_<subcommand>):
  init                  Phase 1 setup, budget gate, static repo brief, prior-run carryover
  catalog               Inspect embedded attack-class & companion playbooks and blocks
  architecture          Validate word cap (~1,000 words) and write architecture.md
  ledger-seed           Derive canonical RFC 3986 coverage_ids, verify paths/blocks, seed ledger
  agent-assign          Enforce adversarial isolation & budget reserves, create scratch/artifacts, compile prompt
  artifact-promote      Execute 11-step OS race-safe O_NOFOLLOW promotion from scratch/ to artifacts/
  hunter-submit         Verify source file:line citations on disk and update coverage-ledger.json
  critic-submit         Archive reopened attempts, add missing units, advance hunting wave
  verifier-submit       Enforce verifier != hunter, verify source trace on disk, update findings.json
  record-verify-submit  Enforce 3-way adversarial independence & material-replacement gate (Phase 5)
  validate              Validate coverage-ledger.json, findings.json, and source paths on disk
  render                Deterministically generate REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md, findings.sarif
  mcp                   Run JSON-RPC 2.0 MCP server over stdio`)
}
