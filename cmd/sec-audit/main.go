package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/demo"
	"github.com/fabriziosalmi/security-audit-cli/internal/engine"
	"github.com/fabriziosalmi/security-audit-cli/internal/mcp"
	"github.com/fabriziosalmi/security-audit-cli/internal/registry"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// Version is the canonical semantic version of sec-audit.
var Version = "0.2.2"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		printUsage(stdout)
		return 1
	}
	sub := args[0]
	if sub == "-h" || sub == "--help" || sub == "help" {
		printUsage(stdout)
		return 0
	}
	rest, format, err := extractFormat(args[1:])
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	text := format == formatText || (format == formatAuto && isTerminal(stdout))
	t := tty{w: stdout, color: format != formatJSON && useColor(stdout)}

	switch sub {
	case "-v", "--version", "version":
		if text {
			fmt.Fprintf(stdout, "sec-audit %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
			return 0
		}
		vOut, _ := json.MarshalIndent(map[string]string{
			"name":    "sec-audit",
			"version": Version,
			"os":      runtime.GOOS,
			"arch":    runtime.GOARCH,
		}, "", "  ")
		fmt.Fprintln(stdout, string(vOut))
		return 0
	case "mcp":
		mcp.Version = Version
		if err := mcp.ServeStdio(stdin, stdout); err != nil {
			fmt.Fprintf(stderr, "mcp server error: %v\n", err)
			return 1
		}
		return 0
	case "demo":
		return runDemo(rest, stdout, stderr, t.color)
	case "setup":
		return runSetup(rest, stdout, stderr)
	}

	if _, ok := registry.BySubcommand(sub); !ok {
		fmt.Fprintf(stderr, "unknown subcommand %q\n\n", sub)
		printUsage(stderr)
		return 1
	}

	rawArgs, err := parseSubcommandFlags(sub, rest, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	res, err := registry.DispatchSubcommand(sub, rawArgs)
	if err != nil {
		if text {
			fmt.Fprintf(stderr, "%s %s\n", tty{w: stderr, color: useColor(stderr)}.s("1;31", "error:"), err.Error())
			return 1
		}
		errOut, _ := json.MarshalIndent(map[string]any{"error": err.Error()}, "", "  ")
		fmt.Fprintln(stderr, string(errOut))
		return 1
	}

	if !text || !renderText(sub, res, t) {
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Fprintln(stdout, string(out))
	}
	if m, isMap := res.(map[string]any); isMap {
		if v, hasValid := m["valid"].(bool); hasValid && !v {
			return 1
		}
		if gp, hasGate := m["gate_passed"].(bool); hasGate && !gp {
			return 2
		}
	}
	if rr, isRender := res.(*engine.RenderResponse); isRender && !rr.GatePassed {
		return 2
	}
	return 0
}

func parseSubcommandFlags(sub string, args []string, stdin io.Reader) (json.RawMessage, error) {
	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	jsonInput := fs.String("json", "", "Raw JSON input object (or '-' to read from stdin)")
	inputFile := fs.String("input", "", "Path to JSON input file")

	target := fs.String("target", "", "Target repository path")
	outputDir := fs.String("output-dir", "", "Audit run output directory")
	profile := fs.String("profile", "", "Audit profile (quick, standard, deep)")
	budget := fs.Int("budget", -1, "Optional total agent invocation budget")
	scopePaths := fs.String("scope-paths", "", "Comma-separated repository-relative scope paths")
	companions := fs.String("companions", "", "Comma-separated companion files override (or 'none')")
	priorRunDirs := fs.String("prior-run-dirs", "", "Comma-separated prior audit run directories")
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
	criticKind := fs.String("critic-kind", "", "Critic kind (post_wave or final_clean)")
	decision := fs.String("decision", "", "Verifier decision")
	reason := fs.String("reason", "", "Reason for replacement or incomplete run")
	ledgerPath := fs.String("ledger", "", "Direct path to coverage-ledger.json")
	findingsPath := fs.String("findings", "", "Direct path to findings.json")
	carryoverUnchanged := fs.Bool("carryover-unchanged", false, "Carry over SHA-256 unchanged clean units from prior runs")
	failOn := fs.String("fail-on", "", "CI exit gate threshold (critical, high, medium, low, needs_validation, any)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	payload := make(map[string]any)
	unmarshalInputBytes := func(b []byte) error {
		trimmed := strings.TrimSpace(string(b))
		if sub == "ledger-seed" && strings.HasPrefix(trimmed, "[") {
			var arr []any
			if err := json.Unmarshal(b, &arr); err != nil {
				return err
			}
			payload["units"] = arr
			return nil
		}
		var obj map[string]any
		if err := json.Unmarshal(b, &obj); err != nil {
			return err
		}
		_, hasOutDir := obj["output_dir"]
		_, hasResult := obj["result"]
		_, hasRecord := obj["record"]
		if (sub == "hunter-submit" || sub == "critic-submit") && !hasOutDir && !hasResult {
			payload["result"] = obj
		} else if (sub == "verifier-submit" || sub == "record-verify-submit") && !hasOutDir && !hasRecord {
			payload["record"] = obj
		} else {
			for k, v := range obj {
				payload[k] = v
			}
		}
		return nil
	}

	hasExtraFlags := *target != "" || *outputDir != "" || *profile != "" || *budget >= 0 ||
		*scopePaths != "" || *companions != "" || *priorRunDirs != "" || *fileFlag != "" ||
		*blockFlag != "" || *contentFlag != "" || *role != "" || *agentID != "" ||
		*coverageIDs != "" || *fingerprint != "" || *filesList != "" || *maxFileBytes > 0 ||
		*maxTotalBytes > 0 || *criticKind != "" || *decision != "" || *reason != "" ||
		*ledgerPath != "" || *findingsPath != "" || *carryoverUnchanged || *failOn != ""

	if *jsonInput != "" {
		var b []byte
		if *jsonInput == "-" {
			var err error
			b, err = io.ReadAll(io.LimitReader(stdin, validator.MaxInputBytes+1))
			if err != nil {
				return nil, err
			}
			if int64(len(b)) > validator.MaxInputBytes {
				return nil, fmt.Errorf("stdin input exceeds %d byte limit", validator.MaxInputBytes)
			}
		} else {
			b = []byte(*jsonInput)
		}
		if !hasExtraFlags {
			return json.RawMessage(b), nil
		}
		if err := validator.ValidateJSONPreflight(b); err != nil {
			return nil, fmt.Errorf("invalid --json: %w", err)
		}
		if err := unmarshalInputBytes(b); err != nil {
			return nil, err
		}
	}

	if *inputFile != "" {
		b, err := validator.ReadFileNoFollow(*inputFile)
		if err != nil {
			return nil, fmt.Errorf("read --input %q: %w", *inputFile, err)
		}
		if err := validator.ValidateJSONPreflight(b); err != nil {
			return nil, fmt.Errorf("invalid --input %q: %w", *inputFile, err)
		}
		if err := unmarshalInputBytes(b); err != nil {
			return nil, err
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
	setSliceIfNotEmpty("companions", *companions)
	setSliceIfNotEmpty("prior_run_dirs", *priorRunDirs)
	if sub == "catalog" {
		setIfNotEmpty("file", *fileFlag)
		setIfNotEmpty("block", *blockFlag)
	}
	if sub == "architecture" {
		if *contentFlag != "" {
			payload["content"] = *contentFlag
		} else if *fileFlag != "" {
			b, err := validator.ReadFileNoFollow(*fileFlag)
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
		if _, ok := payload["critic_kind"]; !ok {
			payload["critic_kind"] = "post_wave"
		}
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
	if *carryoverUnchanged {
		payload["carryover_unchanged"] = true
	}
	setIfNotEmpty("fail_on", *failOn)

	b, err := json.Marshal(payload)
	return json.RawMessage(b), err
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "sec-audit: gated multi-agent security audits. Agents propose, deterministic gates decide.")
	fmt.Fprintln(w, "\nUsage: sec-audit <command> [flags]")
	fmt.Fprintln(w, "\nStart here:")
	fmt.Fprintf(w, "  %-21s %s\n", "demo", "Run a complete audit of a bundled vulnerable API in under a second, no LLM")
	fmt.Fprintf(w, "  %-21s %s\n", "setup <client>", "Register the MCP server in claude, cursor or claude-desktop")
	fmt.Fprintf(w, "  %-21s %s\n", "mcp", "Run the MCP server over stdio (what your agent talks to)")
	fmt.Fprintln(w, "\nAudit steps (each is also the MCP tool sec_audit_<step>):")
	for _, c := range registry.All() {
		fmt.Fprintf(w, "  %-21s %s\n", c.Subcommand, c.Summary)
	}
	fmt.Fprintln(w, "\nOther:")
	fmt.Fprintf(w, "  %-21s %s\n", "version", "Print version and platform")
	fmt.Fprintln(w, "\nOutput is JSON when piped and readable text on a terminal; force it with --format json|text.")
	fmt.Fprintln(w, "Docs: https://github.com/fabriziosalmi/security-audit-cli")
}

func runDemo(args []string, stdout, stderr io.Writer, color bool) int {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "Directory for the demo target and run (must be empty; default: a new temp dir)")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if _, err := demo.Run(demo.Options{Dir: *dir, Color: color}, stdout); err != nil {
		fmt.Fprintf(stderr, "demo failed: %v\n", err)
		return 1
	}
	return 0
}
