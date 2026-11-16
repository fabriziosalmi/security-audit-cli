package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/engine"
)

// Output format. JSON is the contract for agents and scripts; text is for a
// person at a terminal. "auto" picks text only when stdout is a terminal, so
// pipes, CI logs and agents shelling out keep getting JSON.
const (
	formatAuto = "auto"
	formatJSON = "json"
	formatText = "text"
)

// extractFormat removes --format X / --format=X from args.
func extractFormat(args []string) ([]string, string, error) {
	format := formatAuto
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--format" || a == "-format":
			if i+1 >= len(args) {
				return nil, "", fmt.Errorf("--format needs a value (auto, json, text)")
			}
			format = args[i+1]
			i++
		case strings.HasPrefix(a, "--format=") || strings.HasPrefix(a, "-format="):
			_, format, _ = strings.Cut(a, "=")
		default:
			out = append(out, a)
		}
	}
	switch format {
	case formatAuto, formatJSON, formatText:
		return out, format, nil
	}
	return nil, "", fmt.Errorf("invalid --format %q (expected auto, json, text)", format)
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func useColor(w io.Writer) bool {
	return isTerminal(w) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
}

type tty struct {
	w     io.Writer
	color bool
}

func (t tty) s(code, text string) string {
	if !t.color {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (t tty) kv(k string, v any) {
	// Pad before styling: escape codes would otherwise count toward the width.
	fmt.Fprintf(t.w, "  %s %v\n", t.s("2", fmt.Sprintf("%-14s", k)), v)
}

func (t tty) list(title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(t.w, "  %s\n", t.s("2", title))
	for _, it := range items {
		fmt.Fprintf(t.w, "    - %s\n", it)
	}
}

// renderText prints res for a person. It returns false when sub has no text
// form, and the caller falls back to JSON.
func renderText(sub string, res any, t tty) bool {
	switch r := res.(type) {
	case *engine.InitResponse:
		textInit(r, t)
	case *engine.StatusResponse:
		textStatus(r, t)
	case *engine.RenderResponse:
		textRender(r, t)
	case map[string]any:
		if sub != "validate" {
			return false
		}
		textValidate(r, t)
	default:
		return false
	}
	return true
}

func textInit(r *engine.InitResponse, t tty) {
	m := r.Metadata
	fmt.Fprintf(t.w, "%s %s\n", t.s("1", "sec-audit init"), m.Repo)
	t.kv("run", r.OutputDir)
	t.kv("target", m.Target)
	ref := m.SourceRef
	if ref == "" {
		ref = "(not a git repository)"
	} else if m.DirtyWorktree {
		ref += " " + t.s("33", "(uncommitted changes)")
	}
	t.kv("source", ref)
	t.kv("profile", m.Profile)
	t.kv("files", r.RepoBrief.TotalFiles)
	langs := make([]string, 0, len(r.RepoBrief.Languages))
	for l, n := range r.RepoBrief.Languages {
		langs = append(langs, fmt.Sprintf("%s %d", l, n))
	}
	sort.Strings(langs)
	t.kv("languages", strings.Join(langs, ", "))
	t.list("entrypoint candidates", r.RepoBrief.EntrypointCandidates)
	comps := make([]string, 0, len(r.RepoBrief.RecommendedCompanions))
	for _, c := range r.RepoBrief.RecommendedCompanions {
		comps = append(comps, c.File+": "+c.Reason)
	}
	t.list("companion playbooks", comps)
	if m.RunStatus == "incomplete" {
		fmt.Fprintf(t.w, "\n  %s %s\n", t.s("1;31", "incomplete:"), m.IncompleteReason)
		return
	}
	fmt.Fprintf(t.w, "\n  next: write architecture.md, then seed the ledger (sec-audit status --output-dir %s)\n", r.OutputDir)
}

func textStatus(r *engine.StatusResponse, t tty) {
	fmt.Fprintf(t.w, "%s %s  %s\n", t.s("1", "sec-audit status"), r.Repo, t.s("2", r.RunID))
	t.kv("run", r.RunStatus)
	t.kv("profile", r.Profile)
	t.kv("wave", r.CurrentWave)
	agents := fmt.Sprint(r.AgentsSpent)
	if r.Budget != nil {
		agents = fmt.Sprintf("%d / %d", r.AgentsSpent, *r.Budget)
	}
	t.kv("agents", agents)
	arch := "missing"
	if r.ArchitectureWritten {
		arch = "written"
	}
	t.kv("architecture", arch)
	keys := make([]string, 0, len(r.UnitStatusCounts))
	for k := range r.UnitStatusCounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, r.UnitStatusCounts[k]))
	}
	if len(parts) == 0 {
		parts = []string{"none yet"}
	}
	t.kv("units", strings.Join(parts, ", "))
	if len(r.SourceDriftFiles) > 0 {
		t.kv("source drift", t.s("1;31", strings.Join(r.SourceDriftFiles, ", ")))
	}
	fmt.Fprintln(t.w)
	if r.RunStatus == "complete" && r.ReadyToRender {
		fmt.Fprintf(t.w, "  %s report rendered; render again only after new submissions\n", t.s("1;32", "complete"))
		return
	}
	head := t.s("1;33", "next")
	if r.ReadyToRender {
		head = t.s("1;32", "ready")
	}
	fmt.Fprintf(t.w, "  %s\n", head)
	for _, a := range r.NextRequiredActions {
		fmt.Fprintf(t.w, "    - %s\n", a)
	}
}

func textValidate(r map[string]any, t tty) {
	valid, _ := r["valid"].(bool)
	verdict := t.s("1;32", "valid")
	if !valid {
		verdict = t.s("1;31", "INVALID")
	}
	fmt.Fprintf(t.w, "%s %s\n", t.s("1", "sec-audit validate"), verdict)
	if n, ok := r["units_count"]; ok {
		t.kv("units", n)
	}
	if n, ok := r["findings_count"]; ok {
		t.kv("findings", n)
	}
	for _, k := range []string{"ledger_errors", "finding_errors"} {
		if errs, ok := r[k].([]string); ok {
			t.list(strings.ReplaceAll(k, "_", " "), errs)
		}
	}
	if gp, ok := r["gate_passed"].(bool); ok && !gp {
		fmt.Fprintf(t.w, "  %s %v\n", t.s("1;31", "gate failed:"), r["gate_failure_reason"])
	}
}

func textRender(r *engine.RenderResponse, t tty) {
	fmt.Fprintf(t.w, "%s %s\n", t.s("1", "sec-audit render"), r.RunStatus)
	t.kv("confirmed", r.ConfirmedCount)
	t.kv("needs valid.", r.NeedsValCount)
	t.kv("rejected", r.RejectedCount)
	t.kv("hardening", r.HardeningCount)
	t.kv("report", r.ReportPath)
	t.kv("sarif", r.SarifPath)
	t.kv("advisories", len(r.AdvisoryPaths))
	t.kv("manifest", r.ManifestPath)
	if !r.GatePassed {
		fmt.Fprintf(t.w, "\n  %s %s\n", t.s("1;31", "gate failed:"), r.GateFailureReason)
	}
}
