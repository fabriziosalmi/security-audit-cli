// Package demo runs a complete sec-audit run against a small embedded target,
// with scripted agent output in place of a language model. Along the way it
// submits four things a careless or dishonest agent would submit, and fails
// if any gate lets one of them through.
package demo

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fabriziosalmi/security-audit-cli/internal/engine"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// Options configures a demo run.
type Options struct {
	// Dir receives the target repository (notes-api/) and the run (run/).
	// It must not exist yet or be empty. Empty means a new temporary directory.
	Dir string
	// Color enables ANSI styling.
	Color bool
}

// Summary is what a demo run produced.
type Summary struct {
	Dir             string
	TargetDir       string
	RunDir          string
	ReportPath      string
	BlockedLies     int
	Confirmed       int
	Rejected        int
	Advisories      int
	ManifestEntries int
	Steps           int
	Duration        time.Duration
}

const (
	fpIDOR      = "notes.get.missing-owner-check"
	fpTraversal = "notes.export.path-traversal"
	fpSQLi      = "notes.search.sql-injection"
	hunterID    = "hunter-wave1-a"
	handlerPath = "internal/notes/handler.go"
	mainPath    = "cmd/server/main.go"
)

type printer struct {
	w     io.Writer
	color bool
	steps int
}

func (p *printer) style(code, s string) string {
	if !p.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p *printer) phase(n, title string) {
	fmt.Fprintf(p.w, "\n %s  %s\n", p.style("1;36", "PHASE "+n), p.style("1", title))
}

func (p *printer) ok(step, detail string) {
	p.steps++
	fmt.Fprintf(p.w, "   %s %-22s %s\n", p.style("32", "ok"), step, p.style("2", detail))
}

func (p *printer) blocked(step, lie, why string) {
	p.steps++
	fmt.Fprintf(p.w, "   %s %-22s %s\n", p.style("1;31", "no"), step, p.style("1;31", "BLOCKED")+"  "+lie)
	fmt.Fprintf(p.w, "      %-22s %s\n", "", p.style("2", why))
}

// Run executes the demo and writes a narrated transcript to w.
func Run(opts Options, w io.Writer) (*Summary, error) {
	start := time.Now()
	dir, err := prepareDir(opts.Dir)
	if err != nil {
		return nil, err
	}
	target := filepath.Join(dir, "notes-api")
	out := filepath.Join(dir, "run")
	if err := writeFixture(target); err != nil {
		return nil, err
	}
	p := &printer{w: w, color: opts.Color}
	s := &Summary{Dir: dir, TargetDir: target, RunDir: out}

	fmt.Fprintf(w, "%s  a complete 6-phase audit of a small Go API, with scripted agents\n",
		p.style("1", "sec-audit demo"))
	fmt.Fprintf(w, "   target  %s\n   run     %s\n", rel(target), rel(out))

	cids, err := phaseRecon(p, target, out)
	if err != nil {
		return nil, err
	}
	if err := phaseHunt(p, s, out, cids); err != nil {
		return nil, err
	}
	if err := phaseVerify(p, s, out); err != nil {
		return nil, err
	}
	if err := phaseRender(p, s, target, out); err != nil {
		return nil, err
	}

	s.Steps = p.steps
	s.Duration = time.Since(start)
	printSummary(p, s)
	return s, nil
}

func phaseRecon(p *printer, target, out string) ([]string, error) {
	p.phase("1", "recon and coverage plan")
	initResp, err := engine.Init(engine.InitRequest{Target: target, OutputDir: out, Profile: "standard"})
	if err != nil {
		return nil, fmt.Errorf("init: %w", err)
	}
	p.ok("init", fmt.Sprintf("%d files, %d entrypoint candidate(s), profile standard",
		initResp.RepoBrief.TotalFiles, len(initResp.RepoBrief.EntrypointCandidates)))

	if _, err := engine.WriteArchitecture(out, fixtureArchitecture); err != nil {
		return nil, fmt.Errorf("architecture: %w", err)
	}
	p.ok("architecture", fmt.Sprintf("%d words, 3 trust boundaries", len(strings.Fields(fixtureArchitecture))))

	units, err := engine.SeedLedger(out, seedUnits())
	if err != nil {
		return nil, fmt.Errorf("ledger-seed: %w", err)
	}
	cids := make([]string, 0, len(units))
	for _, u := range units {
		cids = append(cids, u.CoverageID)
	}
	p.ok("ledger-seed", fmt.Sprintf("%d coverage units: access control, file handling, injection", len(units)))
	return cids, nil
}

func phaseHunt(p *printer, s *Summary, out string, cids []string) error {
	p.phase("2", "hunt (one hunter, three units)")
	assign, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: out, Role: "hunter", AgentID: hunterID, CoverageIDs: cids,
	})
	if err != nil {
		return fmt.Errorf("agent-assign hunter: %w", err)
	}
	p.ok("agent-assign", fmt.Sprintf("%s, compiled prompt %s bytes", hunterID, thousands(len(assign.Prompt))))

	// Lie 1: evidence that is really a symlink to a host file.
	if err := os.Symlink("/etc/passwd", filepath.Join(assign.ScratchDir, "poc-output.txt")); err != nil {
		return err
	}
	prom, err := engine.PromoteArtifacts(out, hunterID, []string{"poc-output.txt"}, 0, 0)
	if err != nil {
		return fmt.Errorf("artifact-promote: %w", err)
	}
	if prom[0].Promoted {
		return errors.New("gate failure: a symlink to /etc/passwd was promoted as evidence")
	}
	s.BlockedLies++
	p.blocked("artifact-promote", "evidence file is a symlink to /etc/passwd", firstLine(prom[0].Blocker))
	if err := os.Remove(filepath.Join(assign.ScratchDir, "poc-output.txt")); err != nil {
		return err
	}
	poc := "$ curl -b session=alice localhost:8080/notes/42   # note 42 belongs to bob\n" +
		"{\"body\":\"bob's private note\",\"id\":\"42\"}\n" +
		"$ curl -b session=alice 'localhost:8080/export?name=../../../../etc/hostname'\n" +
		"notes-prod-1\n"
	if err := os.WriteFile(filepath.Join(assign.ScratchDir, "poc-output.txt"), []byte(poc), 0o600); err != nil {
		return err
	}
	prom, err = engine.PromoteArtifacts(out, hunterID, []string{"poc-output.txt"}, 0, 0)
	if err != nil || !prom[0].Promoted {
		return fmt.Errorf("artifact-promote of a regular file failed: %v %+v", err, prom)
	}
	artifact := prom[0].ArtifactPath
	p.ok("artifact-promote", artifact)

	// Lie 2: a citation to a line that does not exist.
	phantom := hunterResult(cids, artifact)
	phantom.Candidates[0]["trace"] = []map[string]any{
		{"kind": "entrypoint", "file": handlerPath, "line": 999, "scope": "Get", "description": "Request enters Get"},
		{"kind": "sink", "file": handlerPath, "line": 1000, "scope": "Get", "description": "Note returned"},
	}
	_, err = engine.SubmitHunter(out, hunterID, phantom)
	if err == nil {
		return fmt.Errorf("gate failure: hunter-submit accepted a citation to line 999 of a %d-line file",
			strings.Count(fixtureHandler, "\n"))
	}
	s.BlockedLies++
	why := err.Error()
	if i := strings.Index(why, "line 999"); i > 0 {
		why = handlerPath + " " + strings.SplitN(why[i:], ";", 2)[0]
	}
	why = firstLine(why)
	p.blocked("hunter-submit", "cites "+handlerPath+":999", why)

	if _, err := engine.SubmitHunter(out, hunterID, hunterResult(cids, artifact)); err != nil {
		return fmt.Errorf("hunter-submit: %w", err)
	}
	p.ok("hunter-submit", "3 candidates, every file:line checked on disk, sources pinned by SHA-256")

	for _, c := range []struct{ id, kind string }{{"critic-wave1", "post_wave"}, {"critic-final", "final_clean"}} {
		if _, err := engine.AssignAgent(engine.AssignAgentRequest{OutputDir: out, Role: "critic", AgentID: c.id}); err != nil {
			return fmt.Errorf("agent-assign %s: %w", c.id, err)
		}
		if _, err := engine.SubmitCritic(out, c.id, c.kind, engine.CriticResult{Stop: true}); err != nil {
			return fmt.Errorf("critic-submit %s: %w", c.id, err)
		}
		p.ok("critic-submit", c.kind+": no missing units, no reassignment")
	}
	return nil
}

func phaseVerify(p *printer, s *Summary, out string) error {
	p.phase("3-5", "adversarial verification")

	// Lie 3: the hunter grades its own finding.
	_, err := engine.AssignAgent(engine.AssignAgentRequest{
		OutputDir: out, Role: "verifier", AgentID: hunterID, Fingerprint: fpIDOR,
	})
	if err == nil {
		return errors.New("gate failure: the hunter was allowed to verify its own candidate")
	}
	s.BlockedLies++
	p.blocked("agent-assign", hunterID+" asks to verify its own finding",
		"agent ids are single-use: "+strings.SplitN(firstLine(err.Error()), ";", 2)[0])

	verdicts := []struct {
		agent, fp, decision string
		record              map[string]any
	}{
		{"verifier-idor", fpIDOR, "confirmed", confirmedRecord(idorCandidate())},
		{"verifier-traversal", fpTraversal, "confirmed", confirmedRecord(traversalCandidate())},
		{"verifier-search", fpSQLi, "rejected", rejectedSQLiRecord()},
	}
	for _, v := range verdicts {
		if _, err := engine.AssignAgent(engine.AssignAgentRequest{
			OutputDir: out, Role: "verifier", AgentID: v.agent, Fingerprint: v.fp,
		}); err != nil {
			return fmt.Errorf("agent-assign %s: %w", v.agent, err)
		}
		if _, err := engine.SubmitVerifier(engine.VerifierSubmitRequest{
			OutputDir: out, AgentID: v.agent, Fingerprint: v.fp, Decision: v.decision, Record: v.record,
		}); err != nil {
			return fmt.Errorf("verifier-submit %s: %w", v.agent, err)
		}
		detail := v.fp + " confirmed"
		if v.decision == "rejected" {
			detail = v.fp + " REJECTED: the query uses placeholders"
			s.Rejected++
		}
		p.ok("verifier-submit", detail)
	}

	if _, err := engine.Render(engine.RenderRequest{OutputDir: out}); err == nil {
		return errors.New("gate failure: render succeeded before Phase 5 record verification")
	}
	p.ok("render (early)", "refused: 2 confirmed records still need an independent Phase 5 check")

	for _, r := range []struct{ agent, fp string }{{"recverify-idor", fpIDOR}, {"recverify-traversal", fpTraversal}} {
		if _, err := engine.AssignAgent(engine.AssignAgentRequest{
			OutputDir: out, Role: "record_verifier", AgentID: r.agent, Fingerprint: r.fp,
		}); err != nil {
			return fmt.Errorf("agent-assign %s: %w", r.agent, err)
		}
		if _, err := engine.SubmitRecordVerifier(engine.RecordVerifySubmitRequest{
			OutputDir: out, AgentID: r.agent, Fingerprint: r.fp, Decision: "verified",
		}); err != nil {
			return fmt.Errorf("record-verify-submit %s: %w", r.agent, err)
		}
		p.ok("record-verify-submit", r.fp+" verified by a third agent")
	}
	return nil
}

func phaseRender(p *printer, s *Summary, target, out string) error {
	p.phase("6", "validate and render")

	// Lie 4: the audited source changes after review.
	handlerAbs := filepath.Join(target, filepath.FromSlash(handlerPath))
	orig, err := os.ReadFile(handlerAbs)
	if err != nil {
		return err
	}
	if err := os.WriteFile(handlerAbs, append(append([]byte{}, orig...), "\n// changed after the audit\n"...), 0o600); err != nil {
		return err
	}
	st, err := engine.Status(engine.StatusRequest{OutputDir: out})
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}
	_, renderErr := engine.Render(engine.RenderRequest{OutputDir: out})
	if len(st.SourceDriftFiles) == 0 || renderErr == nil {
		return errors.New("gate failure: an audited file changed after review and render did not notice")
	}
	s.BlockedLies++
	p.blocked("render", handlerPath+" edited after it was audited",
		"SHA-256 no longer matches the pinned digest: "+strings.Join(st.SourceDriftFiles, ", "))
	if err := os.WriteFile(handlerAbs, orig, 0o600); err != nil {
		return err
	}

	val, err := engine.ValidateRunWithGate(out, "")
	if err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	if valid, _ := val["valid"].(bool); !valid {
		return fmt.Errorf("validate failed after restoring the source: %v", val)
	}
	p.ok("validate", fmt.Sprintf("%v units, %v findings, 0 ledger errors, 0 finding errors", val["units_count"], val["findings_count"]))

	res, err := engine.Render(engine.RenderRequest{OutputDir: out, FailOn: "high"})
	if err != nil {
		return fmt.Errorf("render: %w", err)
	}
	s.ReportPath = res.ReportPath
	s.Confirmed = res.ConfirmedCount
	s.Advisories = len(res.AdvisoryPaths)
	p.ok("render", fmt.Sprintf("REPORT.md, FINDINGS-DETAIL.md, findings.sarif, %d advisories", s.Advisories))

	n, err := verifyManifest(out, res.ManifestPath)
	if err != nil {
		return err
	}
	s.ManifestEntries = n
	p.ok("manifest.sha256", fmt.Sprintf("%d of %d hashes match the files on disk", n, n))
	gate := "passed"
	if !res.GatePassed {
		gate = "FAILED, a CI job would exit 2"
		if _, list, ok := strings.Cut(res.GateFailureReason, "finding(s): "); ok {
			gate += ": " + list
		}
	}
	p.ok("--fail-on high", gate)
	return nil
}

func printSummary(p *printer, s *Summary) {
	fmt.Fprintf(p.w, "\n %s\n", p.style("1", "RESULT"))
	fmt.Fprintf(p.w, "   %d confirmed findings, %d false positive rejected by an independent verifier\n", s.Confirmed, s.Rejected)
	fmt.Fprintf(p.w, "   %d of 4 bad agent submissions blocked by deterministic gates\n", s.BlockedLies)
	fmt.Fprintf(p.w, "   %d steps in %s, no model calls\n\n", s.Steps, s.Duration.Round(time.Millisecond))
	fmt.Fprintf(p.w, "   read the report:  %s\n", p.style("1", "less "+rel(s.ReportPath)))
	fmt.Fprintf(p.w, "   check integrity:  %s\n", p.style("1", "(cd "+rel(s.RunDir)+" && shasum -a 256 -c manifest.sha256)"))
	fmt.Fprintf(p.w, "   audit your repo:  %s\n", p.style("1", "sec-audit setup claude"))
}

func prepareDir(dir string) (string, error) {
	if dir == "" {
		return os.MkdirTemp("", "sec-audit-demo-")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(abs)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return abs, os.MkdirAll(abs, 0o700)
	case err != nil:
		return "", err
	case len(entries) > 0:
		return "", fmt.Errorf("demo directory %s is not empty", abs)
	}
	return abs, nil
}

func writeFixture(target string) error {
	for rel, content := range fixtureFiles {
		full := filepath.Join(target, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func verifyManifest(out, manifestPath string) (int, error) {
	raw, err := validator.ReadFileNoFollow(manifestPath)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		want, name, ok := strings.Cut(line, "  ")
		if !ok {
			return 0, fmt.Errorf("malformed manifest line %q", line)
		}
		got, err := engine.FileHashSHA256(filepath.Join(out, filepath.FromSlash(name)))
		if err != nil || got != want {
			return 0, fmt.Errorf("manifest mismatch for %s", name)
		}
		n++
	}
	return n, nil
}

// rel shows p relative to the working directory when it is below it, so the
// transcript stays narrow.
func rel(p string) string {
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	if r, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(r, "..") {
		return r
	}
	return p
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	// Drop wrapper prefixes so the reason itself fits on one line.
	for _, p := range []string{"hunter candidate validation failed: "} {
		s = strings.TrimPrefix(s, p)
	}
	if len(s) > 90 {
		s = s[:87] + "..."
	}
	return s
}

func thousands(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
