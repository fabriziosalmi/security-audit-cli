package prompt

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// Example texts used in the generated hunter result example. They are valid
// for the validator, so the example passes SubmitHunter as is.
const (
	exampleInvariant  = "One sentence: the security property you checked."
	exampleResultText = "One or more sentences: what the source showed."
)

// HunterResultContract describes the exact object SubmitHunter accepts. The
// ledger shape shown in "Assigned Coverage Units" uses other names (status,
// local_checks, result_fingerprints); this section names the ones to return,
// and its example, built from the assigned units, passes submission unchanged
// (see contract_test.go).
func HunterResultContract(agentID string, assigned []validator.CoverageUnit) string {
	var b strings.Builder
	fmt.Fprintf(&b, "### Structured result\n\n"+
		"Return exactly one JSON object with the top-level keys `units`, `candidates`, `hardening`, `uncovered`.\n"+
		"This is not the ledger shape shown under Assigned Coverage Units; use these names:\n\n"+
		"- `units`: exactly one entry per assigned coverage unit:\n"+
		"  - `coverage_id`: the assigned id, verbatim.\n"+
		"  - `disposition`: `covered` (checks found no failure; `unresolved` stays empty), `candidate`\n"+
		"    (list the fingerprints in `candidate_fingerprints`), or `blocked` (say what blocked you in `unresolved`).\n"+
		"  - `reviewed_paths`: every starting path of the unit, plus any other repository-relative path you reviewed.\n"+
		"  - `checks`: at least one. Each has exactly `agent_id` (`%s`), `reviewed_paths`, `invariant`,\n"+
		"    `method` (`source` or `local`), `result`, and `artifact`: `null` for a source check; for a local\n"+
		"    check `agents/%s/artifacts/<file>`, a scratch file the parent promotes. Every path in the unit's\n"+
		"    `reviewed_paths` appears in some check's `reviewed_paths`, and no check names a path outside it.\n"+
		"  - `candidate_fingerprints`: non-empty only when the disposition is `candidate`.\n"+
		"  - `unresolved`: strings; empty for `covered`, non-empty for `blocked`.\n"+
		"- `candidates`: records following a schema branch below, except that the verdict field is named\n"+
		"  `proposed_verdict` (`confirmed` or `needs_validation`) instead of `verdict`.\n"+
		"- `hardening`: strings, for gaps that are not findings.\n"+
		"- `uncovered`: objects `{surface, boundary, subsystem, attack_class, starting_paths, reason}` for\n"+
		"  surfaces you found but could not cover.\n\n"+
		"Example with every assigned unit covered by one source check (replace the texts with yours):\n```json\n",
		agentID, agentID)
	b.WriteString(HunterResultExample(agentID, assigned))
	b.WriteString("\n```\n")
	return b.String()
}

type exampleCheck struct {
	AgentID       string   `json:"agent_id"`
	ReviewedPaths []string `json:"reviewed_paths"`
	Invariant     string   `json:"invariant"`
	Method        string   `json:"method"`
	Result        string   `json:"result"`
	Artifact      *string  `json:"artifact"`
}

type exampleUnit struct {
	CoverageID            string         `json:"coverage_id"`
	Disposition           string         `json:"disposition"`
	ReviewedPaths         []string       `json:"reviewed_paths"`
	Checks                []exampleCheck `json:"checks"`
	CandidateFingerprints []string       `json:"candidate_fingerprints"`
	Unresolved            []string       `json:"unresolved"`
}

type exampleResult struct {
	Units      []exampleUnit `json:"units"`
	Candidates []any         `json:"candidates"`
	Hardening  []string      `json:"hardening"`
	Uncovered  []any         `json:"uncovered"`
}

// HunterResultExample returns the example result for the assigned units as
// indented JSON.
func HunterResultExample(agentID string, assigned []validator.CoverageUnit) string {
	ex := exampleResult{Units: []exampleUnit{}, Candidates: []any{}, Hardening: []string{}, Uncovered: []any{}}
	for _, u := range assigned {
		paths := append([]string{}, u.StartingPaths...)
		ex.Units = append(ex.Units, exampleUnit{
			CoverageID:    u.CoverageID,
			Disposition:   "covered",
			ReviewedPaths: paths,
			Checks: []exampleCheck{{
				AgentID: agentID, ReviewedPaths: paths, Method: "source",
				Invariant: exampleInvariant, Result: exampleResultText,
			}},
			CandidateFingerprints: []string{},
			Unresolved:            []string{},
		})
	}
	out, _ := json.MarshalIndent(ex, "", "  ")
	return string(out)
}
