package prompt

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/spec"
	"github.com/fabriziosalmi/security-audit-cli/internal/store"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// CompileRecon builds the Phase 1 reconnaissance subagent prompt.
func CompileRecon(targetDir string) string {
	return fmt.Sprintf(
		"Read the target at %s. Do not use network access. "+
			"Return only source facts with repository-relative file:line references.",
		targetDir,
	)
}

// CompileHunter builds the 9-part self-contained Phase 2 hunter prompt from HUNTING.md.
func CompileHunter(
	outputDir, agentID string,
	assignedUnits, allUnits []validator.CoverageUnit,
	state *store.InternalState,
	cat *spec.Catalog,
) (string, error) {
	archBytes, err := validator.ReadFileNoFollow(filepath.Join(outputDir, "architecture.md"))
	if err != nil {
		return "", fmt.Errorf("architecture.md must be written before assigning hunters: %w", err)
	}
	schemas, err := cat.SchemaBranches(false)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	// Part 1: Two-sentence role preamble
	b.WriteString("Your goal is to find source-grounded security invariant failures in your assigned coverage units. " +
		"You must return exactly one JSON object matching the structured-result contract at the end of this prompt.\n\n")

	// Part 2: architecture.md verbatim
	b.WriteString("## Architecture Summary\n\n")
	b.Write(archBytes)
	b.WriteString("\n")

	// Part 3: Assigned coverage IDs and assignment block map
	b.WriteString("## Assigned Coverage Units\n\n")
	assignedJSON, _ := json.MarshalIndent(assignedUnits, "", "  ")
	b.Write(assignedJSON)
	b.WriteString("\n\n")

	// Part 4: Exact selected blocks copied verbatim
	b.WriteString("## Selected Attack-Class and Companion Blocks\n\n")
	selectedRefs := make([]string, 0)
	seenRef := make(map[string]bool)
	for _, u := range assignedUnits {
		if u.OrdinaryAttackClassBlock != nil && !seenRef[*u.OrdinaryAttackClassBlock] {
			seenRef[*u.OrdinaryAttackClassBlock] = true
			selectedRefs = append(selectedRefs, *u.OrdinaryAttackClassBlock)
		}
		for _, cb := range u.SelectedCompanionBlocks {
			if !seenRef[cb] {
				seenRef[cb] = true
				selectedRefs = append(selectedRefs, cb)
			}
		}
	}
	for _, ref := range selectedRefs {
		if blk, ok := cat.Blocks[ref]; ok {
			fmt.Fprintf(&b, "### %s\n\n%s\n\n", blk.Ref, blk.Content)
		}
	}

	// Part 5: Explicit excluded blocks with reasons
	b.WriteString("## Excluded Blocks\n\n")
	for _, u := range assignedUnits {
		for _, ex := range u.ExcludedBlocks {
			fmt.Fprintf(&b, "- `%s`: %s\n", ex.Block, ex.Reason)
		}
	}
	b.WriteString("\n")

	// Part 6: Core hunting method + Promotion procedure
	b.WriteString(spec.CoreHuntingMethodBlock)
	b.WriteString("\n\n")
	b.WriteString(spec.PromotionProcedureBlock)
	b.WriteString("\n\n")

	// Part 7: Core validation rules
	b.WriteString(spec.CandidateGateBlock)
	b.WriteString("\n\n")

	// Part 8: Carried same-source prior confirmed exclusions and peer-owned coverage IDs
	b.WriteString("## Exclusions and Peer-Owned Coverage Units\n\n")
	assignedIDSet := make(map[string]bool)
	for _, u := range assignedUnits {
		assignedIDSet[u.CoverageID] = true
	}
	for _, u := range allUnits {
		if !assignedIDSet[u.CoverageID] {
			fmt.Fprintf(&b, "- Peer coverage_id (do not duplicate): `%s`\n", u.CoverageID)
		}
	}
	candKeys := make([]string, 0, len(state.Candidates))
	for fp := range state.Candidates {
		candKeys = append(candKeys, fp)
	}
	sort.Strings(candKeys)
	for _, fp := range candKeys {
		env := state.Candidates[fp]
		if env.HunterID == "prior-run-carryover" && env.ProposedVerdict == "confirmed" {
			fmt.Fprintf(
				&b,
				"- Carried prior confirmed exclusion: `%s` (%s): %s\n",
				env.Fingerprint,
				env.CandidateRecord.Title,
				env.CandidateRecord.RootCause,
			)
		}
	}
	b.WriteString("\n")

	// Part 9: Scratch/artifact paths, agent ID, and structured result contract
	fmt.Fprintf(
		&b,
		"## Workspace and Structured Result Contract\n\n"+
			"- Canonical `agent_id`: `%s`\n"+
			"- Writable scratch directory: `%s/agents/%s/scratch`\n"+
			"- Retained artifacts prefix (parent-promoted only): `agents/%s/artifacts/`\n\n"+
			"Schema branches (`confirmed` and `needs_validation`):\n```json\n%s\n```\n",
		agentID, outputDir, agentID, agentID, schemas,
	)

	return b.String(), nil
}

// CompileVerifier builds the Phase 3 adversarial verifier prompt.
func CompileVerifier(outputDir, agentID string, env *store.CandidateEnvelope, cat *spec.Catalog) (string, error) {
	schemas, err := cat.SchemaBranches(true)
	if err != nil {
		return "", err
	}
	candJSON, _ := json.MarshalIndent(env.CandidateRaw, "", "  ")

	var b strings.Builder
	b.WriteString("You did not write this candidate. Try to refute it from repository source and bounded local evidence.\n\n")
	b.WriteString("## Candidate Under Adversarial Review\n\n```json\n")
	b.Write(candJSON)
	b.WriteString("\n```\n\n")
	b.WriteString(spec.PromotionProcedureBlock)
	b.WriteString("\n\n## Schema Branches (`confirmed`, `needs_validation`, `rejected`)\n\n```json\n")
	b.WriteString(schemas)
	b.WriteString("\n```\n\n")
	fmt.Fprintf(
		&b,
		"Assigned verifier `agent_id`: `%s`\nScratch directory: `%s/agents/%s/scratch`\n"+
			"Return `{\"decision\": \"confirmed|needs_validation|rejected\", \"record\": { ... }}`.\n",
		agentID, outputDir, agentID,
	)
	return b.String(), nil
}

// CompileRecordVerifier builds the Phase 5 independent record-verification prompt.
func CompileRecordVerifier(env *store.CandidateEnvelope) string {
	recJSON, _ := json.MarshalIndent(env.FinalRecord, "", "  ")
	return fmt.Sprintf(
		"Independently verify this final record against repository source:\n\n```json\n%s\n```\n\n"+
			"Return `{\"decision\":\"verified\",\"fingerprint\":%q}` or `{\"decision\":\"replace\",\"reason\":\"...\",\"record\":{...}}`.",
		string(recJSON),
		env.Fingerprint,
	)
}

// CompileCritic builds the Phase 2 coverage-critic prompt.
func CompileCritic(outputDir string, units []validator.CoverageUnit) (string, error) {
	archBytes, _ := validator.ReadFileNoFollow(filepath.Join(outputDir, "architecture.md"))
	ledgerJSON, _ := json.MarshalIndent(units, "", "  ")
	return fmt.Sprintf(
		"Review architecture and coverage-ledger.json for unmapped entry points, "+
			"unchecked parallel paths, or premature closures.\n\n## Architecture\n%s\n\n## Coverage Ledger\n```json\n%s\n```\n",
		string(archBytes),
		string(ledgerJSON),
	), nil
}
