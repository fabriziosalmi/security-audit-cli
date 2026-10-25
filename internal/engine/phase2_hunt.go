package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/scanner"
	"github.com/fabriziosalmi/security-audit-cli/internal/spec"
	"github.com/fabriziosalmi/security-audit-cli/internal/store"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// SubmitHunter validates a hunter's structured result, verifies all cited source paths and lines on disk,
// updates coverage-ledger.json, and stores candidates for Phase 3 validation.
func SubmitHunter(outputDir, agentID string, result HunterStructuredResult) (map[string]any, error) {
	rs := store.New(outputDir)
	meta, err := rs.LoadMetadata()
	if err != nil {
		return nil, err
	}
	state, err := rs.LoadState()
	if err != nil {
		return nil, err
	}
	assign, ok := state.Agents[agentID]
	if !ok || assign.Role != "hunter" {
		return nil, fmt.Errorf("agent_id %q is not a registered hunter", agentID)
	}
	units, err := rs.LoadLedger()
	if err != nil {
		return nil, err
	}
	cat, err := spec.LoadCatalog()
	if err != nil {
		return nil, err
	}
	validBlocks := cat.ValidBlockMap()

	candidateByFP := make(map[string]validator.Finding)
	candidateRawByFP := make(map[string]map[string]any)
	for idx, rawCand := range result.Candidates {
		b, _ := json.Marshal(rawCand)
		var f validator.Finding
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("candidates[%d] unmarshal error: %w", idx, err)
		}
		if pv, ok := rawCand["proposed_verdict"].(string); ok {
			f.Verdict = pv
		}
		errs := validator.ValidateSingleFinding(f, rawCand, fmt.Sprintf("candidates[%d]", idx), meta.Target, true)
		if len(errs) > 0 {
			return nil, fmt.Errorf("hunter candidate validation failed: %s", strings.Join(errs, "; "))
		}
		candidateByFP[f.Fingerprint] = f
		candidateRawByFP[f.Fingerprint] = rawCand
	}

	assignedSet := make(map[string]bool)
	for _, cid := range assign.CoverageIDs {
		assignedSet[cid] = true
	}
	if len(result.Units) != len(assign.CoverageIDs) {
		return nil, fmt.Errorf("hunter must report exactly %d assigned units, got %d", len(assign.CoverageIDs), len(result.Units))
	}

	ledgerIdx := make(map[string]int, len(units))
	for idx, u := range units {
		ledgerIdx[u.CoverageID] = idx
	}

	seenResultID := make(map[string]bool)
	for _, ur := range result.Units {
		if !assignedSet[ur.CoverageID] {
			return nil, fmt.Errorf("unit %q was not assigned to hunter %q", ur.CoverageID, agentID)
		}
		if seenResultID[ur.CoverageID] {
			return nil, fmt.Errorf("duplicate coverage_id %q in hunter result", ur.CoverageID)
		}
		seenResultID[ur.CoverageID] = true

		if ur.Disposition != "covered" && ur.Disposition != "candidate" && ur.Disposition != "blocked" {
			return nil, fmt.Errorf("unit %q has invalid disposition %q", ur.CoverageID, ur.Disposition)
		}
		if ur.Disposition == "candidate" {
			for _, fp := range ur.CandidateFingerprints {
				if _, ok := candidateByFP[fp]; !ok {
					if _, existsInState := state.Candidates[fp]; !existsInState {
						return nil, fmt.Errorf("unit %q links fingerprint %q which is missing from candidates array", ur.CoverageID, fp)
					}
				}
			}
		}

		idx := ledgerIdx[ur.CoverageID]
		u := &units[idx]
		u.Status = ur.Disposition
		u.ReviewedPaths = nonNilSlice(ur.ReviewedPaths)
		u.LocalChecks = ur.Checks
		if u.LocalChecks == nil {
			u.LocalChecks = []validator.LocalCheck{}
		}
		u.ResultFingerprints = nonNilSlice(ur.CandidateFingerprints)
		u.Unresolved = nonNilSlice(ur.Unresolved)
		if len(result.Hardening) > 0 {
			u.Hardening = append(u.Hardening, result.Hardening...)
		}
	}

	rawLedger, err := json.MarshalIndent(units, "", "  ")
	if err != nil {
		return nil, err
	}
	ledgerErrs := validator.ValidateCoverageLedgerBytes(rawLedger, meta.Target, outputDir, validBlocks)
	if len(ledgerErrs) > 0 {
		return nil, fmt.Errorf("updated coverage-ledger failed validation: %s", strings.Join(ledgerErrs, "; "))
	}

	for fp, f := range candidateByFP {
		var linked []string
		for _, ur := range result.Units {
			for _, ufp := range ur.CandidateFingerprints {
				if ufp == fp {
					linked = append(linked, ur.CoverageID)
				}
			}
		}
		if existing, exists := state.Candidates[fp]; exists {
			existing.LinkedUnits = uniqueStrings(append(existing.LinkedUnits, linked...))
		} else {
			state.Candidates[fp] = &CandidateEnvelope{
				Fingerprint:     fp,
				HunterID:        agentID,
				ProposedVerdict: f.Verdict,
				CandidateRecord: f,
				CandidateRaw:    candidateRawByFP[fp],
				LinkedUnits:     linked,
			}
		}
	}

	state.HardeningNotes = uniqueStrings(append(state.HardeningNotes, result.Hardening...))
	state.UncoveredQueue = append(state.UncoveredQueue, result.Uncovered...)
	assign.Completed = true

	if err := rs.SaveLedger(units); err != nil {
		return nil, err
	}
	if err := rs.SaveState(state); err != nil {
		return nil, err
	}

	return map[string]any{
		"status":           "ok",
		"updated_units":    len(result.Units),
		"total_candidates": len(state.Candidates),
	}, nil
}

// SubmitCritic processes a coverage-critic wave, archiving reopened units into attempts[] and adding missing units.
func SubmitCritic(outputDir, agentID, criticKind string, result CriticResult) (map[string]any, error) {
	rs := store.New(outputDir)
	meta, err := rs.LoadMetadata()
	if err != nil {
		return nil, err
	}
	state, err := rs.LoadState()
	if err != nil {
		return nil, err
	}
	assign, ok := state.Agents[agentID]
	if !ok || assign.Role != "critic" {
		return nil, fmt.Errorf("agent_id %q is not a registered critic", agentID)
	}
	units, err := rs.LoadLedger()
	if err != nil {
		return nil, err
	}
	cat, err := spec.LoadCatalog()
	if err != nil {
		return nil, err
	}
	validBlocks := cat.ValidBlockMap()

	nextWave := state.CurrentWave + 1
	reason := result.ReassignmentReason
	if !validator.IsVisibleText(reason, 0) {
		reason = "coverage critic requested deeper verification of boundary paths"
	}

	reassignSet := make(map[string]bool)
	for _, id := range result.ReassignIDs {
		reassignSet[id] = true
	}

	reassignedCount := 0
	for i := range units {
		u := &units[i]
		if !reassignSet[u.CoverageID] {
			continue
		}
		if u.Status != "covered" && u.Status != "candidate" && u.Status != "blocked" {
			return nil, fmt.Errorf("cannot archive and reassign unit %q with status %q (must be covered, candidate, or blocked)", u.CoverageID, u.Status)
		}
		arch := validator.ArchivedAttempt{
			Wave:               u.Wave,
			Status:             u.Status,
			AgentID:            u.AgentID,
			ReviewedPaths:      u.ReviewedPaths,
			LocalChecks:        u.LocalChecks,
			ResultFingerprints: u.ResultFingerprints,
			Unresolved:         u.Unresolved,
			ReassignmentReason: reason,
		}
		u.Attempts = append(u.Attempts, arch)
		u.Wave = nextWave
		u.AgentID = nil
		u.ReviewedPaths = []string{}
		u.LocalChecks = []validator.LocalCheck{}
		u.ResultFingerprints = []string{}
		if meta.Profile == "quick" {
			u.Status = "deferred"
			u.Unresolved = []string{"quick_profile_final_critic"}
		} else {
			u.Status = "planned"
			u.Unresolved = []string{}
		}
		reassignedCount++
	}

	existingIDs := make(map[string]bool, len(units))
	for _, u := range units {
		existingIDs[u.CoverageID] = true
	}
	addedCount := 0
	for idx, mu := range result.MissingUnits {
		refs := validator.CanonicalRefs{
			Surface:     mu.Surface,
			Boundary:    mu.Boundary,
			Subsystem:   mu.Subsystem,
			AttackClass: mu.AttackClass,
		}
		if mu.CanonicalRefs != nil {
			refs = *mu.CanonicalRefs
		}
		if meta.Profile == "quick" {
			refs.Subsystem = "profile/quick/all-in-scope-subsystems"
		}
		cid, err := validator.DeriveCoverageID(refs)
		if err != nil {
			return nil, fmt.Errorf("missing_units[%d] canonical_refs error: %w", idx, err)
		}
		if existingIDs[cid] {
			continue
		}
		existingIDs[cid] = true

		status := "planned"
		var unresolved []string
		if len(meta.ScopePaths) > 0 && !scanner.AnyPathInScope(mu.StartingPaths, meta.ScopePaths) {
			status = "out_of_scope"
			unresolved = []string{mu.Reason}
		} else if meta.Profile == "quick" {
			status = "deferred"
			unresolved = []string{"quick_profile_final_critic"}
		} else {
			unresolved = []string{}
		}

		ordinary := mu.OrdinaryAttackClassBlock
		if ordinary == nil && strings.HasPrefix(refs.AttackClass, "ATTACK-CLASSES.md#") {
			ac := refs.AttackClass
			ordinary = &ac
		}

		selectedCompanions := cat.ExpandCompanionBlocks(mu.SelectedCompanionBlocks)
		if selectedCompanions == nil {
			selectedCompanions = []string{}
		}

		units = append(units, validator.CoverageUnit{
			CoverageID:               cid,
			CanonicalRefs:            refs,
			Surface:                  mu.Surface,
			Boundary:                 mu.Boundary,
			Subsystem:                mu.Subsystem,
			AttackClass:              mu.AttackClass,
			StartingPaths:            mu.StartingPaths,
			OrdinaryAttackClassBlock: ordinary,
			SelectedCompanionBlocks:  selectedCompanions,
			ExcludedBlocks:           nonNilExcluded(mu.ExcludedBlocks),
			PriorStatus:              "none",
			Attempts:                 []validator.ArchivedAttempt{},
			Wave:                     nextWave,
			Status:                   status,
			AgentID:                  nil,
			ReviewedPaths:            []string{},
			LocalChecks:              []validator.LocalCheck{},
			ResultFingerprints:       []string{},
			Unresolved:               unresolved,
		})
		addedCount++
	}

	sort.Slice(units, func(i, j int) bool {
		return units[i].CoverageID < units[j].CoverageID
	})

	rawLedger, err := json.MarshalIndent(units, "", "  ")
	if err != nil {
		return nil, err
	}
	if errs := validator.ValidateCoverageLedgerBytes(rawLedger, meta.Target, outputDir, validBlocks); len(errs) > 0 {
		return nil, fmt.Errorf("critic ledger update failed validation: %s", strings.Join(errs, "; "))
	}

	if reassignedCount > 0 || addedCount > 0 {
		state.CurrentWave = nextWave
	}
	if criticKind == "final_clean" && addedCount == 0 && reassignedCount == 0 && result.Stop {
		state.FinalCleanDone = true
	} else {
		state.PostWaveCriticDone = true
	}
	assign.Completed = true

	if err := rs.SaveLedger(units); err != nil {
		return nil, err
	}
	if err := rs.SaveState(state); err != nil {
		return nil, err
	}

	return map[string]any{
		"status":           "ok",
		"added_units":      addedCount,
		"reassigned_units": reassignedCount,
		"current_wave":     state.CurrentWave,
		"final_clean_done": state.FinalCleanDone,
	}, nil
}

func nonNilSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilExcluded(s []validator.ExcludedBlock) []validator.ExcludedBlock {
	if s == nil {
		return []validator.ExcludedBlock{}
	}
	return s
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if out == nil {
		return []string{}
	}
	return out
}
