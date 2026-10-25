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
	if assign.Completed {
		return nil, fmt.Errorf("critic %q has already submitted its result", agentID)
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
			return nil, fmt.Errorf(
				"cannot archive and reassign unit %q with status %q (must be covered, candidate, or blocked)",
				u.CoverageID, u.Status,
			)
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
	state.UncoveredQueue = []UncoveredEntry{}
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
