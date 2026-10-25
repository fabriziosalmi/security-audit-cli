package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/promote"
	"github.com/fabriziosalmi/security-audit-cli/internal/spec"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// AssignAgentRequest is the input for sec-audit agent-assign / sec_audit_agent_assign.
type AssignAgentRequest struct {
	OutputDir   string   `json:"output_dir"`
	Role        string   `json:"role"` // "recon" | "hunter" | "critic" | "verifier" | "record_verifier"
	AgentID     string   `json:"agent_id"`
	CoverageIDs []string `json:"coverage_ids,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

// AssignAgentResponse returns the isolated workspace paths and compiled prompt.
type AssignAgentResponse struct {
	AgentID      string   `json:"agent_id"`
	Role         string   `json:"role"`
	ScratchDir   string   `json:"scratch_dir"`
	ArtifactsDir string   `json:"artifacts_dir"`
	DeferredIDs  []string `json:"deferred_ids,omitempty"`
	Prompt       string   `json:"prompt"`
}

// AssignAgent validates agent_id, enforces budget reserves and adversarial separation,
// creates isolated scratch/ and artifacts/ directories, updates ledger state, and compiles the exact prompt.
func AssignAgent(req AssignAgentRequest) (*AssignAgentResponse, error) {
	if !validator.IsSafeAgentID(req.AgentID) {
		return nil, fmt.Errorf("invalid canonical agent_id %q (must match ^[a-z0-9][a-z0-9_-]{0,63}$ and not be a reserved device name)", req.AgentID)
	}
	meta, err := loadMetadata(req.OutputDir)
	if err != nil {
		return nil, err
	}
	if meta.RunStatus == "incomplete" {
		return nil, fmt.Errorf("cannot assign agent: run is already marked incomplete (%s)", meta.IncompleteReason)
	}
	state, err := loadState(req.OutputDir)
	if err != nil {
		return nil, err
	}
	if _, exists := state.Agents[req.AgentID]; exists {
		return nil, fmt.Errorf("agent_id %q was already used in this run; every assignment requires a fresh agent_id", req.AgentID)
	}

	units, err := loadLedger(req.OutputDir)
	if err != nil {
		return nil, err
	}
	cat, err := spec.LoadCatalog()
	if err != nil {
		return nil, err
	}

	switch req.Role {
	case "recon", "hunter", "critic", "verifier", "record_verifier":
	default:
		return nil, fmt.Errorf("invalid role %q (expected recon, hunter, critic, verifier, or record_verifier)", req.Role)
	}

	// Budget enforcement before assignment
	if meta.Budget != nil {
		remaining := *meta.Budget - meta.AgentsSpent
		if remaining <= 0 {
			if req.Role == "verifier" || req.Role == "record_verifier" {
				meta.RunStatus = "incomplete"
				meta.IncompleteReason = "validation_budget_exhausted"
				_ = saveMetadata(req.OutputDir, meta)
			}
			return nil, fmt.Errorf("budget exhausted (%d/%d spent)", meta.AgentsSpent, *meta.Budget)
		}
		if req.Role == "hunter" {
			criticReserve := 1
			if meta.Profile != "quick" {
				criticReserve = 2
			}
			valReserve := len(state.Candidates)
			if valReserve < 1 {
				valReserve = 1
			}
			if remaining-1 < criticReserve+valReserve {
				// Mark requested planned units as deferred with budget_cannot_reserve_critics_and_validation
				reqSet := make(map[string]bool)
				for _, id := range req.CoverageIDs {
					reqSet[id] = true
				}
				var deferred []string
				for i := range units {
					if reqSet[units[i].CoverageID] && units[i].Status == "planned" {
						units[i].Status = "deferred"
						units[i].Unresolved = []string{"budget_cannot_reserve_critics_and_validation"}
						deferred = append(deferred, units[i].CoverageID)
					}
				}
				if err := saveLedger(req.OutputDir, units); err != nil {
					return nil, err
				}
				return &AssignAgentResponse{
					AgentID:     req.AgentID,
					Role:        req.Role,
					DeferredIDs: deferred,
					Prompt:      "BUDGET_GATE_DEFERRED: remaining budget cannot cover mandatory critic and validation reserves.",
				}, nil
			}
		}
	}

	// Adversarial isolation checks
	if req.Role == "verifier" {
		if req.Fingerprint == "" {
			return nil, fmt.Errorf("fingerprint is required for role=verifier")
		}
		env, ok := state.Candidates[req.Fingerprint]
		if !ok {
			return nil, fmt.Errorf("unknown candidate fingerprint %q", req.Fingerprint)
		}
		if req.AgentID == env.HunterID {
			return nil, fmt.Errorf("adversarial isolation violation: verifier agent_id %q cannot equal hunter_id %q", req.AgentID, env.HunterID)
		}
	}
	if req.Role == "record_verifier" {
		if req.Fingerprint == "" {
			return nil, fmt.Errorf("fingerprint is required for role=record_verifier")
		}
		env, ok := state.Candidates[req.Fingerprint]
		if !ok || env.FinalRecord == nil {
			return nil, fmt.Errorf("candidate %q has no Phase 3/4 decision yet", req.Fingerprint)
		}
		if req.AgentID == env.HunterID {
			return nil, fmt.Errorf("adversarial isolation violation: record_verifier %q cannot equal hunter_id %q", req.AgentID, env.HunterID)
		}
		if req.AgentID == env.Phase3VerifierID {
			return nil, fmt.Errorf("adversarial isolation violation: record_verifier %q cannot equal phase3_verifier_id %q", req.AgentID, env.Phase3VerifierID)
		}
		for _, prevP5 := range env.Phase5VerifierIDs {
			if req.AgentID == prevP5 {
				return nil, fmt.Errorf("adversarial isolation violation: record_verifier %q already participated in Phase 5 for %q", req.AgentID, req.Fingerprint)
			}
		}
	}

	var prompt string
	if req.Role == "hunter" {
		if len(req.CoverageIDs) == 0 {
			return nil, fmt.Errorf("at least one coverage_id is required for role=hunter")
		}
		unitMap := make(map[string]int)
		for idx, u := range units {
			unitMap[u.CoverageID] = idx
		}
		var assignedUnits []validator.CoverageUnit
		for _, cid := range req.CoverageIDs {
			idx, ok := unitMap[cid]
			if !ok {
				return nil, fmt.Errorf("coverage_id %q not found in coverage-ledger.json", cid)
			}
			u := &units[idx]
			if u.Status != "planned" {
				return nil, fmt.Errorf("coverage_id %q has status %q (must be \"planned\" to assign hunter)", cid, u.Status)
			}
			for _, att := range u.Attempts {
				if att.AgentID != nil && *att.AgentID == req.AgentID {
					return nil, fmt.Errorf("agent_id %q already owned an archived attempt on %q", req.AgentID, cid)
				}
			}
			aid := req.AgentID
			u.Status = "in_progress"
			u.AgentID = &aid
			u.Wave = state.CurrentWave
			assignedUnits = append(assignedUnits, *u)
		}
		if err := saveLedger(req.OutputDir, units); err != nil {
			return nil, err
		}
		p, err := compileHunterPrompt(req.OutputDir, req.AgentID, assignedUnits, units, state, cat)
		if err != nil {
			return nil, err
		}
		prompt = p
	} else if req.Role == "verifier" {
		env := state.Candidates[req.Fingerprint]
		p, err := compileVerifierPrompt(req.OutputDir, req.AgentID, env, units, cat)
		if err != nil {
			return nil, err
		}
		prompt = p
	} else if req.Role == "record_verifier" {
		env := state.Candidates[req.Fingerprint]
		prompt = compileRecordVerifierPrompt(env)
	} else if req.Role == "critic" {
		p, err := compileCriticPrompt(req.OutputDir, units, state)
		if err != nil {
			return nil, err
		}
		prompt = p
	} else if req.Role == "recon" {
		prompt = fmt.Sprintf("Read the target at %s. Do not use network access. Return only source facts with repository-relative file:line references.", meta.Target)
	}

	scratchDir := filepath.Join(req.OutputDir, "agents", req.AgentID, "scratch")
	artifactsDir := filepath.Join(req.OutputDir, "agents", req.AgentID, "artifacts")
	if err := os.MkdirAll(scratchDir, 0o700); err != nil {
		return nil, fmt.Errorf("create scratch dir: %w", err)
	}
	if err := os.MkdirAll(artifactsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create artifacts dir: %w", err)
	}

	state.Agents[req.AgentID] = &AgentAssignment{
		AgentID:     req.AgentID,
		Role:        req.Role,
		Wave:        state.CurrentWave,
		CoverageIDs: req.CoverageIDs,
		Fingerprint: req.Fingerprint,
		Completed:   false,
	}
	meta.AgentsSpent++
	if err := saveMetadata(req.OutputDir, meta); err != nil {
		return nil, err
	}
	if err := saveState(req.OutputDir, state); err != nil {
		return nil, err
	}

	return &AssignAgentResponse{
		AgentID:      req.AgentID,
		Role:         req.Role,
		ScratchDir:   scratchDir,
		ArtifactsDir: artifactsDir,
		Prompt:       prompt,
	}, nil
}

// PromoteArtifacts runs the 11-step OS race-safe descriptor-relative promotion from scratch/ to artifacts/.
func PromoteArtifacts(outputDir, agentID string, files []string, maxFileBytes, maxTotalBytes int64) ([]promote.PromotedArtifact, error) {
	return promote.PromoteAllowlist(outputDir, agentID, files, maxFileBytes, maxTotalBytes)
}

// HunterUnitResult matches one entry in the hunter's structured result `units` array.
type HunterUnitResult struct {
	CoverageID            string                 `json:"coverage_id"`
	Disposition           string                 `json:"disposition"` // "covered" | "candidate" | "blocked"
	ReviewedPaths         []string               `json:"reviewed_paths"`
	Checks                []validator.LocalCheck `json:"checks"`
	CandidateFingerprints []string               `json:"candidate_fingerprints"`
	Unresolved            []string               `json:"unresolved"`
}

// HunterStructuredResult matches the JSON returned by a Phase 2 hunter.
type HunterStructuredResult struct {
	Units      []HunterUnitResult `json:"units"`
	Candidates []map[string]any   `json:"candidates"`
	Hardening  []string           `json:"hardening"`
	Uncovered  []UncoveredEntry   `json:"uncovered"`
}

// SubmitHunter validates a hunter's structured result, verifies all cited source paths and lines on disk,
// updates coverage-ledger.json, and stores candidates for Phase 3 validation.
func SubmitHunter(outputDir, agentID string, result HunterStructuredResult) (map[string]any, error) {
	meta, err := loadMetadata(outputDir)
	if err != nil {
		return nil, err
	}
	state, err := loadState(outputDir)
	if err != nil {
		return nil, err
	}
	assign, ok := state.Agents[agentID]
	if !ok || assign.Role != "hunter" {
		return nil, fmt.Errorf("agent_id %q is not a registered hunter", agentID)
	}
	units, err := loadLedger(outputDir)
	if err != nil {
		return nil, err
	}
	cat, err := spec.LoadCatalog()
	if err != nil {
		return nil, err
	}
	validBlocks := make(map[string]bool, len(cat.Blocks))
	for k := range cat.Blocks {
		validBlocks[k] = true
	}

	// Validate every candidate first, including source-file & line checks on disk!
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

	// Map unit results to assigned coverage_ids
	assignedSet := make(map[string]bool)
	for _, cid := range assign.CoverageIDs {
		assignedSet[cid] = true
	}
	if len(result.Units) != len(assign.CoverageIDs) {
		return nil, fmt.Errorf("hunter must report exactly %d assigned units, got %d", len(assign.CoverageIDs), len(result.Units))
	}

	ledgerIdx := make(map[string]int)
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

	// Commit candidates to parent state
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

	if err := saveLedger(outputDir, units); err != nil {
		return nil, err
	}
	if err := saveState(outputDir, state); err != nil {
		return nil, err
	}

	return map[string]any{
		"status":           "ok",
		"updated_units":    len(result.Units),
		"total_candidates": len(state.Candidates),
	}, nil
}

// CriticMissingUnit describes a coverage gap discovered by a coverage critic.
type CriticMissingUnit struct {
	CanonicalRefs            *validator.CanonicalRefs  `json:"canonical_refs,omitempty"`
	Surface                  string                    `json:"surface"`
	Boundary                 string                    `json:"boundary"`
	Subsystem                string                    `json:"subsystem"`
	AttackClass              string                    `json:"attack_class"`
	StartingPaths            []string                  `json:"starting_paths"`
	OrdinaryAttackClassBlock *string                   `json:"ordinary_attack_class_block,omitempty"`
	SelectedCompanionBlocks  []string                  `json:"selected_companion_blocks"`
	ExcludedBlocks           []validator.ExcludedBlock `json:"excluded_blocks"`
	Reason                   string                    `json:"reason"`
}

// CriticResult matches the JSON returned by a Phase 2 coverage critic.
type CriticResult struct {
	MissingUnits       []CriticMissingUnit `json:"missing_units"`
	ReassignIDs        []string            `json:"reassign_ids"`
	ReassignmentReason string              `json:"reassignment_reason,omitempty"`
	ResolvedPriorLeads []string            `json:"resolved_prior_leads"`
	Stop               bool                `json:"stop"`
}

// SubmitCritic processes a coverage-critic wave, archiving reopened units into attempts[] and adding missing units.
func SubmitCritic(outputDir, agentID, criticKind string, result CriticResult) (map[string]any, error) {
	meta, err := loadMetadata(outputDir)
	if err != nil {
		return nil, err
	}
	state, err := loadState(outputDir)
	if err != nil {
		return nil, err
	}
	assign, ok := state.Agents[agentID]
	if !ok || assign.Role != "critic" {
		return nil, fmt.Errorf("agent_id %q is not a registered critic", agentID)
	}
	units, err := loadLedger(outputDir)
	if err != nil {
		return nil, err
	}
	cat, err := spec.LoadCatalog()
	if err != nil {
		return nil, err
	}
	validBlocks := make(map[string]bool, len(cat.Blocks))
	for k := range cat.Blocks {
		validBlocks[k] = true
	}

	nextWave := state.CurrentWave + 1
	reason := result.ReassignmentReason
	if !validator.IsVisibleText(reason, 0) {
		reason = "coverage critic requested deeper verification of boundary paths"
	}

	// Process reassignments
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

	// Process missing units
	existingIDs := make(map[string]bool)
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
		if len(meta.ScopePaths) > 0 && !anyPathInScope(mu.StartingPaths, meta.ScopePaths) {
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

		newUnit := validator.CoverageUnit{
			CoverageID:               cid,
			CanonicalRefs:            refs,
			Surface:                  mu.Surface,
			Boundary:                 mu.Boundary,
			Subsystem:                mu.Subsystem,
			AttackClass:              mu.AttackClass,
			StartingPaths:            mu.StartingPaths,
			OrdinaryAttackClassBlock: ordinary,
			SelectedCompanionBlocks:  cat.ExpandCompanionBlocks(mu.SelectedCompanionBlocks),
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
		}
		if newUnit.SelectedCompanionBlocks == nil {
			newUnit.SelectedCompanionBlocks = []string{}
		}
		units = append(units, newUnit)
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

	if err := saveLedger(outputDir, units); err != nil {
		return nil, err
	}
	if err := saveState(outputDir, state); err != nil {
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

// VerifierSubmitRequest is the input for sec-audit verifier-submit / sec_audit_verifier_submit.
type VerifierSubmitRequest struct {
	OutputDir   string                `json:"output_dir"`
	AgentID     string                `json:"agent_id"`
	Fingerprint string                `json:"fingerprint"`
	Decision    string                `json:"decision"` // "confirmed" | "needs_validation" | "rejected"
	Record      map[string]any        `json:"record"`
	Check       *validator.LocalCheck `json:"check,omitempty"`
}

// SubmitVerifier enforces adversarial separation (verifier != hunter), validates the Phase 3 record
// against report-schema.json and source files on disk, updates linked ledger units, and writes findings.json.
func SubmitVerifier(req VerifierSubmitRequest) (map[string]any, error) {
	meta, err := loadMetadata(req.OutputDir)
	if err != nil {
		return nil, err
	}
	state, err := loadState(req.OutputDir)
	if err != nil {
		return nil, err
	}
	assign, ok := state.Agents[req.AgentID]
	if !ok || assign.Role != "verifier" {
		return nil, fmt.Errorf("agent_id %q is not a registered Phase 3 verifier", req.AgentID)
	}
	env, ok := state.Candidates[req.Fingerprint]
	if !ok {
		return nil, fmt.Errorf("unknown candidate fingerprint %q", req.Fingerprint)
	}
	if req.AgentID == env.HunterID {
		return nil, fmt.Errorf("adversarial isolation violation: verifier %q cannot equal hunter %q", req.AgentID, env.HunterID)
	}
	if req.Decision != "confirmed" && req.Decision != "needs_validation" && req.Decision != "rejected" {
		return nil, fmt.Errorf("invalid decision %q (expected confirmed, needs_validation, or rejected)", req.Decision)
	}

	rawBytes, err := json.Marshal(req.Record)
	if err != nil {
		return nil, err
	}
	var finding validator.Finding
	if err := json.Unmarshal(rawBytes, &finding); err != nil {
		return nil, fmt.Errorf("unmarshal record: %w", err)
	}
	if finding.Verdict != req.Decision {
		return nil, fmt.Errorf("record.verdict %q does not match decision %q", finding.Verdict, req.Decision)
	}
	if finding.Fingerprint != req.Fingerprint {
		return nil, fmt.Errorf("record.fingerprint %q does not match candidate fingerprint %q", finding.Fingerprint, req.Fingerprint)
	}

	errs := validator.ValidateSingleFinding(finding, req.Record, "$", meta.Target, false)
	if len(errs) > 0 {
		return nil, fmt.Errorf("verifier record failed schema/source validation: %s", strings.Join(errs, "; "))
	}

	units, err := loadLedger(req.OutputDir)
	if err != nil {
		return nil, err
	}
	if req.Check != nil {
		req.Check.AgentID = req.AgentID
		linkedSet := make(map[string]bool)
		for _, cid := range env.LinkedUnits {
			linkedSet[cid] = true
		}
		for i := range units {
			u := &units[i]
			if linkedSet[u.CoverageID] {
				if u.Status == "planned" {
					// Carried prior record unit: verifier becomes assignment owner and moves unit to candidate
					aid := req.AgentID
					u.AgentID = &aid
					u.Status = "candidate"
					u.ResultFingerprints = []string{req.Fingerprint}
				}
				u.LocalChecks = append(u.LocalChecks, *req.Check)
				u.ReviewedPaths = uniqueStrings(append(u.ReviewedPaths, req.Check.ReviewedPaths...))
			}
		}
		if err := saveLedger(req.OutputDir, units); err != nil {
			return nil, err
		}
	}

	env.Phase3VerifierID = req.AgentID
	env.Phase3Decision = req.Decision
	env.FinalRecord = &finding
	env.FinalRaw = req.Record
	if meta.Profile == "quick" || req.Decision == "rejected" {
		env.Phase5Verified = true
		env.NeedsFreshVerify = false
	} else {
		env.Phase5Verified = false
		env.NeedsFreshVerify = true
	}
	assign.Completed = true

	if err := syncFindingsFile(req.OutputDir, meta.Target, state); err != nil {
		return nil, err
	}
	if err := saveState(req.OutputDir, state); err != nil {
		return nil, err
	}

	return map[string]any{
		"status":           "ok",
		"fingerprint":      req.Fingerprint,
		"decision":         req.Decision,
		"phase5_satisfied": env.Phase5Verified,
	}, nil
}

// RecordVerifySubmitRequest is the input for sec-audit record-verify-submit / sec_audit_record_verify_submit.
type RecordVerifySubmitRequest struct {
	OutputDir   string         `json:"output_dir"`
	AgentID     string         `json:"agent_id"`
	Fingerprint string         `json:"fingerprint"`
	Decision    string         `json:"decision"` // "verified" | "replace"
	Reason      string         `json:"reason,omitempty"`
	Record      map[string]any `json:"record,omitempty"`
}

// SubmitRecordVerifier handles Phase 5 independent record verification and detects material replacements
// that require an additional fresh independent verifier.
func SubmitRecordVerifier(req RecordVerifySubmitRequest) (map[string]any, error) {
	meta, err := loadMetadata(req.OutputDir)
	if err != nil {
		return nil, err
	}
	state, err := loadState(req.OutputDir)
	if err != nil {
		return nil, err
	}
	assign, ok := state.Agents[req.AgentID]
	if !ok || assign.Role != "record_verifier" {
		return nil, fmt.Errorf("agent_id %q is not a registered Phase 5 record_verifier", req.AgentID)
	}
	env, ok := state.Candidates[req.Fingerprint]
	if !ok || env.FinalRecord == nil {
		return nil, fmt.Errorf("candidate %q has no Phase 3/4 record to verify", req.Fingerprint)
	}
	if req.AgentID == env.HunterID || req.AgentID == env.Phase3VerifierID {
		return nil, fmt.Errorf("adversarial isolation violation: record_verifier %q cannot match hunter or Phase 3 verifier", req.AgentID)
	}
	for _, prev := range env.Phase5VerifierIDs {
		if req.AgentID == prev {
			return nil, fmt.Errorf("adversarial isolation violation: record_verifier %q already reviewed %q", req.AgentID, req.Fingerprint)
		}
	}

	materialReplacement := false
	switch req.Decision {
	case "verified":
		env.Phase5VerifierIDs = append(env.Phase5VerifierIDs, req.AgentID)
		env.Phase5Verified = true
		env.NeedsFreshVerify = false
	case "replace":
		if !validator.IsVisibleText(req.Reason, 0) {
			return nil, fmt.Errorf("replacement requires a non-empty reason")
		}
		if req.Record == nil {
			return nil, fmt.Errorf("replacement requires a replacement record object")
		}
		rawBytes, err := json.Marshal(req.Record)
		if err != nil {
			return nil, err
		}
		var newFinding validator.Finding
		if err := json.Unmarshal(rawBytes, &newFinding); err != nil {
			return nil, fmt.Errorf("unmarshal replacement record: %w", err)
		}
		if newFinding.Fingerprint != req.Fingerprint {
			return nil, fmt.Errorf("replacement fingerprint %q must match %q", newFinding.Fingerprint, req.Fingerprint)
		}
		errs := validator.ValidateSingleFinding(newFinding, req.Record, "$", meta.Target, false)
		if len(errs) > 0 {
			return nil, fmt.Errorf("replacement record failed validation: %s", strings.Join(errs, "; "))
		}

		materialReplacement = isMaterialReplacement(*env.FinalRecord, newFinding)
		env.FinalRecord = &newFinding
		env.FinalRaw = req.Record
		env.Phase5VerifierIDs = append(env.Phase5VerifierIDs, req.AgentID)
		if materialReplacement && newFinding.Verdict != "rejected" {
			// SKILL.md Phase 5 rule: material replacements receive another independent verifier!
			env.Phase5Verified = false
			env.NeedsFreshVerify = true
		} else {
			env.Phase5Verified = true
			env.NeedsFreshVerify = false
		}
	default:
		return nil, fmt.Errorf("invalid Phase 5 decision %q (expected verified or replace)", req.Decision)
	}

	assign.Completed = true
	if err := syncFindingsFile(req.OutputDir, meta.Target, state); err != nil {
		return nil, err
	}
	if err := saveState(req.OutputDir, state); err != nil {
		return nil, err
	}

	return map[string]any{
		"status":                        "ok",
		"fingerprint":                   req.Fingerprint,
		"decision":                      req.Decision,
		"material_replacement":          materialReplacement,
		"requires_another_fresh_verify": env.NeedsFreshVerify,
		"phase5_verified":               env.Phase5Verified,
	}, nil
}

// isMaterialReplacement implements the exact Phase 5 rule from VALIDATION-AND-REPORTING.md:
// "Do not apply a Phase 5 replacement as final when it promotes a record to a stronger verdict,
// including any promotion to confirmed, or materially changes the root cause, trace, execution input
// or observed result, demonstrated impact, or severity."
func isMaterialReplacement(oldF, newF validator.Finding) bool {
	verdictStrength := map[string]int{"rejected": 0, "needs_validation": 1, "confirmed": 2}
	if verdictStrength[newF.Verdict] > verdictStrength[oldF.Verdict] {
		return true
	}
	if oldF.RootCause != newF.RootCause || oldF.ClaimedRootCause != newF.ClaimedRootCause {
		return true
	}
	if len(oldF.Trace) != len(newF.Trace) {
		return true
	}
	for i := range oldF.Trace {
		if oldF.Trace[i].Kind != newF.Trace[i].Kind || oldF.Trace[i].File != newF.Trace[i].File || oldF.Trace[i].Line != newF.Trace[i].Line || oldF.Trace[i].Scope != newF.Trace[i].Scope {
			return true
		}
	}
	if oldF.Execution != nil && newF.Execution != nil {
		if !reflect.DeepEqual(oldF.Execution.Payloads, newF.Execution.Payloads) || oldF.Execution.ObservedResult != newF.Execution.ObservedResult {
			return true
		}
	} else if (oldF.Execution == nil) != (newF.Execution == nil) {
		return true
	}
	if oldF.Severity != nil && newF.Severity != nil {
		if oldF.Severity.Impact.Score != newF.Severity.Impact.Score || oldF.Severity.OverallSeverity != newF.Severity.OverallSeverity {
			return true
		}
	} else if (oldF.Severity == nil) != (newF.Severity == nil) {
		return true
	}
	return false
}

func syncFindingsFile(outputDir, targetDir string, state *InternalState) error {
	var findings []validator.Finding
	for _, env := range state.Candidates {
		if env.FinalRecord != nil {
			findings = append(findings, *env.FinalRecord)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
	if err := saveFindings(outputDir, findings); err != nil {
		return err
	}
	rawBytes, err := os.ReadFile(filepath.Join(outputDir, "findings.json"))
	if err != nil {
		return err
	}
	errs := validator.ValidateFindingsBytes(rawBytes, targetDir)
	if len(errs) > 0 {
		return fmt.Errorf("findings.json failed validation: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ValidateRun validates coverage-ledger.json, findings.json, source paths on disk, and cross-file consistency.
func ValidateRun(outputDir string) (map[string]any, error) {
	meta, err := loadMetadata(outputDir)
	if err != nil {
		return nil, err
	}
	cat, err := spec.LoadCatalog()
	if err != nil {
		return nil, err
	}
	validBlocks := make(map[string]bool, len(cat.Blocks))
	for k := range cat.Blocks {
		validBlocks[k] = true
	}

	ledgerPath := filepath.Join(outputDir, "coverage-ledger.json")
	ledgerErrs, err := validator.ValidateCoverageLedgerFile(ledgerPath, meta.Target, outputDir, validBlocks)
	if err != nil {
		return nil, fmt.Errorf("ledger read error: %w", err)
	}

	findingsPath := filepath.Join(outputDir, "findings.json")
	var findingsErrs []string
	findingsCount := 0
	if _, stErr := os.Stat(findingsPath); stErr == nil {
		fErrs, ferr := validator.ValidateFindingsFile(findingsPath, meta.Target)
		if ferr != nil {
			return nil, fmt.Errorf("findings read error: %w", ferr)
		}
		findingsErrs = fErrs
		findings, _ := loadFindings(outputDir)
		findingsCount = len(findings)
	}

	units, _ := loadLedger(outputDir)
	valid := len(ledgerErrs) == 0 && len(findingsErrs) == 0
	return map[string]any{
		"valid":          valid,
		"units_count":    len(units),
		"findings_count": findingsCount,
		"ledger_errors":  nonNilSlice(ledgerErrs),
		"finding_errors": nonNilSlice(findingsErrs),
	}, nil
}

func compileHunterPrompt(outputDir, agentID string, assignedUnits, allUnits []validator.CoverageUnit, state *InternalState, cat *spec.Catalog) (string, error) {
	archBytes, err := os.ReadFile(filepath.Join(outputDir, "architecture.md"))
	if err != nil {
		return "", fmt.Errorf("architecture.md must be written before assigning hunters: %w", err)
	}
	schemas, err := cat.SchemaBranches(false)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	// Part 1: Two-sentence role preamble
	b.WriteString("Your goal is to find source-grounded security invariant failures in your assigned coverage units. You must return exactly one JSON object matching the structured-result contract at the end of this prompt.\n\n")

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
	for _, env := range state.Candidates {
		if env.HunterID == "prior-run-carryover" && env.ProposedVerdict == "confirmed" {
			fmt.Fprintf(&b, "- Carried prior confirmed exclusion: `%s` (%s) — %s\n", env.Fingerprint, env.CandidateRecord.Title, env.CandidateRecord.RootCause)
		}
	}
	b.WriteString("\n")

	// Part 9: Scratch/artifact paths, agent ID, and structured result contract
	fmt.Fprintf(&b, "## Workspace and Structured Result Contract\n\n- Canonical `agent_id`: `%s`\n- Writable scratch directory: `%s/agents/%s/scratch`\n- Retained artifacts prefix (parent-promoted only): `agents/%s/artifacts/`\n\nSchema branches (`confirmed` and `needs_validation`):\n```json\n%s\n```\n",
		agentID, outputDir, agentID, agentID, schemas)

	return b.String(), nil
}

func compileVerifierPrompt(outputDir, agentID string, env *CandidateEnvelope, allUnits []validator.CoverageUnit, cat *spec.Catalog) (string, error) {
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
	fmt.Fprintf(&b, "Assigned verifier `agent_id`: `%s`\nScratch directory: `%s/agents/%s/scratch`\nReturn `{\"decision\": \"confirmed|needs_validation|rejected\", \"record\": { ... }}`.\n", agentID, outputDir, agentID)
	return b.String(), nil
}

func compileRecordVerifierPrompt(env *CandidateEnvelope) string {
	recJSON, _ := json.MarshalIndent(env.FinalRecord, "", "  ")
	return fmt.Sprintf("Independently verify this final record against repository source:\n\n```json\n%s\n```\n\nReturn `{\"decision\":\"verified\",\"fingerprint\":%q}` or `{\"decision\":\"replace\",\"reason\":\"...\",\"record\":{...}}`.", string(recJSON), env.Fingerprint)
}

func compileCriticPrompt(outputDir string, units []validator.CoverageUnit, state *InternalState) (string, error) {
	archBytes, _ := os.ReadFile(filepath.Join(outputDir, "architecture.md"))
	ledgerJSON, _ := json.MarshalIndent(units, "", "  ")
	return fmt.Sprintf("Review architecture and coverage-ledger.json for unmapped entry points, unchecked parallel paths, or premature closures.\n\n## Architecture\n%s\n\n## Coverage Ledger\n```json\n%s\n```\n", string(archBytes), string(ledgerJSON)), nil
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
