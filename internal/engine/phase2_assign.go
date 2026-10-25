package engine

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fabriziosalmi/security-audit-cli/internal/promote"
	"github.com/fabriziosalmi/security-audit-cli/internal/prompt"
	"github.com/fabriziosalmi/security-audit-cli/internal/spec"
	"github.com/fabriziosalmi/security-audit-cli/internal/store"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// AssignAgent validates agent_id, enforces budget reserves and adversarial separation,
// creates isolated scratch/ and artifacts/ directories, updates ledger state, and compiles the exact prompt.
func AssignAgent(req AssignAgentRequest) (*AssignAgentResponse, error) {
	if !validator.IsSafeAgentID(req.AgentID) {
		return nil, fmt.Errorf(
			"invalid canonical agent_id %q (must match ^[a-z0-9][a-z0-9_-]{0,63}$ and not be a reserved device name)",
			req.AgentID,
		)
	}
	rs := store.New(req.OutputDir)
	meta, err := rs.LoadMetadata()
	if err != nil {
		return nil, err
	}
	if meta.RunStatus == "incomplete" {
		return nil, fmt.Errorf("cannot assign agent: run is already marked incomplete (%s)", meta.IncompleteReason)
	}
	state, err := rs.LoadState()
	if err != nil {
		return nil, err
	}
	if _, exists := state.Agents[req.AgentID]; exists {
		return nil, fmt.Errorf("agent_id %q was already used in this run; every assignment requires a fresh agent_id", req.AgentID)
	}

	units, err := rs.LoadLedger()
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
				_ = rs.SaveMetadata(meta)
			}
			return nil, fmt.Errorf("budget exhausted (%d/%d spent)", meta.AgentsSpent, *meta.Budget)
		}
		if req.Role == "hunter" {
			criticReserve := 1
			if meta.Profile != "quick" {
				criticReserve = 2
			}
			valReserve := max(len(state.Candidates), 1)
			if remaining-1 < criticReserve+valReserve {
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
				if err := rs.SaveLedger(units); err != nil {
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
	if err := enforceAdversarialSeparation(req, state); err != nil {
		return nil, err
	}

	compiledPrompt, err := buildRolePrompt(req, rs, meta, state, units, cat)
	if err != nil {
		return nil, err
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
	if err := rs.SaveMetadata(meta); err != nil {
		return nil, err
	}
	if err := rs.SaveState(state); err != nil {
		return nil, err
	}

	return &AssignAgentResponse{
		AgentID:      req.AgentID,
		Role:         req.Role,
		ScratchDir:   scratchDir,
		ArtifactsDir: artifactsDir,
		Prompt:       compiledPrompt,
	}, nil
}

func enforceAdversarialSeparation(req AssignAgentRequest, state *InternalState) error {
	switch req.Role {
	case "verifier":
		if req.Fingerprint == "" {
			return fmt.Errorf("fingerprint is required for role=verifier")
		}
		env, ok := state.Candidates[req.Fingerprint]
		if !ok {
			return fmt.Errorf("unknown candidate fingerprint %q", req.Fingerprint)
		}
		if req.AgentID == env.HunterID {
			return fmt.Errorf("adversarial isolation violation: verifier agent_id %q cannot equal hunter_id %q", req.AgentID, env.HunterID)
		}
	case "record_verifier":
		if req.Fingerprint == "" {
			return fmt.Errorf("fingerprint is required for role=record_verifier")
		}
		env, ok := state.Candidates[req.Fingerprint]
		if !ok || env.FinalRecord == nil {
			return fmt.Errorf("candidate %q has no Phase 3/4 decision yet", req.Fingerprint)
		}
		if req.AgentID == env.HunterID {
			return fmt.Errorf("adversarial isolation violation: record_verifier %q cannot equal hunter_id %q", req.AgentID, env.HunterID)
		}
		if req.AgentID == env.Phase3VerifierID {
			return fmt.Errorf(
				"adversarial isolation violation: record_verifier %q cannot equal phase3_verifier_id %q",
				req.AgentID, env.Phase3VerifierID,
			)
		}
		for _, prevP5 := range env.Phase5VerifierIDs {
			if req.AgentID == prevP5 {
				return fmt.Errorf(
					"adversarial isolation violation: record_verifier %q already participated in Phase 5 for %q",
					req.AgentID, req.Fingerprint,
				)
			}
		}
	}
	return nil
}

func buildRolePrompt(
	req AssignAgentRequest,
	rs *store.RunStore,
	meta *RunMetadata,
	state *InternalState,
	units []validator.CoverageUnit,
	cat *spec.Catalog,
) (string, error) {
	switch req.Role {
	case "hunter":
		if len(req.CoverageIDs) == 0 {
			return "", fmt.Errorf("at least one coverage_id is required for role=hunter")
		}
		unitMap := make(map[string]int, len(units))
		for idx, u := range units {
			unitMap[u.CoverageID] = idx
		}
		var assignedUnits []validator.CoverageUnit
		for _, cid := range req.CoverageIDs {
			idx, ok := unitMap[cid]
			if !ok {
				return "", fmt.Errorf("coverage_id %q not found in coverage-ledger.json", cid)
			}
			u := &units[idx]
			if u.Status != "planned" {
				return "", fmt.Errorf("coverage_id %q has status %q (must be \"planned\" to assign hunter)", cid, u.Status)
			}
			for _, att := range u.Attempts {
				if att.AgentID != nil && *att.AgentID == req.AgentID {
					return "", fmt.Errorf("agent_id %q already owned an archived attempt on %q", req.AgentID, cid)
				}
			}
			aid := req.AgentID
			u.Status = "in_progress"
			u.AgentID = &aid
			u.Wave = state.CurrentWave
			assignedUnits = append(assignedUnits, *u)
		}
		if err := rs.SaveLedger(units); err != nil {
			return "", err
		}
		return prompt.CompileHunter(req.OutputDir, req.AgentID, assignedUnits, units, state, cat)
	case "verifier":
		return prompt.CompileVerifier(req.OutputDir, req.AgentID, state.Candidates[req.Fingerprint], cat)
	case "record_verifier":
		return prompt.CompileRecordVerifier(state.Candidates[req.Fingerprint]), nil
	case "critic":
		return prompt.CompileCritic(req.OutputDir, units)
	default: // "recon"
		return prompt.CompileRecon(meta.Target), nil
	}
}

// PromoteArtifacts runs the 11-step OS race-safe descriptor-relative promotion from scratch/ to artifacts/.
func PromoteArtifacts(outputDir, agentID string, files []string, maxFileBytes, maxTotalBytes int64) ([]promote.PromotedArtifact, error) {
	return promote.PromoteAllowlist(outputDir, agentID, files, maxFileBytes, maxTotalBytes)
}
