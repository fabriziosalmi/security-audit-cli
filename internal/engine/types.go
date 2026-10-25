package engine

import (
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// RunMetadata matches the run-metadata.json contract from SKILL.md.
type RunMetadata struct {
	RunID                  string            `json:"run_id"`
	Repo                   string            `json:"repo"`
	Target                 string            `json:"target"`
	SourceRef              string            `json:"source_ref"`
	DirtyWorktree          bool              `json:"dirty_worktree"`
	Profile                string            `json:"profile"` // "quick" | "standard" | "deep"
	ScopePaths             []string          `json:"scope_paths"`
	Budget                 *int              `json:"budget"`
	AgentsSpent            int               `json:"agents_spent"`
	ExecutionPolicy        string            `json:"execution_policy"`
	SelectedCompanionFiles []string          `json:"selected_companion_files"`
	PriorRunPaths          []string          `json:"prior_run_paths"`
	SharedFileOwners       map[string]string `json:"shared_file_owners"`
	RunStatus              string            `json:"run_status"` // "in_progress" | "complete" | "incomplete"
	IncompleteReason       string            `json:"incomplete_reason,omitempty"`
}

// CandidateEnvelope tracks a candidate's lifecycle and adversarial provenance across Phases 2, 3, 4, and 5.
type CandidateEnvelope struct {
	Fingerprint       string            `json:"fingerprint"`
	HunterID          string            `json:"hunter_id"`
	ProposedVerdict   string            `json:"proposed_verdict"` // "confirmed" | "needs_validation"
	CandidateRecord   validator.Finding `json:"candidate_record"`
	CandidateRaw      map[string]any    `json:"candidate_raw"`
	LinkedUnits       []string          `json:"linked_units"`
	Phase3VerifierID  string            `json:"phase3_verifier_id,omitempty"`
	Phase3Decision    string            `json:"phase3_decision,omitempty"` // "confirmed" | "needs_validation" | "rejected"
	FinalRecord       *validator.Finding `json:"final_record,omitempty"`
	FinalRaw          map[string]any    `json:"final_raw,omitempty"`
	Phase5VerifierIDs []string          `json:"phase5_verifier_ids,omitempty"`
	Phase5Verified    bool              `json:"phase5_verified"`
	NeedsFreshVerify  bool              `json:"needs_fresh_verify"`
}

// AgentAssignment records an allocated agent invocation and its role/ownership.
type AgentAssignment struct {
	AgentID     string   `json:"agent_id"`
	Role        string   `json:"role"` // "recon" | "hunter" | "critic" | "verifier" | "record_verifier"
	Wave        int      `json:"wave"`
	CoverageIDs []string `json:"coverage_ids,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Completed   bool     `json:"completed"`
}

// PriorCarryover summarizes how prior-run records and units map onto the current source.
type PriorCarryover struct {
	PriorRunDir             string   `json:"prior_run_dir"`
	CarriedConfirmed        []string `json:"carried_confirmed_fingerprints"`
	ChangedConfirmed        []string `json:"changed_confirmed_fingerprints"`
	CarriedNeedsValidation  []string `json:"carried_needs_validation_fingerprints"`
	SuppressedRejected      []string `json:"suppressed_rejected_fingerprints"`
}

// InternalState persists parent-side orchestration state in <output-dir>/.sec-audit-state.json.
type InternalState struct {
	CurrentWave        int                          `json:"current_wave"`
	PostWaveCriticDone bool                         `json:"post_wave_critic_done"`
	FinalCleanDone     bool                         `json:"final_clean_done"`
	Agents             map[string]*AgentAssignment  `json:"agents"`
	Candidates         map[string]*CandidateEnvelope `json:"candidates"`
	HardeningNotes     []string                     `json:"hardening_notes"`
	UncoveredQueue     []UncoveredEntry             `json:"uncovered_queue"`
	PriorCarryovers    []PriorCarryover             `json:"prior_carryovers"`
}

// UncoveredEntry represents a newly discovered boundary reported by a hunter or critic.
type UncoveredEntry struct {
	Surface       string   `json:"surface"`
	Boundary      string   `json:"boundary"`
	Subsystem     string   `json:"subsystem"`
	AttackClass   string   `json:"attack_class"`
	StartingPaths []string `json:"starting_paths"`
	Reason        string   `json:"reason"`
}

// CompanionRecommendation links a companion file to source-grounded files that triggered it.
type CompanionRecommendation struct {
	File     string   `json:"file"`
	Reason   string   `json:"reason"`
	Evidence []string `json:"evidence_paths"`
}

// RepoBrief is the deterministic static reconnaissance output returned by Init.
type RepoBrief struct {
	TotalFiles              int                       `json:"total_files"`
	Languages               map[string]int            `json:"languages"`
	Manifests               []string                  `json:"manifests"`
	EntrypointCandidates    []string                  `json:"entrypoint_candidates"`
	AuthBoundaryCandidates  []string                  `json:"auth_boundary_candidates"`
	RecommendedCompanions   []CompanionRecommendation `json:"recommended_companions"`
	SuggestedSeedSubsystems []string                  `json:"suggested_seed_subsystems"`
}

// InitRequest is the input for sec-audit init / sec_audit_init.
type InitRequest struct {
	Target       string   `json:"target"`
	OutputDir    string   `json:"output_dir,omitempty"`
	Profile      string   `json:"profile,omitempty"`
	ScopePaths   []string `json:"scope_paths,omitempty"`
	Budget       *int     `json:"budget,omitempty"`
	PriorRunDirs []string `json:"prior_run_dirs,omitempty"`
}

// InitResponse is the output for sec-audit init / sec_audit_init.
type InitResponse struct {
	OutputDir       string          `json:"output_dir"`
	Metadata        RunMetadata     `json:"metadata"`
	RepoBrief       RepoBrief       `json:"repo_brief"`
	PriorCarryovers []PriorCarryover `json:"prior_carryovers,omitempty"`
}

// SeedUnitInput is a single unit specification for ledger_seed (coverage_id is derived automatically).
type SeedUnitInput struct {
	CanonicalRefs            validator.CanonicalRefs   `json:"canonical_refs"`
	Surface                  string                    `json:"surface"`
	Boundary                 string                    `json:"boundary"`
	Subsystem                string                    `json:"subsystem"`
	AttackClass              string                    `json:"attack_class"`
	Lifecycle                *string                   `json:"lifecycle,omitempty"`
	StartingPaths            []string                  `json:"starting_paths"`
	OrdinaryAttackClassBlock *string                   `json:"ordinary_attack_class_block"`
	SelectedCompanionBlocks  []string                  `json:"selected_companion_blocks"`
	ExcludedBlocks           []validator.ExcludedBlock `json:"excluded_blocks"`
	PriorStatus              string                    `json:"prior_status,omitempty"`
}
