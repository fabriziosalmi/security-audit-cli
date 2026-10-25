package engine

import (
	"github.com/fabriziosalmi/security-audit-cli/internal/scanner"
	"github.com/fabriziosalmi/security-audit-cli/internal/store"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// Re-export core domain types from store and scanner for clean caller ergonomics.
type (
	RunMetadata             = store.RunMetadata
	CandidateEnvelope       = store.CandidateEnvelope
	AgentAssignment         = store.AgentAssignment
	PriorCarryover          = store.PriorCarryover
	InternalState           = store.InternalState
	UncoveredEntry          = store.UncoveredEntry
	CompanionRecommendation = scanner.CompanionRecommendation
	RepoBrief               = scanner.RepoBrief
)

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
	OutputDir       string           `json:"output_dir"`
	Metadata        RunMetadata      `json:"metadata"`
	RepoBrief       RepoBrief        `json:"repo_brief"`
	PriorCarryovers []PriorCarryover `json:"prior_carryovers,omitempty"`
}

// CatalogRequest is the input for sec-audit catalog / sec_audit_catalog.
type CatalogRequest struct {
	File  string `json:"file,omitempty"`
	Block string `json:"block,omitempty"`
}

// ArchitectureRequest is the input for sec-audit architecture / sec_audit_architecture.
type ArchitectureRequest struct {
	OutputDir string `json:"output_dir"`
	Content   string `json:"content"`
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

// SeedLedgerRequest is the input for sec-audit ledger-seed / sec_audit_ledger_seed.
type SeedLedgerRequest struct {
	OutputDir string          `json:"output_dir"`
	Units     []SeedUnitInput `json:"units"`
}

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

// PromoteArtifactsRequest is the input for sec-audit artifact-promote / sec_audit_artifact_promote.
type PromoteArtifactsRequest struct {
	OutputDir     string   `json:"output_dir"`
	AgentID       string   `json:"agent_id"`
	Files         []string `json:"files"`
	MaxFileBytes  int64    `json:"max_file_bytes,omitempty"`
	MaxTotalBytes int64    `json:"max_total_bytes,omitempty"`
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

// SubmitHunterRequest is the input for sec-audit hunter-submit / sec_audit_hunter_submit.
type SubmitHunterRequest struct {
	OutputDir string                 `json:"output_dir"`
	AgentID   string                 `json:"agent_id"`
	Result    HunterStructuredResult `json:"result"`
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

// SubmitCriticRequest is the input for sec-audit critic-submit / sec_audit_critic_submit.
type SubmitCriticRequest struct {
	OutputDir  string       `json:"output_dir"`
	AgentID    string       `json:"agent_id"`
	CriticKind string       `json:"critic_kind,omitempty"`
	Result     CriticResult `json:"result"`
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

// RecordVerifySubmitRequest is the input for sec-audit record-verify-submit / sec_audit_record_verify_submit.
type RecordVerifySubmitRequest struct {
	OutputDir   string         `json:"output_dir"`
	AgentID     string         `json:"agent_id"`
	Fingerprint string         `json:"fingerprint"`
	Decision    string         `json:"decision"` // "verified" | "replace"
	Reason      string         `json:"reason,omitempty"`
	Record      map[string]any `json:"record,omitempty"`
}

// ValidateRequest is the input for sec-audit validate / sec_audit_validate.
type ValidateRequest struct {
	OutputDir    string `json:"output_dir,omitempty"`
	LedgerPath   string `json:"ledger_path,omitempty"`
	FindingsPath string `json:"findings_path,omitempty"`
	TargetPath   string `json:"target_path,omitempty"`
}

// RenderRequest is the input for sec-audit render / sec_audit_render.
type RenderRequest struct {
	OutputDir        string `json:"output_dir"`
	IncompleteReason string `json:"incomplete_reason,omitempty"`
}

// RenderResponse lists the generated Phase 6 artifact paths and terminal run status.
type RenderResponse struct {
	RunStatus           string   `json:"run_status"`
	IncompleteReason    string   `json:"incomplete_reason,omitempty"`
	ReportPath          string   `json:"report_path"`
	FindingsDetailPath  string   `json:"findings_detail_path"`
	NeedsValidationPath string   `json:"needs_validation_path"`
	SarifPath           string   `json:"sarif_path"`
	ConfirmedCount      int      `json:"confirmed_count"`
	NeedsValCount       int      `json:"needs_validation_count"`
	RejectedCount       int      `json:"rejected_count"`
	HardeningCount      int      `json:"hardening_count"`
	UnvalidatedFPs      []string `json:"unvalidated_fingerprints"`
}
