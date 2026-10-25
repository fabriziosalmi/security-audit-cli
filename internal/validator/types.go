package validator

// CanonicalRefs holds the stable source-derived identity of a coverage unit.
type CanonicalRefs struct {
	Surface     string  `json:"surface"`
	Boundary    string  `json:"boundary"`
	Subsystem   string  `json:"subsystem"`
	AttackClass string  `json:"attack_class"`
	Lifecycle   *string `json:"lifecycle,omitempty"`
}

// ExcludedBlock records a considered but unselected block with a source-grounded reason.
type ExcludedBlock struct {
	Block  string `json:"block"`
	Reason string `json:"reason"`
}

// LocalCheck records one source or bounded-local check inside a coverage unit.
type LocalCheck struct {
	AgentID       string   `json:"agent_id"`
	ReviewedPaths []string `json:"reviewed_paths"`
	Invariant     string   `json:"invariant"`
	Method        string   `json:"method"` // "source" | "local"
	Result        string   `json:"result"`
	Artifact      *string  `json:"artifact"`
}

// ArchivedAttempt stores an evidence-bearing attempt archived when a critic reopens a unit.
type ArchivedAttempt struct {
	Wave               int          `json:"wave"`
	Status             string       `json:"status"` // "covered" | "candidate" | "blocked"
	AgentID            *string      `json:"agent_id"`
	ReviewedPaths      []string     `json:"reviewed_paths"`
	LocalChecks        []LocalCheck `json:"local_checks"`
	ResultFingerprints []string     `json:"result_fingerprints"`
	Unresolved         []string     `json:"unresolved"`
	ReassignmentReason string       `json:"reassignment_reason"`
}

// CoverageUnit represents one entry in coverage-ledger.json.
type CoverageUnit struct {
	CoverageID               string            `json:"coverage_id"`
	CanonicalRefs            CanonicalRefs     `json:"canonical_refs"`
	Surface                  string            `json:"surface"`
	Boundary                 string            `json:"boundary"`
	Subsystem                string            `json:"subsystem"`
	AttackClass              string            `json:"attack_class"`
	Lifecycle                *string           `json:"lifecycle,omitempty"`
	StartingPaths            []string          `json:"starting_paths"`
	OrdinaryAttackClassBlock *string           `json:"ordinary_attack_class_block"`
	SelectedCompanionBlocks  []string          `json:"selected_companion_blocks"`
	ExcludedBlocks           []ExcludedBlock   `json:"excluded_blocks"`
	PriorStatus              string            `json:"prior_status"`
	Attempts                 []ArchivedAttempt `json:"attempts"`
	Wave                     int               `json:"wave"`
	Status                   string            `json:"status"`
	AgentID                  *string           `json:"agent_id"`
	ReviewedPaths            []string          `json:"reviewed_paths"`
	LocalChecks              []LocalCheck      `json:"local_checks"`
	ResultFingerprints       []string          `json:"result_fingerprints"`
	Unresolved               []string          `json:"unresolved"`
	Hardening                []string          `json:"hardening,omitempty"`
}

// TraceEntry represents one step in a finding's source trace.
type TraceEntry struct {
	Kind        string `json:"kind"` // "entrypoint" | "propagation" | "sink"
	File        string `json:"file"`
	Line        int    `json:"line"`
	Scope       string `json:"scope"`
	Description string `json:"description"`
}

// EvidenceEntry represents one supporting source citation.
type EvidenceEntry struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Description string `json:"description"`
}

// ConditionEntry represents a precondition required for a confirmed finding.
type ConditionEntry struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

// ExecutionBlock describes target-neutral bounded reproduction.
type ExecutionBlock struct {
	AttackerPerspective string   `json:"attacker_perspective"`
	Payloads            []string `json:"payloads"`
	Instructions        []string `json:"instructions"`
	ObservedResult      string   `json:"observed_result"`
}

// CodeChange represents a specific file change in remediation.
type CodeChange struct {
	FileName  string `json:"file_name"`
	FixedCode string `json:"fixed_code"`
}

// RemediationBlock describes the smallest effective source fix.
type RemediationBlock struct {
	Strategy    string       `json:"strategy"`
	CodeChanges []CodeChange `json:"code_changes,omitempty"`
}

// ScoreReason holds a score and its justification.
type ScoreReason struct {
	Score  string `json:"score"`
	Reason string `json:"reason"`
}

// SeverityBlock holds likelihood, impact, and overall severity for a confirmed finding.
type SeverityBlock struct {
	Likelihood      ScoreReason `json:"likelihood"`
	Impact          ScoreReason `json:"impact"`
	OverallSeverity string      `json:"overall_severity"`
}

// ValidationPlan holds local and/or deployment validation plans for a needs_validation record.
type ValidationPlan struct {
	Local      string `json:"local,omitempty"`
	Deployment string `json:"deployment,omitempty"`
}

// Finding represents a unified record in findings.json (confirmed, needs_validation, or rejected).
type Finding struct {
	Verdict           string           `json:"verdict"`
	Fingerprint       string           `json:"fingerprint"`
	Title             string           `json:"title"`
	Description       string           `json:"description"`
	RootCause         string           `json:"root_cause,omitempty"`
	ClaimedRootCause  string           `json:"claimed_root_cause,omitempty"`
	IntendedBehavior  string           `json:"intended_behavior,omitempty"`
	Trace             []TraceEntry     `json:"trace"`
	Evidence          []EvidenceEntry  `json:"evidence"`
	Conditions        []ConditionEntry `json:"conditions,omitempty"`
	Execution         *ExecutionBlock  `json:"execution,omitempty"`
	Remediation       *RemediationBlock `json:"remediation,omitempty"`
	Severity          *SeverityBlock   `json:"severity,omitempty"`
	Confidence        *ScoreReason     `json:"confidence,omitempty"`
	Blockers          []string         `json:"blockers,omitempty"`
	ValidationPlan    *ValidationPlan  `json:"validation_plan,omitempty"`
	Reason            string           `json:"reason,omitempty"`
}
