package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

const StateFilename = ".sec-audit-state.json"

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
	Fingerprint       string             `json:"fingerprint"`
	HunterID          string             `json:"hunter_id"`
	ProposedVerdict   string             `json:"proposed_verdict"` // "confirmed" | "needs_validation"
	CandidateRecord   validator.Finding  `json:"candidate_record"`
	CandidateRaw      map[string]any     `json:"candidate_raw"`
	LinkedUnits       []string           `json:"linked_units"`
	Phase3VerifierID  string             `json:"phase3_verifier_id,omitempty"`
	Phase3Decision    string             `json:"phase3_decision,omitempty"` // "confirmed" | "needs_validation" | "rejected"
	FinalRecord       *validator.Finding `json:"final_record,omitempty"`
	FinalRaw          map[string]any     `json:"final_raw,omitempty"`
	Phase5VerifierIDs []string           `json:"phase5_verifier_ids,omitempty"`
	Phase5Verified    bool               `json:"phase5_verified"`
	NeedsFreshVerify  bool               `json:"needs_fresh_verify"`
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
	PriorRunDir            string   `json:"prior_run_dir"`
	CarriedConfirmed       []string `json:"carried_confirmed_fingerprints"`
	ChangedConfirmed       []string `json:"changed_confirmed_fingerprints"`
	CarriedNeedsValidation []string `json:"carried_needs_validation_fingerprints"`
	SuppressedRejected     []string `json:"suppressed_rejected_fingerprints"`
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

// InternalState persists parent-side orchestration state in <output-dir>/.sec-audit-state.json.
type InternalState struct {
	CurrentWave        int                           `json:"current_wave"`
	PostWaveCriticDone bool                          `json:"post_wave_critic_done"`
	FinalCleanDone     bool                          `json:"final_clean_done"`
	Agents             map[string]*AgentAssignment   `json:"agents"`
	Candidates         map[string]*CandidateEnvelope `json:"candidates"`
	HardeningNotes     []string                      `json:"hardening_notes"`
	UncoveredQueue     []UncoveredEntry              `json:"uncovered_queue"`
	PriorCarryovers    []PriorCarryover              `json:"prior_carryovers"`
}

// RunStore provides crash-safe atomic persistence for all parent-owned files in an audit run directory.
type RunStore struct {
	OutputDir string
}

// New creates a RunStore bound to outputDir.
func New(outputDir string) *RunStore {
	return &RunStore{OutputDir: outputDir}
}

// WriteFileAtomic writes data to a temporary file in the same directory, fsyncs, sets permissions, and atomically renames it.
func WriteFileAtomic(targetPath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	tmp, err := os.CreateTemp(dir, ".sec-audit-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, targetPath); err != nil {
		cleanup()
		return fmt.Errorf("atomic rename to %s: %w", targetPath, err)
	}
	return nil
}

// WriteJSONAtomic marshals v with 2-space indentation and trailing newline and writes it atomically.
func WriteJSONAtomic(targetPath string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(targetPath, append(b, '\n'), 0o600)
}

func (s *RunStore) MetadataPath() string     { return filepath.Join(s.OutputDir, "run-metadata.json") }
func (s *RunStore) LedgerPath() string       { return filepath.Join(s.OutputDir, "coverage-ledger.json") }
func (s *RunStore) FindingsPath() string     { return filepath.Join(s.OutputDir, "findings.json") }
func (s *RunStore) StatePath() string        { return filepath.Join(s.OutputDir, StateFilename) }
func (s *RunStore) ArchitecturePath() string { return filepath.Join(s.OutputDir, "architecture.md") }

// ReadJSON reads a regular file without following symlinks, runs single-pass JSON preflight, and unmarshals into dst.
func ReadJSON(path string, dst any) error {
	b, err := validator.ReadFileNoFollow(path)
	if err != nil {
		return err
	}
	if err := validator.ValidateJSONPreflight(b); err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func (s *RunStore) SaveMetadata(meta *RunMetadata) error {
	return WriteJSONAtomic(s.MetadataPath(), meta)
}

func (s *RunStore) LoadMetadata() (*RunMetadata, error) {
	var m RunMetadata
	if err := ReadJSON(s.MetadataPath(), &m); err != nil {
		return nil, fmt.Errorf("read run-metadata.json: %w", err)
	}
	return &m, nil
}

func (s *RunStore) SaveLedger(units []validator.CoverageUnit) error {
	return WriteJSONAtomic(s.LedgerPath(), units)
}

func (s *RunStore) LoadLedger() ([]validator.CoverageUnit, error) {
	var units []validator.CoverageUnit
	if err := ReadJSON(s.LedgerPath(), &units); err != nil {
		return nil, fmt.Errorf("read coverage-ledger.json: %w", err)
	}
	return units, nil
}

func (s *RunStore) SaveFindings(findings []validator.Finding) error {
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
	return WriteJSONAtomic(s.FindingsPath(), findings)
}

func (s *RunStore) LoadFindings() ([]validator.Finding, error) {
	if _, err := os.Lstat(s.FindingsPath()); os.IsNotExist(err) {
		return []validator.Finding{}, nil
	}
	var findings []validator.Finding
	if err := ReadJSON(s.FindingsPath(), &findings); err != nil {
		return nil, fmt.Errorf("read findings.json: %w", err)
	}
	return findings, nil
}

func (s *RunStore) SaveState(st *InternalState) error {
	return WriteJSONAtomic(s.StatePath(), st)
}

func (s *RunStore) LoadState() (*InternalState, error) {
	var st InternalState
	if err := ReadJSON(s.StatePath(), &st); err != nil {
		return nil, fmt.Errorf("read internal state: %w", err)
	}
	if st.Agents == nil {
		st.Agents = make(map[string]*AgentAssignment)
	}
	if st.Candidates == nil {
		st.Candidates = make(map[string]*CandidateEnvelope)
	}
	return &st, nil
}

// SaveArchitecture validates the ~1,000 word cap and atomically writes <output-dir>/architecture.md.
func (s *RunStore) SaveArchitecture(content string) (string, int, error) {
	trimmed := strings.TrimSpace(content)
	if !validator.HasVisibleProse(trimmed) {
		return "", 0, fmt.Errorf("architecture.md content must contain visible prose")
	}
	words := len(strings.Fields(trimmed))
	if words > 1100 {
		return "", words, fmt.Errorf("architecture.md exceeds hard cap (~1,000 words): got %d words", words)
	}
	archPath := s.ArchitecturePath()
	if err := WriteFileAtomic(archPath, []byte(trimmed+"\n"), 0o600); err != nil {
		return "", words, fmt.Errorf("write architecture.md: %w", err)
	}
	return archPath, words, nil
}

func (s *RunStore) LoadArchitecture() ([]byte, error) {
	b, err := validator.ReadFileNoFollow(s.ArchitecturePath())
	if err != nil {
		return nil, fmt.Errorf("architecture.md must be written before assigning agents: %w", err)
	}
	return b, nil
}

// SyncFindings writes sorted findings.json from state.Candidates and validates the resulting file on disk.
func (s *RunStore) SyncFindings(targetDir string, state *InternalState) error {
	var findings []validator.Finding
	for _, env := range state.Candidates {
		if env.FinalRecord != nil {
			findings = append(findings, *env.FinalRecord)
		}
	}
	if err := s.SaveFindings(findings); err != nil {
		return err
	}
	rawBytes, err := validator.ReadFileNoFollow(s.FindingsPath())
	if err != nil {
		return err
	}
	errs := validator.ValidateFindingsBytes(rawBytes, targetDir)
	if len(errs) > 0 {
		return fmt.Errorf("findings.json failed validation: %s", strings.Join(errs, "; "))
	}
	return nil
}
