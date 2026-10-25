package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/scanner"
	"github.com/fabriziosalmi/security-audit-cli/internal/spec"
	"github.com/fabriziosalmi/security-audit-cli/internal/store"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// Init initializes an audit run directory, enforces the strict pre-reconnaissance budget gate,
// scans the target repository deterministically, and processes prior-run ledgers/findings.
func Init(req InitRequest) (*InitResponse, error) {
	if req.Target == "" {
		return nil, fmt.Errorf("target repository path is required")
	}
	absTarget, err := filepath.Abs(req.Target)
	if err != nil {
		return nil, fmt.Errorf("resolve target path: %w", err)
	}
	st, err := os.Stat(absTarget)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("target %q must be an existing directory", absTarget)
	}

	profile := req.Profile
	if profile == "" {
		profile = "standard"
	}
	if profile != "quick" && profile != "standard" && profile != "deep" {
		return nil, fmt.Errorf("invalid profile %q (expected quick, standard, or deep)", profile)
	}

	repoName := filepath.Base(absTarget)
	sourceRef, dirty := scanner.ResolveGitRef(absTarget)

	outputDir := req.OutputDir
	if outputDir == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			home = os.TempDir()
		}
		baseOut := filepath.Join(home, "security-audit-skill", repoName)
		outputDir = scanner.NextRunDir(baseOut)
	} else {
		absOut, err := filepath.Abs(outputDir)
		if err != nil {
			return nil, fmt.Errorf("resolve output_dir: %w", err)
		}
		outputDir = absOut
	}

	// Enforce target-containment safety rule from SKILL.md
	if scanner.IsSubpath(absTarget, outputDir) {
		if !scanner.IsGitIgnored(absTarget, outputDir) {
			return nil, fmt.Errorf(
				"output_dir %q is inside target %q and is not ignored by version control; "+
					"choose an external path or add it to .gitignore",
				outputDir, absTarget,
			)
		}
	}

	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return nil, fmt.Errorf("create output_dir: %w", err)
	}

	scopePaths := req.ScopePaths
	if scopePaths == nil {
		scopePaths = []string{}
	}
	for _, sp := range scopePaths {
		if err := validator.VerifyRepoFileAndLine(absTarget, sp, 0); err != nil {
			return nil, fmt.Errorf("invalid scope_path %q: %w", sp, err)
		}
	}

	brief := scanner.ScanRepository(absTarget)
	var companionNames []string
	if len(req.Companions) > 0 {
		cat, err := spec.LoadCatalog()
		if err != nil {
			return nil, err
		}
		for _, c := range req.Companions {
			if c == "none" {
				companionNames = []string{}
				break
			}
			if _, ok := cat.Files[c]; !ok {
				return nil, fmt.Errorf("unknown companion file %q in companions override", c)
			}
			companionNames = append(companionNames, c)
		}
	} else {
		for _, rc := range brief.RecommendedCompanions {
			companionNames = append(companionNames, rc.File)
		}
	}
	if companionNames == nil {
		companionNames = []string{}
	}

	// Strict pre-reconnaissance budget gate from SKILL.md
	runStatus := "in_progress"
	incompleteReason := ""
	if req.Budget != nil {
		minRequired := 4 + 1 + 1 // 4 recon + 1 post-wave critic + 1 verifier = 6 for quick
		if profile == "standard" || profile == "deep" {
			minRequired = 4 + 2 + 1 // 4 recon + 2 critics + 1 verifier = 7 for standard/deep
		}
		if *req.Budget < minRequired {
			runStatus = "incomplete"
			incompleteReason = "budget_cannot_fund_reconnaissance_and_reserves"
		}
	}

	priorPaths := req.PriorRunDirs
	if priorPaths == nil {
		priorPaths = []string{}
	}
	carryovers, carriedCandidates := scanner.EvaluatePriorRuns(absTarget, priorPaths)

	meta := RunMetadata{
		RunID:                  filepath.Base(outputDir),
		Repo:                   repoName,
		Target:                 absTarget,
		SourceRef:              sourceRef,
		DirtyWorktree:          dirty,
		Profile:                profile,
		ScopePaths:             scopePaths,
		Budget:                 req.Budget,
		AgentsSpent:            0,
		ExecutionPolicy:        "sandboxed-source-and-local-only",
		SelectedCompanionFiles: companionNames,
		PriorRunPaths:          priorPaths,
		SharedFileOwners: map[string]string{
			"run-metadata.json":    "parent",
			"architecture.md":      "parent",
			"coverage-ledger.json": "parent",
			"findings.json":        "parent",
			"REPORT.md":            "parent",
			"FINDINGS-DETAIL.md":   "parent",
			"NEEDS-VALIDATION.md":  "parent",
		},
		RunStatus:        runStatus,
		IncompleteReason: incompleteReason,
	}

	rs := store.New(outputDir)
	if err := rs.SaveMetadata(&meta); err != nil {
		return nil, err
	}
	if err := rs.SaveLedger([]validator.CoverageUnit{}); err != nil {
		return nil, err
	}

	state := &InternalState{
		CurrentWave:     1,
		Agents:          make(map[string]*AgentAssignment),
		Candidates:      carriedCandidates,
		HardeningNotes:  []string{},
		UncoveredQueue:  []UncoveredEntry{},
		PriorCarryovers: carryovers,
	}
	if err := rs.SaveState(state); err != nil {
		return nil, err
	}

	return &InitResponse{
		OutputDir:       outputDir,
		Metadata:        meta,
		RepoBrief:       brief,
		PriorCarryovers: carryovers,
	}, nil
}

// CatalogQuery lists companion files or returns a specific block's verbatim content.
func CatalogQuery(file, blockRef string) (any, error) {
	cat, err := spec.LoadCatalog()
	if err != nil {
		return nil, err
	}
	if blockRef != "" {
		b, ok := cat.Blocks[blockRef]
		if !ok {
			return nil, fmt.Errorf("unknown block reference %q", blockRef)
		}
		return b, nil
	}
	if file != "" {
		cf, ok := cat.Files[file]
		if !ok {
			return nil, fmt.Errorf("unknown companion file %q", file)
		}
		return cf, nil
	}
	var list []*spec.CompanionFile
	for _, f := range cat.FileOrder {
		list = append(list, cat.Files[f])
	}
	return list, nil
}

// WriteArchitecture validates and writes <output-dir>/architecture.md, enforcing the ~1,000 word cap.
func WriteArchitecture(outputDir, content string) (map[string]any, error) {
	archPath, words, err := store.New(outputDir).SaveArchitecture(content)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"path":       archPath,
		"word_count": words,
		"status":     "ok",
	}, nil
}

// SeedLedger deterministically derives coverage_ids, verifies starting_paths on disk and block refs against the catalog,
// sorts units lexicographically, validates the ledger, and writes <output-dir>/coverage-ledger.json.
func SeedLedger(outputDir string, inputs []SeedUnitInput) ([]validator.CoverageUnit, error) {
	return SeedLedgerWithOptions(outputDir, inputs, false)
}

// SeedLedgerWithOptions extends SeedLedger with optional SHA-256 verified carryover of clean units from prior runs.
func SeedLedgerWithOptions(outputDir string, inputs []SeedUnitInput, carryoverUnchanged bool) ([]validator.CoverageUnit, error) {
	rs := store.New(outputDir)
	meta, err := rs.LoadMetadata()
	if err != nil {
		return nil, err
	}
	state, err := rs.LoadState()
	if err != nil {
		return nil, err
	}
	cat, err := spec.LoadCatalog()
	if err != nil {
		return nil, err
	}
	validBlocks := cat.ValidBlockMap()
	selectedFileSet := make(map[string]bool, len(meta.SelectedCompanionFiles))
	for _, f := range meta.SelectedCompanionFiles {
		selectedFileSet[f] = true
	}

	var priorClean map[string]validator.CoverageUnit
	if len(meta.PriorRunPaths) > 0 {
		priorClean = scanner.LoadPriorCleanUnits(meta.Target, meta.PriorRunPaths)
	}

	units := make([]validator.CoverageUnit, 0, len(inputs))
	for i, in := range inputs {
		for _, blk := range in.SelectedCompanionBlocks {
			if parts := strings.SplitN(blk, "#", 2); len(parts) == 2 && parts[0] != "ATTACK-CLASSES.md" {
				if len(selectedFileSet) > 0 && !selectedFileSet[parts[0]] {
					return nil, fmt.Errorf("unit[%d] selected_companion_block %q belongs to %q which is not in selected_companion_files %v", i, blk, parts[0], meta.SelectedCompanionFiles)
				}
			}
		}
		refs := in.CanonicalRefs
		if refs.Surface == "" && in.Surface != "" {
			refs.Surface = in.Surface
		}
		if refs.Boundary == "" && in.Boundary != "" {
			refs.Boundary = in.Boundary
		}
		if refs.Subsystem == "" && in.Subsystem != "" {
			refs.Subsystem = in.Subsystem
		}
		if refs.AttackClass == "" && in.AttackClass != "" {
			refs.AttackClass = in.AttackClass
		}
		if meta.Profile == "quick" {
			refs.Subsystem = "profile/quick/all-in-scope-subsystems"
		}
		if in.Lifecycle != nil && refs.Lifecycle == nil {
			refs.Lifecycle = in.Lifecycle
		}
		cid, err := validator.DeriveCoverageID(refs)
		if err != nil {
			return nil, fmt.Errorf("unit[%d] canonical_refs error: %w", i, err)
		}

		priorStatus := in.PriorStatus
		if priorStatus == "" {
			if len(meta.PriorRunPaths) > 0 {
				priorStatus = "new"
			} else {
				priorStatus = "none"
			}
		}

		status := "planned"
		var agentID *string
		reviewedPaths := []string{}
		localChecks := []validator.LocalCheck{}
		var unresolved []string
		if len(meta.ScopePaths) > 0 && !scanner.AnyPathInScope(in.StartingPaths, meta.ScopePaths) {
			status = "out_of_scope"
			unresolved = []string{"outside_requested_scope_paths"}
		} else if (carryoverUnchanged || in.PriorStatus == "prior_covered_same_source") && priorClean != nil {
			if pu, ok := priorClean[cid]; ok {
				priorStatus = "prior_covered_same_source"
				status = "covered"
				aid := *pu.AgentID
				agentID = &aid
				reviewedPaths = append(reviewedPaths, pu.ReviewedPaths...)
				for _, lc := range pu.LocalChecks {
					if lc.Method == "local" {
						lc.Method = "source"
						lc.Artifact = nil
					}
					localChecks = append(localChecks, lc)
				}
				unresolved = []string{}
				pinPaths := append(append([]string{}, in.StartingPaths...), pu.ReviewedPaths...)
				if err := scanner.VerifyAndPinSourceFiles(meta.Target, state, pinPaths); err != nil {
					return nil, err
				}
			} else {
				unresolved = []string{}
			}
		} else {
			unresolved = []string{}
		}

		selectedCompanions := cat.ExpandCompanionBlocks(in.SelectedCompanionBlocks)
		if selectedCompanions == nil {
			selectedCompanions = []string{}
		}

		units = append(units, validator.CoverageUnit{
			CoverageID:               cid,
			CanonicalRefs:            refs,
			Surface:                  in.Surface,
			Boundary:                 in.Boundary,
			Subsystem:                in.Subsystem,
			AttackClass:              in.AttackClass,
			Lifecycle:                in.Lifecycle,
			StartingPaths:            in.StartingPaths,
			OrdinaryAttackClassBlock: in.OrdinaryAttackClassBlock,
			SelectedCompanionBlocks:  selectedCompanions,
			ExcludedBlocks:           nonNilExcluded(in.ExcludedBlocks),
			PriorStatus:              priorStatus,
			Attempts:                 []validator.ArchivedAttempt{},
			Wave:                     1,
			Status:                   status,
			AgentID:                  agentID,
			ReviewedPaths:            reviewedPaths,
			LocalChecks:              localChecks,
			ResultFingerprints:       []string{},
			Unresolved:               unresolved,
		})
	}

	sort.Slice(units, func(i, j int) bool {
		return units[i].CoverageID < units[j].CoverageID
	})

	rawBytes, err := json.MarshalIndent(units, "", "  ")
	if err != nil {
		return nil, err
	}
	errs := validator.ValidateCoverageLedgerBytes(rawBytes, meta.Target, outputDir, validBlocks)
	if len(errs) > 0 {
		return nil, fmt.Errorf("coverage-ledger validation failed (%d errors): %s", len(errs), strings.Join(errs, "; "))
	}

	if err := rs.SaveLedger(units); err != nil {
		return nil, err
	}
	if err := rs.SaveState(state); err != nil {
		return nil, err
	}
	return units, nil
}

// FileHashSHA256 delegates to scanner.FileHashSHA256 for deterministic file digest comparison.
func FileHashSHA256(path string) (string, error) {
	return scanner.FileHashSHA256(path)
}
