package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/spec"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

const stateFilename = ".sec-audit-state.json"

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
	sourceRef, dirty := resolveGitRef(absTarget)

	outputDir := req.OutputDir
	if outputDir == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			home = os.TempDir()
		}
		baseOut := filepath.Join(home, "security-audit-skill", repoName)
		outputDir = nextRunDir(baseOut)
	} else {
		absOut, err := filepath.Abs(outputDir)
		if err != nil {
			return nil, fmt.Errorf("resolve output_dir: %w", err)
		}
		outputDir = absOut
	}

	// Enforce target-containment safety rule from SKILL.md:
	// "Use a directory inside the target only when the user explicitly selects it and the parent
	// verifies that version control ignores the whole directory. Otherwise stop and request an external path."
	if isSubpath(absTarget, outputDir) {
		if !isGitIgnored(absTarget, outputDir) {
			return nil, fmt.Errorf("output_dir %q is inside target %q and is not ignored by version control; choose an external path or add it to .gitignore", outputDir, absTarget)
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

	brief := scanRepository(absTarget)
	var companionNames []string
	for _, rc := range brief.RecommendedCompanions {
		companionNames = append(companionNames, rc.File)
	}

	// Strict pre-reconnaissance budget gate from SKILL.md:
	// "Reserve the four baseline reconnaissance calls, one final post-wave critic for quick or one
	// post-wave plus one distinct final-clean critic for standard/deep, and at least one verifier call."
	runStatus := "in_progress"
	incompleteReason := ""
	if req.Budget != nil {
		minRequired := 4 + 1 + 1 // 4 recon + 1 post-wave critic + 1 verifier = 6 for quick
		if profile == "standard" || profile == "deep" {
			minRequired = 4 + 2 + 1 // 4 recon + 2 critics + 1 verifier = 7 for standard/deep
		}
		//Also need at least 1 hunter to do a pass? Note SKILL.md says:
		// "Reserve the four baseline reconnaissance calls, one final post-wave critic for quick or one post-wave plus one distinct final-clean critic for standard/deep, and at least one verifier call."
		if *req.Budget < minRequired {
			runStatus = "incomplete"
			incompleteReason = "budget_cannot_fund_reconnaissance_and_reserves"
		}
	}

	priorPaths := req.PriorRunDirs
	if priorPaths == nil {
		priorPaths = []string{}
	}
	carryovers, carriedCandidates := evaluatePriorRuns(absTarget, priorPaths)

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

	if err := saveMetadata(outputDir, &meta); err != nil {
		return nil, err
	}

	emptyLedger := []validator.CoverageUnit{}
	if err := saveLedger(outputDir, emptyLedger); err != nil {
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
	if err := saveState(outputDir, state); err != nil {
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
	trimmed := strings.TrimSpace(content)
	if !validator.HasVisibleProse(trimmed) {
		return nil, fmt.Errorf("architecture.md content must contain visible prose")
	}
	words := len(strings.Fields(trimmed))
	if words > 1100 {
		return nil, fmt.Errorf("architecture.md exceeds hard cap (~1,000 words): got %d words", words)
	}
	archPath := filepath.Join(outputDir, "architecture.md")
	if err := os.WriteFile(archPath, []byte(trimmed+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write architecture.md: %w", err)
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

	units := make([]validator.CoverageUnit, 0, len(inputs))
	for i, in := range inputs {
		refs := in.CanonicalRefs
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
		var unresolved []string
		// Check if scoped run excludes this unit's starting_paths
		if len(meta.ScopePaths) > 0 && !anyPathInScope(in.StartingPaths, meta.ScopePaths) {
			status = "out_of_scope"
			unresolved = []string{"outside_requested_scope_paths"}
		} else {
			unresolved = []string{}
		}

		selectedCompanions := cat.ExpandCompanionBlocks(in.SelectedCompanionBlocks)
		if selectedCompanions == nil {
			selectedCompanions = []string{}
		}
		excluded := in.ExcludedBlocks
		if excluded == nil {
			excluded = []validator.ExcludedBlock{}
		}

		u := validator.CoverageUnit{
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
			ExcludedBlocks:           excluded,
			PriorStatus:              priorStatus,
			Attempts:                 []validator.ArchivedAttempt{},
			Wave:                     1,
			Status:                   status,
			AgentID:                  nil,
			ReviewedPaths:            []string{},
			LocalChecks:              []validator.LocalCheck{},
			ResultFingerprints:       []string{},
			Unresolved:               unresolved,
		}
		units = append(units, u)
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

	if err := saveLedger(outputDir, units); err != nil {
		return nil, err
	}
	return units, nil
}

func anyPathInScope(paths, scopePaths []string) bool {
	for _, p := range paths {
		for _, sp := range scopePaths {
			if p == sp || strings.HasPrefix(p, strings.TrimSuffix(sp, "/")+"/") || strings.HasPrefix(sp, strings.TrimSuffix(p, "/")+"/") {
				return true
			}
		}
	}
	return false
}

func resolveGitRef(targetDir string) (string, bool) {
	cmd := exec.Command("git", "-C", targetDir, "rev-parse", "HEAD")
	out, err := cmd.Output()
	ref := "unversioned"
	if err == nil {
		ref = strings.TrimSpace(string(out))
	}
	statusCmd := exec.Command("git", "-C", targetDir, "status", "--porcelain")
	stOut, stErr := statusCmd.Output()
	dirty := stErr == nil && len(strings.TrimSpace(string(stOut))) > 0
	return ref, dirty
}

func isSubpath(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func isGitIgnored(targetDir, checkPath string) bool {
	cmd := exec.Command("git", "-C", targetDir, "check-ignore", "-q", checkPath)
	return cmd.Run() == nil
}

func nextRunDir(baseOut string) string {
	for n := 1; n < 10000; n++ {
		candidate := filepath.Join(baseOut, fmt.Sprintf("run-%d", n))
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
	return filepath.Join(baseOut, "run-latest")
}

func scanRepository(targetDir string) RepoBrief {
	brief := RepoBrief{
		Languages:               make(map[string]int),
		Manifests:               []string{},
		EntrypointCandidates:    []string{},
		AuthBoundaryCandidates:  []string{},
		RecommendedCompanions:   []CompanionRecommendation{},
		SuggestedSeedSubsystems: []string{},
	}

	subsystems := make(map[string]bool)
	var nativeFiles, aiFiles, webFiles, clientFiles, ciFiles, cloudFiles, rpcFiles, dataFiles, ipcFiles []string

	_ = filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" || name == "node_modules" || name == "vendor" || name == ".venv" || name == "dist" || name == "build" || name == "target" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(targetDir, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		brief.TotalFiles++

		parts := strings.Split(rel, "/")
		if len(parts) > 1 {
			subsystems[parts[0]] = true
		} else {
			subsystems["."] = true
		}

		ext := strings.ToLower(filepath.Ext(name))
		switch ext {
		case ".go":
			brief.Languages["go"]++
		case ".py":
			brief.Languages["python"]++
		case ".ts", ".tsx":
			brief.Languages["typescript"]++
		case ".js", ".jsx", ".cjs", ".mjs":
			brief.Languages["javascript"]++
		case ".rs":
			brief.Languages["rust"]++
		case ".c", ".cc", ".cpp", ".h", ".hpp":
			brief.Languages["c_cpp"]++
			nativeFiles = appendCap(nativeFiles, rel, 5)
		case ".java", ".kt":
			brief.Languages["jvm"]++
		case ".proto", ".capnp", ".thrift", ".graphql":
			brief.Languages["idl"]++
			rpcFiles = appendCap(rpcFiles, rel, 5)
		case ".tf", ".hcl":
			brief.Languages["terraform"]++
			cloudFiles = appendCap(cloudFiles, rel, 5)
		}

		lowerRel := strings.ToLower(rel)
		switch name {
		case "go.mod", "package.json", "pyproject.toml", "Cargo.toml", "requirements.txt", "pom.xml", "Dockerfile", "docker-compose.yml":
			brief.Manifests = appendCap(brief.Manifests, rel, 25)
		}

		if strings.Contains(lowerRel, ".github/workflows/") || strings.Contains(lowerRel, ".gitlab-ci") || name == "goreleaser.yml" || name == ".goreleaser.yaml" {
			ciFiles = appendCap(ciFiles, rel, 5)
		}
		if name == "Dockerfile" || strings.Contains(lowerRel, "k8s/") || strings.Contains(lowerRel, "helm/") || strings.Contains(lowerRel, "Wrangler") || name == "wrangler.toml" {
			cloudFiles = appendCap(cloudFiles, rel, 5)
		}
		if strings.Contains(lowerRel, "router") || strings.Contains(lowerRel, "handler") || strings.Contains(lowerRel, "server") || strings.Contains(lowerRel, "api") || strings.Contains(lowerRel, "cmd/") || strings.Contains(lowerRel, "main.") {
			brief.EntrypointCandidates = appendCap(brief.EntrypointCandidates, rel, 20)
		}
		if strings.Contains(lowerRel, "auth") || strings.Contains(lowerRel, "jwt") || strings.Contains(lowerRel, "oauth") || strings.Contains(lowerRel, "session") || strings.Contains(lowerRel, "middleware") || strings.Contains(lowerRel, "rbac") || strings.Contains(lowerRel, "acl") || strings.Contains(lowerRel, "policy") {
			brief.AuthBoundaryCandidates = appendCap(brief.AuthBoundaryCandidates, rel, 20)
			webFiles = appendCap(webFiles, rel, 5)
		}
		if strings.Contains(lowerRel, "mcp") || strings.Contains(lowerRel, "prompt") || strings.Contains(lowerRel, "llm") || strings.Contains(lowerRel, "agent") || strings.Contains(lowerRel, "openai") || strings.Contains(lowerRel, "rag") {
			aiFiles = appendCap(aiFiles, rel, 5)
		}
		if ext == ".tsx" || ext == ".jsx" || strings.Contains(lowerRel, "webview") || strings.Contains(lowerRel, "service-worker") {
			clientFiles = appendCap(clientFiles, rel, 5)
		}
		if strings.Contains(lowerRel, "grpc") || strings.Contains(lowerRel, "rpc") || strings.Contains(lowerRel, "webhook") || strings.Contains(lowerRel, "queue") || strings.Contains(lowerRel, "broker") {
			rpcFiles = appendCap(rpcFiles, rel, 5)
		}
		if strings.Contains(lowerRel, "tenant") || strings.Contains(lowerRel, "export") || strings.Contains(lowerRel, "backup") || strings.Contains(lowerRel, "migration") || strings.Contains(lowerRel, "store") || strings.Contains(lowerRel, "db") {
			dataFiles = appendCap(dataFiles, rel, 5)
		}
		if strings.Contains(lowerRel, "ipc") || strings.Contains(lowerRel, "socket") || strings.Contains(lowerRel, "daemon") || strings.Contains(lowerRel, "unix") {
			ipcFiles = appendCap(ipcFiles, rel, 5)
		}
		return nil
	})

	for sub := range subsystems {
		brief.SuggestedSeedSubsystems = append(brief.SuggestedSeedSubsystems, sub)
	}
	sort.Strings(brief.SuggestedSeedSubsystems)

	addRec := func(file, reason string, ev []string) {
		if len(ev) > 0 {
			brief.RecommendedCompanions = append(brief.RecommendedCompanions, CompanionRecommendation{
				File:     file,
				Reason:   reason,
				Evidence: ev,
			})
		}
	}
	addRec("MEMORY-SAFETY-AND-BINARY.md", "Native/C/C++ or low-level binary paths detected", nativeFiles)
	addRec("AI-AND-LLM.md", "LLM, prompt, agent, or MCP server/client paths detected", aiFiles)
	addRec("WEB-PROTOCOL-AND-AUTH.md", "HTTP, session, authentication, or authorization boundary files detected", webFiles)
	addRec("CLIENT-SIDE.md", "Browser/UI/DOM or frontend component files detected", clientFiles)
	addRec("SUPPLY-CHAIN-AND-RELEASE.md", "CI/CD workflow or release automation files detected", ciFiles)
	addRec("CLOUD-AND-DEPLOYMENT.md", "Container, IaC, Kubernetes, or edge deployment manifests detected", cloudFiles)
	addRec("PROTOCOLS-RPC-AND-MESSAGING.md", "RPC, IDL, webhook, or message queue paths detected", rpcFiles)
	addRec("DATA-ISOLATION-AND-LIFECYCLE.md", "Storage, tenant, migration, or export/backup paths detected", dataFiles)
	addRec("DESKTOP-MOBILE-AND-LOCAL-IPC.md", "Local IPC, daemon, or socket paths detected", ipcFiles)

	return brief
}

func appendCap(slice []string, val string, max int) []string {
	if len(slice) >= max {
		return slice
	}
	return append(slice, val)
}

func evaluatePriorRuns(targetDir string, priorDirs []string) ([]PriorCarryover, map[string]*CandidateEnvelope) {
	var carryovers []PriorCarryover
	carried := make(map[string]*CandidateEnvelope)

	for _, pdir := range priorDirs {
		findingsPath := filepath.Join(pdir, "findings.json")
		raw, err := os.ReadFile(findingsPath)
		if err != nil {
			continue
		}
		var findings []validator.Finding
		var rawList []map[string]any
		if json.Unmarshal(raw, &findings) != nil || json.Unmarshal(raw, &rawList) != nil {
			continue
		}
		co := PriorCarryover{
			PriorRunDir:            pdir,
			CarriedConfirmed:       []string{},
			ChangedConfirmed:       []string{},
			CarriedNeedsValidation: []string{},
			SuppressedRejected:     []string{},
		}
		for idx, f := range findings {
			allExistAndValid := true
			for _, t := range f.Trace {
				if validator.VerifyRepoFileAndLine(targetDir, t.File, t.Line) != nil {
					allExistAndValid = false
					break
				}
			}
			for _, ev := range f.Evidence {
				if validator.VerifyRepoFileAndLine(targetDir, ev.File, ev.Line) != nil {
					allExistAndValid = false
					break
				}
			}
			switch f.Verdict {
			case "confirmed":
				if allExistAndValid {
					co.CarriedConfirmed = append(co.CarriedConfirmed, f.Fingerprint)
					fCopy := f
					var rMap map[string]any
					if idx < len(rawList) {
						rMap = rawList[idx]
					}
					carried[f.Fingerprint] = &CandidateEnvelope{
						Fingerprint:     f.Fingerprint,
						HunterID:        "prior-run-carryover",
						ProposedVerdict: "confirmed",
						CandidateRecord: fCopy,
						CandidateRaw:    rMap,
					}
				} else {
					co.ChangedConfirmed = append(co.ChangedConfirmed, f.Fingerprint)
				}
			case "needs_validation":
				if allExistAndValid {
					co.CarriedNeedsValidation = append(co.CarriedNeedsValidation, f.Fingerprint)
					fCopy := f
					var rMap map[string]any
					if idx < len(rawList) {
						rMap = rawList[idx]
					}
					carried[f.Fingerprint] = &CandidateEnvelope{
						Fingerprint:     f.Fingerprint,
						HunterID:        "prior-run-carryover",
						ProposedVerdict: "needs_validation",
						CandidateRecord: fCopy,
						CandidateRaw:    rMap,
					}
				}
			case "rejected":
				if allExistAndValid {
					co.SuppressedRejected = append(co.SuppressedRejected, f.Fingerprint)
				}
			}
		}
		carryovers = append(carryovers, co)
	}
	return carryovers, carried
}

// FileHashSHA256 returns the hex SHA-256 of a file for deterministic comparisons.
func FileHashSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func saveMetadata(outputDir string, meta *RunMetadata) error {
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "run-metadata.json"), append(b, '\n'), 0o600)
}

func loadMetadata(outputDir string) (*RunMetadata, error) {
	b, err := os.ReadFile(filepath.Join(outputDir, "run-metadata.json"))
	if err != nil {
		return nil, fmt.Errorf("read run-metadata.json: %w", err)
	}
	var m RunMetadata
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse run-metadata.json: %w", err)
	}
	return &m, nil
}

func saveLedger(outputDir string, units []validator.CoverageUnit) error {
	b, err := json.MarshalIndent(units, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "coverage-ledger.json"), append(b, '\n'), 0o600)
}

func loadLedger(outputDir string) ([]validator.CoverageUnit, error) {
	b, err := os.ReadFile(filepath.Join(outputDir, "coverage-ledger.json"))
	if err != nil {
		return nil, fmt.Errorf("read coverage-ledger.json: %w", err)
	}
	var units []validator.CoverageUnit
	if err := json.Unmarshal(b, &units); err != nil {
		return nil, fmt.Errorf("parse coverage-ledger.json: %w", err)
	}
	return units, nil
}

func saveFindings(outputDir string, findings []validator.Finding) error {
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
	b, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "findings.json"), append(b, '\n'), 0o600)
}

func loadFindings(outputDir string) ([]validator.Finding, error) {
	p := filepath.Join(outputDir, "findings.json")
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return []validator.Finding{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read findings.json: %w", err)
	}
	var findings []validator.Finding
	if err := json.Unmarshal(b, &findings); err != nil {
		return nil, fmt.Errorf("parse findings.json: %w", err)
	}
	return findings, nil
}

func saveState(outputDir string, st *InternalState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, stateFilename), append(b, '\n'), 0o600)
}

func loadState(outputDir string) (*InternalState, error) {
	b, err := os.ReadFile(filepath.Join(outputDir, stateFilename))
	if err != nil {
		return nil, fmt.Errorf("read internal state: %w", err)
	}
	var st InternalState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("parse internal state: %w", err)
	}
	if st.Agents == nil {
		st.Agents = make(map[string]*AgentAssignment)
	}
	if st.Candidates == nil {
		st.Candidates = make(map[string]*CandidateEnvelope)
	}
	return &st, nil
}
