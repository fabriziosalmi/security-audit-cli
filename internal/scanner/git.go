package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/store"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// ResolveGitRef returns the HEAD commit hash (or "unversioned") and whether the worktree is dirty.
func ResolveGitRef(targetDir string) (string, bool) {
	if _, err := os.Stat(filepath.Join(targetDir, ".git")); err != nil {
		return "unversioned", false
	}
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

// resolvePathSymlinks resolves existing ancestor symlinks while preserving any non-existent trailing path components.
func resolvePathSymlinks(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	curr := abs
	var tail []string
	for {
		resolved, rerr := filepath.EvalSymlinks(curr)
		if rerr == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return filepath.Clean(resolved)
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			return filepath.Clean(abs)
		}
		tail = append(tail, filepath.Base(curr))
		curr = parent
	}
}

// IsSubpath reports whether child is inside or equal to parent after resolving symlinks on existing path prefixes.
func IsSubpath(parent, child string) bool {
	realParent := resolvePathSymlinks(parent)
	realChild := resolvePathSymlinks(child)
	rel, err := filepath.Rel(realParent, realChild)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// IsGitIgnored reports whether git ignores checkPath inside targetDir.
func IsGitIgnored(targetDir, checkPath string) bool {
	cmd := exec.Command("git", "-C", targetDir, "check-ignore", "-q", checkPath)
	return cmd.Run() == nil
}

// NextRunDir selects the first non-existent <baseOut>/run-<N> directory.
func NextRunDir(baseOut string) string {
	for n := 1; n < 10000; n++ {
		candidate := filepath.Join(baseOut, fmt.Sprintf("run-%d", n))
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
	return filepath.Join(baseOut, "run-latest")
}

// AnyPathInScope checks whether any path in paths overlaps with any scope path in scopePaths.
func AnyPathInScope(paths, scopePaths []string) bool {
	for _, p := range paths {
		for _, sp := range scopePaths {
			if p == sp || strings.HasPrefix(p, strings.TrimSuffix(sp, "/")+"/") || strings.HasPrefix(sp, strings.TrimSuffix(p, "/")+"/") {
				return true
			}
		}
	}
	return false
}

// EvaluatePriorRuns inspects prior run directories and classifies their findings against current source on disk.
func EvaluatePriorRuns(targetDir string, priorDirs []string) ([]store.PriorCarryover, map[string]*store.CandidateEnvelope) {
	var carryovers []store.PriorCarryover
	carried := make(map[string]*store.CandidateEnvelope)

	for _, pdir := range priorDirs {
		findingsPath := filepath.Join(pdir, "findings.json")
		raw, err := validator.ReadFileNoFollow(findingsPath)
		if err != nil {
			continue
		}
		if validator.ValidateJSONPreflight(raw) != nil {
			continue
		}
		var findings []validator.Finding
		var rawList []map[string]any
		if json.Unmarshal(raw, &findings) != nil || json.Unmarshal(raw, &rawList) != nil {
			continue
		}
		co := store.PriorCarryover{
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
					carried[f.Fingerprint] = &store.CandidateEnvelope{
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
					carried[f.Fingerprint] = &store.CandidateEnvelope{
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

// FileHashSHA256 returns the hex SHA-256 of a regular file (without following symlinks) for deterministic comparisons.
func FileHashSHA256(path string) (string, error) {
	data, err := validator.ReadFileNoFollow(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyAndPinSourceFiles computes the SHA-256 of each repository-relative path in relPaths,
// fails if any previously pinned file in state.SourceHashes has drifted, and records new hashes.
func VerifyAndPinSourceFiles(targetDir string, state *store.InternalState, relPaths []string) error {
	if state.SourceHashes == nil {
		state.SourceHashes = make(map[string]string)
	}
	for _, rawRel := range relPaths {
		if rawRel == "" {
			continue
		}
		rel := filepath.ToSlash(filepath.Clean(rawRel))
		if err := validator.VerifyRepoFileAndLine(targetDir, rel, 0); err != nil {
			return err
		}
		absPath := filepath.Join(targetDir, filepath.FromSlash(rel))
		info, err := os.Lstat(absPath)
		if err != nil || info.IsDir() {
			continue
		}
		curHash, err := FileHashSHA256(absPath)
		if err != nil {
			return fmt.Errorf("hash source file %q: %w", rel, err)
		}
		if prevHash, exists := state.SourceHashes[rel]; exists && prevHash != curHash {
			return fmt.Errorf("source drift detected on %q: sha256 changed from %s to %s during audit run", rel, prevHash, curHash)
		}
		state.SourceHashes[rel] = curHash
	}
	return nil
}

// DetectSourceDrift checks all files pinned in state.SourceHashes against current targetDir on disk
// and returns a sorted list of human-readable drift error messages (and the list of drifted relative paths).
func DetectSourceDrift(targetDir string, state *store.InternalState) ([]string, []string) {
	if state == nil || len(state.SourceHashes) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(state.SourceHashes))
	for k := range state.SourceHashes {
		keys = append(keys, k)
	}
	// Sort deterministically
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	var errs []string
	var drifted []string
	for _, rel := range keys {
		expected := state.SourceHashes[rel]
		if err := validator.VerifyRepoFileAndLine(targetDir, rel, 1); err != nil {
			errs = append(errs, fmt.Sprintf("source drift detected on %q: %v", rel, err))
			drifted = append(drifted, rel)
			continue
		}
		absPath := filepath.Join(targetDir, filepath.FromSlash(rel))
		curHash, err := FileHashSHA256(absPath)
		if err != nil {
			errs = append(errs, fmt.Sprintf("source drift detected on %q: file unreadable (%v)", rel, err))
			drifted = append(drifted, rel)
			continue
		}
		if curHash != expected {
			errs = append(errs, fmt.Sprintf("source drift detected on %q: expected sha256 %s, got %s", rel, expected, curHash))
			drifted = append(drifted, rel)
		}
	}
	return errs, drifted
}

// LoadPriorCleanUnits inspects prior run directories and returns a map of coverage_id -> CoverageUnit
// for units that were cleanly covered (no findings, no unresolved blockers) and whose starting_paths
// and reviewed_paths are cryptographically identical (SHA-256) in targetDir today.
func LoadPriorCleanUnits(targetDir string, priorDirs []string) map[string]validator.CoverageUnit {
	clean := make(map[string]validator.CoverageUnit)
	for _, pdir := range priorDirs {
		var units []validator.CoverageUnit
		if err := store.ReadJSON(filepath.Join(pdir, "coverage-ledger.json"), &units); err != nil {
			continue
		}
		var pState store.InternalState
		_ = store.ReadJSON(filepath.Join(pdir, store.StateFilename), &pState)
		var pMeta store.RunMetadata
		_ = store.ReadJSON(filepath.Join(pdir, "run-metadata.json"), &pMeta)

		for _, u := range units {
			if u.Status != "covered" || len(u.ResultFingerprints) > 0 || len(u.Unresolved) > 0 {
				continue
			}
			if u.AgentID == nil || *u.AgentID == "" || len(u.LocalChecks) == 0 || len(u.ReviewedPaths) == 0 {
				continue
			}
			allPaths := make([]string, 0, len(u.StartingPaths)+len(u.ReviewedPaths))
			allPaths = append(allPaths, u.StartingPaths...)
			allPaths = append(allPaths, u.ReviewedPaths...)
			allUnchanged := true
			for _, rel := range allPaths {
				if validator.VerifyRepoFileAndLine(targetDir, rel, 1) != nil {
					allUnchanged = false
					break
				}
				curHash, err := FileHashSHA256(filepath.Join(targetDir, filepath.FromSlash(rel)))
				if err != nil {
					allUnchanged = false
					break
				}
				verified := false
				if pState.SourceHashes != nil {
					if oldHash, ok := pState.SourceHashes[rel]; ok && oldHash == curHash {
						verified = true
					}
				}
				if !verified && pMeta.SourceRef != "" && pMeta.SourceRef != "unversioned" && !pMeta.DirtyWorktree {
					cmd := exec.Command("git", "-C", targetDir, "show", pMeta.SourceRef+":"+rel)
					if out, gerr := cmd.Output(); gerr == nil {
						sum := sha256.Sum256(out)
						if hex.EncodeToString(sum[:]) == curHash {
							verified = true
						}
					}
				}
				if !verified {
					allUnchanged = false
					break
				}
			}
			if allUnchanged {
				clean[u.CoverageID] = u
			}
		}
	}
	return clean
}
