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

// IsSubpath reports whether child is inside or equal to parent.
func IsSubpath(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
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
		raw, err := os.ReadFile(findingsPath)
		if err != nil {
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

// FileHashSHA256 returns the hex SHA-256 of a file for deterministic comparisons.
func FileHashSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
