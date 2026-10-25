package validator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

var (
	validStatuses = map[string]bool{
		"planned":        true,
		"not_applicable": true,
		"out_of_scope":   true,
		"in_progress":    true,
		"covered":        true,
		"candidate":      true,
		"blocked":        true,
		"deferred":       true,
	}
	validAttemptStatuses = map[string]bool{
		"covered":   true,
		"candidate": true,
		"blocked":   true,
	}
	validPriorStatuses = map[string]bool{
		"new":                            true,
		"prior_confirmed_same_source":    true,
		"prior_confirmed_changed_source": true,
		"prior_needs_validation":         true,
		"prior_deferred":                 true,
		"prior_blocked":                  true,
		"prior_out_of_scope":             true,
		"prior_covered_same_source":      true,
		"prior_covered_changed_source":   true,
		"prior_rejected_claim_changed":   true,
		"none":                           true,
	}
	requiredUnitFields = []string{
		"coverage_id",
		"canonical_refs",
		"surface",
		"boundary",
		"subsystem",
		"attack_class",
		"starting_paths",
		"ordinary_attack_class_block",
		"selected_companion_blocks",
		"excluded_blocks",
		"prior_status",
		"attempts",
		"wave",
		"status",
		"agent_id",
		"reviewed_paths",
		"local_checks",
		"result_fingerprints",
		"unresolved",
	}
)

// ValidateCoverageLedgerFile reads and validates coverage-ledger.json from disk.
// If targetDir is non-empty, also verifies that starting_paths and reviewed_paths exist in targetDir.
// If outputDir is non-empty, also verifies that local check artifacts exist on disk.
func ValidateCoverageLedgerFile(path, targetDir, outputDir string, validBlocks map[string]bool) ([]string, error) {
	raw, err := ReadFileNoFollow(path)
	if err != nil {
		return nil, err
	}
	return ValidateCoverageLedgerBytes(raw, targetDir, outputDir, validBlocks), nil
}

// ValidateCoverageLedgerBytes validates raw JSON bytes of coverage-ledger.json.
func ValidateCoverageLedgerBytes(raw []byte, targetDir, outputDir string, validBlocks map[string]bool) []string {
	var errs []string
	addErr := func(msg string) {
		if len(errs) < MaxValidationErrors {
			errs = append(errs, msg)
		}
	}

	var rawList []map[string]any
	if err := json.Unmarshal(raw, &rawList); err != nil {
		var anyVal any
		if err2 := json.Unmarshal(raw, &anyVal); err2 == nil {
			addErr("$: expected a top-level array")
			return errs
		}
		addErr(fmt.Sprintf("$: invalid JSON syntax: %v", err))
		return errs
	}
	if len(rawList) > MaxUnits {
		addErr(fmt.Sprintf("$: exceeds %d coverage units", MaxUnits))
		return errs
	}

	var units []CoverageUnit
	_ = json.Unmarshal(raw, &units)

	ids := make(map[string]struct {
		index int
		key   string
	})
	semantics := make(map[string]struct {
		id    string
		index int
	})
	var previousID string

	for i, rawUnit := range rawList {
		if len(errs) >= MaxValidationErrors {
			break
		}
		base := fmt.Sprintf("$[%d]", i)
		for _, req := range requiredUnitFields {
			if _, ok := rawUnit[req]; !ok {
				addErr(fmt.Sprintf("%s: missing required field %q", base, req))
			}
		}
		if i >= len(units) {
			continue
		}
		u := units[i]
		unitErrs := validateSingleUnit(u, rawUnit, base, targetDir, outputDir, validBlocks)
		for _, e := range unitErrs {
			addErr(e)
		}
		if len(errs) >= MaxValidationErrors {
			break
		}
		if u.CoverageID == "" {
			continue
		}

		semKey := ""
		if IsVisibleText(u.Surface, 0) && IsVisibleText(u.Boundary, 0) && IsVisibleText(u.Subsystem, 0) && IsVisibleText(u.AttackClass, 0) {
			life := ""
			if u.Lifecycle != nil {
				life = *u.Lifecycle
			}
			semKey = fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s", u.Surface, u.Boundary, u.Subsystem, u.AttackClass, life)
		}

		if prev, exists := ids[u.CoverageID]; exists {
			qualifier := "duplicate coverage ID"
			if semKey != "" && prev.key != "" && prev.key != semKey {
				qualifier = "canonical identity collision with different semantic fields"
			}
			addErr(fmt.Sprintf("%s.coverage_id: %s at $[%d]", base, qualifier, prev.index))
		} else {
			ids[u.CoverageID] = struct {
				index int
				key   string
			}{index: i, key: semKey}
		}

		if semKey != "" {
			if prev, exists := semantics[semKey]; exists && prev.id != u.CoverageID {
				addErr(fmt.Sprintf("%s.canonical_refs: semantic tuple already uses coverage ID %q at $[%d]", base, prev.id, prev.index))
			} else if !exists {
				semantics[semKey] = struct {
					id    string
					index int
				}{id: u.CoverageID, index: i}
			}
		}

		if previousID != "" && previousID > u.CoverageID {
			addErr(fmt.Sprintf("%s.coverage_id: units must be sorted lexicographically", base))
		}
		previousID = u.CoverageID
	}

	return errs
}

func validateSingleUnit(u CoverageUnit, rawUnit map[string]any, base, targetDir, outputDir string, validBlocks map[string]bool) []string {
	var errs []string
	addErr := func(msg string) {
		if len(errs) < MaxValidationErrors {
			errs = append(errs, msg)
		}
	}

	if !IsVisibleText(u.Surface, 0) {
		addErr(fmt.Sprintf("%s.surface: invalid text", base))
	}
	if !IsVisibleText(u.Boundary, 0) {
		addErr(fmt.Sprintf("%s.boundary: invalid text", base))
	}
	if !IsVisibleText(u.Subsystem, 0) {
		addErr(fmt.Sprintf("%s.subsystem: invalid text", base))
	}
	if !IsVisibleText(u.AttackClass, 0) {
		addErr(fmt.Sprintf("%s.attack_class: invalid text", base))
	}
	_, hasLifecycle := rawUnit["lifecycle"]
	if hasLifecycle && (u.Lifecycle == nil || !IsVisibleText(*u.Lifecycle, 0)) {
		addErr(fmt.Sprintf("%s.lifecycle: invalid text", base))
	}

	var expectedID string
	rawRefs, ok := rawUnit["canonical_refs"].(map[string]any)
	if !ok {
		addErr(fmt.Sprintf("%s.canonical_refs: expected object", base))
	} else {
		_, hasRefLifecycle := rawRefs["lifecycle"]
		if hasLifecycle != hasRefLifecycle {
			addErr(fmt.Sprintf("%s: lifecycle and canonical_refs.lifecycle must appear together", base))
		}
		expectedFields := map[string]bool{
			"surface":      true,
			"boundary":     true,
			"subsystem":    true,
			"attack_class": true,
		}
		if hasRefLifecycle {
			expectedFields["lifecycle"] = true
		}
		for f := range expectedFields {
			val, exists := rawRefs[f]
			if !exists {
				addErr(fmt.Sprintf("%s.canonical_refs: missing required field %q", base, f))
			} else if strVal, isStr := val.(string); !isStr || !IsCanonicalRef(strVal) {
				addErr(fmt.Sprintf("%s.canonical_refs.%s: invalid canonical reference", base, f))
			}
		}
		for f := range rawRefs {
			if !expectedFields[f] {
				addErr(fmt.Sprintf("%s.canonical_refs: contains unexpected fields", base))
				break
			}
		}
		if cid, err := DeriveCoverageID(u.CanonicalRefs); err == nil {
			expectedID = cid
		}
	}

	if !IsVisibleText(u.CoverageID, 65536) {
		addErr(fmt.Sprintf("%s.coverage_id: invalid text", base))
	} else if expectedID != "" && u.CoverageID != expectedID {
		addErr(fmt.Sprintf("%s.coverage_id: expected canonical ID %q", base, expectedID))
	}

	validateStringArray(u.StartingPaths, base+".starting_paths", &errs, false, false, true, targetDir)

	if u.OrdinaryAttackClassBlock != nil {
		if !IsVisibleText(*u.OrdinaryAttackClassBlock, 0) {
			addErr(fmt.Sprintf("%s.ordinary_attack_class_block: expected null or non-empty text", base))
		} else if validBlocks != nil && !validBlocks[*u.OrdinaryAttackClassBlock] {
			addErr(fmt.Sprintf("%s.ordinary_attack_class_block: unknown block reference %q", base, *u.OrdinaryAttackClassBlock))
		}
	}

	validateStringArray(u.SelectedCompanionBlocks, base+".selected_companion_blocks", &errs, true, false, false, "")
	if validBlocks != nil {
		for idx, blk := range u.SelectedCompanionBlocks {
			if !validBlocks[blk] {
				addErr(fmt.Sprintf("%s.selected_companion_blocks[%d]: unknown block reference %q", base, idx, blk))
			}
		}
	}

	selectedSet := make(map[string]bool)
	for _, b := range u.SelectedCompanionBlocks {
		selectedSet[b] = true
	}
	seenExcl := make(map[string]bool)
	for idx, ex := range u.ExcludedBlocks {
		ebase := fmt.Sprintf("%s.excluded_blocks[%d]", base, idx)
		if !IsVisibleText(ex.Block, 0) {
			addErr(fmt.Sprintf("%s.block: invalid text", ebase))
		}
		if !IsVisibleText(ex.Reason, 0) {
			addErr(fmt.Sprintf("%s.reason: invalid text", ebase))
		}
		if seenExcl[ex.Block] {
			addErr(fmt.Sprintf("%s.block: duplicate entry", ebase))
		}
		seenExcl[ex.Block] = true
		if selectedSet[ex.Block] {
			addErr(fmt.Sprintf("%s.block: block is also selected", ebase))
		}
	}

	if !validPriorStatuses[u.PriorStatus] {
		addErr(fmt.Sprintf("%s.prior_status: invalid value %q", base, u.PriorStatus))
	}
	if !validStatuses[u.Status] {
		addErr(fmt.Sprintf("%s.status: invalid value %q", base, u.Status))
	}
	if u.Wave < 1 {
		addErr(fmt.Sprintf("%s.wave: expected a positive integer", base))
	}
	if u.AgentID != nil && !IsSafeAgentID(*u.AgentID) {
		addErr(fmt.Sprintf("%s.agent_id: expected null or a safe agent ID", base))
	}

	validateAttempts(u.Attempts, u, base, &errs, targetDir, outputDir)
	validateStringArray(u.ReviewedPaths, base+".reviewed_paths", &errs, true, false, true, targetDir)
	validateChecks(u.LocalChecks, base+".local_checks", &errs, targetDir, outputDir)
	validateReviewedPathOwnership(u.ReviewedPaths, u.LocalChecks, base, &errs)
	validateStringArray(u.ResultFingerprints, base+".result_fingerprints", &errs, true, true, false, "")
	validateStringArray(u.Unresolved, base+".unresolved", &errs, true, false, false, "")

	validateStateInvariants(u.Status, u.AgentID, u.ReviewedPaths, u.LocalChecks, u.ResultFingerprints, u.Unresolved, base, &errs)

	return errs
}

func validateStringArray(arr []string, location string, errs *[]string, allowEmpty, fingerprint, pathValue bool, targetDir string) {
	addErr := func(msg string) {
		if len(*errs) < MaxValidationErrors {
			*errs = append(*errs, msg)
		}
	}
	if !allowEmpty && len(arr) == 0 {
		addErr(fmt.Sprintf("%s: must not be empty", location))
	}
	if len(arr) > MaxListItems {
		addErr(fmt.Sprintf("%s: exceeds %d entries", location, MaxListItems))
	}
	seen := make(map[string]bool)
	limit := len(arr)
	if limit > MaxListItems {
		limit = MaxListItems
	}
	for i := 0; i < limit; i++ {
		entry := arr[i]
		entryLoc := fmt.Sprintf("%s[%d]", location, i)
		valid := false
		if pathValue {
			valid = IsSafeRelativePath(entry)
		} else {
			valid = IsVisibleText(entry, 0)
		}
		if !valid {
			kind := "text"
			if pathValue {
				kind = "repository-relative path"
			}
			addErr(fmt.Sprintf("%s: invalid %s", entryLoc, kind))
		} else if pathValue && targetDir != "" {
			if err := VerifyRepoFileAndLine(targetDir, entry, 0); err != nil {
				addErr(fmt.Sprintf("%s: %v", entryLoc, err))
			}
		}
		if fingerprint && !FingerprintPattern.MatchString(entry) {
			addErr(fmt.Sprintf("%s: invalid fingerprint", entryLoc))
		}
		if seen[entry] {
			addErr(fmt.Sprintf("%s: duplicate entry", entryLoc))
		}
		seen[entry] = true
	}
}

func validateChecks(checks []LocalCheck, location string, errs *[]string, targetDir, outputDir string) {
	addErr := func(msg string) {
		if len(*errs) < MaxValidationErrors {
			*errs = append(*errs, msg)
		}
	}
	if len(checks) > MaxListItems {
		addErr(fmt.Sprintf("%s: exceeds %d entries", location, MaxListItems))
	}
	limit := len(checks)
	if limit > MaxListItems {
		limit = MaxListItems
	}
	for i := 0; i < limit; i++ {
		c := checks[i]
		base := fmt.Sprintf("%s[%d]", location, i)
		if !IsSafeAgentID(c.AgentID) {
			addErr(fmt.Sprintf("%s.agent_id: expected a canonical lowercase agent ID", base))
		}
		validateStringArray(c.ReviewedPaths, base+".reviewed_paths", errs, false, false, true, targetDir)
		if !IsVisibleText(c.Invariant, 0) {
			addErr(fmt.Sprintf("%s.invariant: invalid text", base))
		}
		if c.Method != "source" && c.Method != "local" {
			addErr(fmt.Sprintf("%s.method: expected \"source\" or \"local\"", base))
		}
		if !IsVisibleText(c.Result, 0) {
			addErr(fmt.Sprintf("%s.result: invalid text", base))
		}
		if c.Method == "source" && c.Artifact != nil {
			addErr(fmt.Sprintf("%s.artifact: source-only check must use null", base))
		} else if c.Method == "local" {
			if c.Artifact == nil || !IsOwnedArtifactPath(*c.Artifact, c.AgentID) {
				owner := c.AgentID
				if !IsSafeAgentID(owner) {
					owner = "<agent-id>"
				}
				addErr(fmt.Sprintf("%s.artifact: local check requires an artifact owned by agent %q", base, owner))
			} else if outputDir != "" {
				artDiskPath := filepath.Join(outputDir, filepath.FromSlash(*c.Artifact))
				st, err := os.Lstat(artDiskPath)
				if err != nil || !st.Mode().IsRegular() {
					addErr(fmt.Sprintf("%s.artifact: promoted regular file %q does not exist in output directory", base, *c.Artifact))
				}
			}
		}
	}
}

func validateReviewedPathOwnership(reviewedPaths []string, checks []LocalCheck, base string, errs *[]string) {
	addErr := func(msg string) {
		if len(*errs) < MaxValidationErrors {
			*errs = append(*errs, msg)
		}
	}
	agg := make(map[string]bool)
	for _, p := range reviewedPaths {
		agg[p] = true
	}
	owned := make(map[string]bool)
	for _, c := range checks {
		for _, p := range c.ReviewedPaths {
			owned[p] = true
		}
	}
	for _, p := range reviewedPaths {
		if !owned[p] {
			addErr(fmt.Sprintf("%s.reviewed_paths: %q has no check owner", base, p))
		}
	}
	for _, c := range checks {
		for _, p := range c.ReviewedPaths {
			if !agg[p] {
				addErr(fmt.Sprintf("%s.local_checks: owned path %q is absent from aggregate reviewed_paths", base, p))
			}
		}
	}
}

func validateStateInvariants(status string, agentID *string, reviewedPaths []string, checks []LocalCheck, fingerprints []string, unresolved []string, base string, errs *[]string) {
	addErr := func(msg string) {
		if len(*errs) < MaxValidationErrors {
			*errs = append(*errs, msg)
		}
	}
	requireEmpty := func(length int, field string) {
		if length > 0 {
			addErr(fmt.Sprintf("%s.%s: unit with status %q must keep this array empty", base, field, status))
		}
	}
	requireNonEmpty := func(length int, field string) {
		if length == 0 {
			addErr(fmt.Sprintf("%s.%s: unit with status %q requires entries", base, field, status))
		}
	}
	requireOwner := func() {
		if agentID == nil || !IsSafeAgentID(*agentID) {
			addErr(fmt.Sprintf("%s.agent_id: unit with status %q requires a canonical lowercase agent ID", base, status))
		}
	}

	if status != "candidate" {
		requireEmpty(len(fingerprints), "result_fingerprints")
	}

	switch status {
	case "planned":
		if agentID != nil {
			addErr(fmt.Sprintf("%s.agent_id: planned unit must be unassigned", base))
		}
		requireEmpty(len(reviewedPaths), "reviewed_paths")
		requireEmpty(len(checks), "local_checks")
		requireEmpty(len(unresolved), "unresolved")
	case "not_applicable", "out_of_scope", "deferred":
		if agentID != nil {
			addErr(fmt.Sprintf("%s.agent_id: unit with status %q must be unassigned", base, status))
		}
		requireEmpty(len(reviewedPaths), "reviewed_paths")
		requireEmpty(len(checks), "local_checks")
		requireNonEmpty(len(unresolved), "unresolved")
	case "in_progress":
		requireOwner()
		requireEmpty(len(reviewedPaths), "reviewed_paths")
		requireEmpty(len(checks), "local_checks")
		requireEmpty(len(unresolved), "unresolved")
	case "blocked":
		requireOwner()
		requireNonEmpty(len(reviewedPaths), "reviewed_paths")
		requireNonEmpty(len(checks), "local_checks")
		requireNonEmpty(len(unresolved), "unresolved")
	case "covered":
		requireOwner()
		requireNonEmpty(len(reviewedPaths), "reviewed_paths")
		requireNonEmpty(len(checks), "local_checks")
		requireEmpty(len(unresolved), "unresolved")
	case "candidate":
		requireOwner()
		requireNonEmpty(len(reviewedPaths), "reviewed_paths")
		requireNonEmpty(len(checks), "local_checks")
		requireNonEmpty(len(fingerprints), "result_fingerprints")
	}
}

func validateAttempts(attempts []ArchivedAttempt, u CoverageUnit, base string, errs *[]string, targetDir, outputDir string) {
	addErr := func(msg string) {
		if len(*errs) < MaxValidationErrors {
			*errs = append(*errs, msg)
		}
	}
	if len(attempts) > MaxListItems {
		addErr(fmt.Sprintf("%s.attempts: exceeds %d entries", base, MaxListItems))
	}
	priorOwners := make(map[string]bool)
	priorArtifacts := make(map[string]bool)
	previousWave := 0

	for i, att := range attempts {
		attBase := fmt.Sprintf("%s.attempts[%d]", base, i)
		if att.Wave < 1 {
			addErr(fmt.Sprintf("%s.wave: expected a positive integer", attBase))
		} else {
			if att.Wave <= previousWave {
				addErr(fmt.Sprintf("%s.wave: archived attempt waves must be strictly increasing", attBase))
			}
			if u.Wave >= 1 && att.Wave >= u.Wave {
				addErr(fmt.Sprintf("%s.wave: archived attempt wave must precede current wave %d", attBase, u.Wave))
			}
			previousWave = att.Wave
		}
		if !validAttemptStatuses[att.Status] {
			addErr(fmt.Sprintf("%s.status: expected \"covered\", \"candidate\", or \"blocked\"", attBase))
		}
		hasFreshOwner := false
		if att.AgentID == nil || !IsSafeAgentID(*att.AgentID) {
			addErr(fmt.Sprintf("%s.agent_id: archived attempt requires a canonical lowercase agent ID", attBase))
		} else if priorOwners[*att.AgentID] {
			addErr(fmt.Sprintf("%s.agent_id: assignment owner must be fresh for each attempt", attBase))
		} else {
			hasFreshOwner = true
		}

		validateStringArray(att.ReviewedPaths, attBase+".reviewed_paths", errs, true, false, true, targetDir)
		validateChecks(att.LocalChecks, attBase+".local_checks", errs, targetDir, outputDir)
		validateReviewedPathOwnership(att.ReviewedPaths, att.LocalChecks, attBase, errs)
		validateStringArray(att.ResultFingerprints, attBase+".result_fingerprints", errs, true, true, false, "")
		validateStringArray(att.Unresolved, attBase+".unresolved", errs, true, false, false, "")
		if !IsVisibleText(att.ReassignmentReason, 0) {
			addErr(fmt.Sprintf("%s.reassignment_reason: invalid text", attBase))
		}
		validateStateInvariants(att.Status, att.AgentID, att.ReviewedPaths, att.LocalChecks, att.ResultFingerprints, att.Unresolved, attBase, errs)

		for cIdx, c := range att.LocalChecks {
			if priorOwners[c.AgentID] {
				addErr(fmt.Sprintf("%s.local_checks[%d].agent_id: prior assignment owner evidence must remain in its earlier attempt", attBase, cIdx))
			}
			if c.Artifact != nil && priorArtifacts[*c.Artifact] {
				addErr(fmt.Sprintf("%s.local_checks[%d].artifact: artifact from an earlier attempt cannot be reused", attBase, cIdx))
			}
			if c.Method == "local" && c.Artifact != nil {
				priorArtifacts[*c.Artifact] = true
			}
		}
		if hasFreshOwner {
			priorOwners[*att.AgentID] = true
		}
	}

	if u.AgentID != nil && IsSafeAgentID(*u.AgentID) && priorOwners[*u.AgentID] {
		addErr(fmt.Sprintf("%s.agent_id: current assignment owner must be fresh after reassignment", base))
	}
	for cIdx, c := range u.LocalChecks {
		if priorOwners[c.AgentID] {
			addErr(fmt.Sprintf("%s.local_checks[%d].agent_id: prior assignment owner evidence must remain in its archived attempt", base, cIdx))
		}
		if c.Artifact != nil && priorArtifacts[*c.Artifact] {
			addErr(fmt.Sprintf("%s.local_checks[%d].artifact: artifact from an archived attempt cannot be reused", base, cIdx))
		}
	}
}
