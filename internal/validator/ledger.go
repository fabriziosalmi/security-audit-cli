package validator

import (
	"encoding/json"
	"fmt"
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
	allowedUnitFields = map[string]bool{
		"coverage_id":                 true,
		"canonical_refs":              true,
		"surface":                     true,
		"boundary":                    true,
		"subsystem":                   true,
		"attack_class":                true,
		"lifecycle":                   true,
		"starting_paths":              true,
		"ordinary_attack_class_block": true,
		"selected_companion_blocks":   true,
		"excluded_blocks":             true,
		"prior_status":                true,
		"attempts":                    true,
		"wave":                        true,
		"status":                      true,
		"agent_id":                    true,
		"reviewed_paths":              true,
		"local_checks":                true,
		"result_fingerprints":         true,
		"unresolved":                  true,
		"hardening":                   true,
	}
)

// ValidateCoverageLedgerFile reads and validates coverage-ledger.json from disk.
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

	if err := ValidateJSONPreflight(raw); err != nil {
		addErr(err.Error())
		return errs
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
		for k := range rawUnit {
			if !allowedUnitFields[k] {
				addErr(fmt.Sprintf("%s: unexpected field %q", base, k))
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
		if len(errs) >= MaxValidationErrors || u.CoverageID == "" {
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

// ValidateCrossFileConsistency verifies that every finding in findings.json is linked by at least one unit in coverage-ledger.json.
func ValidateCrossFileConsistency(units []CoverageUnit, findings []Finding) []string {
	var errs []string
	linkedInLedger := make(map[string]bool)
	for _, u := range units {
		for _, fp := range u.ResultFingerprints {
			linkedInLedger[fp] = true
		}
		for _, att := range u.Attempts {
			for _, fp := range att.ResultFingerprints {
				linkedInLedger[fp] = true
			}
		}
	}
	for idx, f := range findings {
		if !linkedInLedger[f.Fingerprint] {
			errs = append(errs, fmt.Sprintf(
				"findings[%d].fingerprint: %q is not referenced by any coverage unit result_fingerprints",
				idx, f.Fingerprint,
			))
		}
	}
	return errs
}
