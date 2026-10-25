package validator

import (
	"fmt"
)

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
	limit := min(len(arr), MaxListItems)
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
	limit := min(len(checks), MaxListItems)
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
				if err := VerifyOutputRegularFile(outputDir, *c.Artifact); err != nil {
					addErr(fmt.Sprintf("%s.artifact: %v", base, err))
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

func validateStateInvariants(
	status string,
	agentID *string,
	reviewedPaths []string,
	checks []LocalCheck,
	fingerprints []string,
	unresolved []string,
	base string,
	errs *[]string,
) {
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
		validateStateInvariants(
			att.Status, att.AgentID, att.ReviewedPaths,
			att.LocalChecks, att.ResultFingerprints, att.Unresolved, attBase, errs,
		)

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
