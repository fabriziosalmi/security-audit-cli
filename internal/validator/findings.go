package validator

import (
	"encoding/json"
	"fmt"
)

var (
	severityRank = map[string]int{
		"informational": 0,
		"low":           1,
		"medium":        2,
		"high":          3,
		"critical":      4,
	}
	confidenceScores = map[string]bool{
		"low":    true,
		"medium": true,
		"high":   true,
	}
	conditionKinds = map[string]bool{
		"authentication_level":     true,
		"authorization_role":       true,
		"user_interaction":         true,
		"system_configuration":     true,
		"network_routing":          true,
		"environmental_dependency": true,
		"data_state":               true,
		"timing_dependency":        true,
		"third_party_dependency":   true,
	}
	confirmedAllowed = map[string]bool{
		"verdict":           true,
		"fingerprint":       true,
		"title":             true,
		"description":       true,
		"root_cause":        true,
		"intended_behavior": true,
		"trace":             true,
		"evidence":          true,
		"conditions":        true,
		"execution":         true,
		"remediation":       true,
		"severity":          true,
		"confidence":        true,
	}
	needsValidationAllowed = map[string]bool{
		"verdict":            true,
		"fingerprint":        true,
		"title":              true,
		"description":        true,
		"claimed_root_cause": true,
		"trace":              true,
		"evidence":           true,
		"blockers":           true,
		"validation_plan":    true,
	}
	rejectedAllowed = map[string]bool{
		"verdict":            true,
		"fingerprint":        true,
		"title":              true,
		"description":        true,
		"claimed_root_cause": true,
		"trace":              true,
		"evidence":           true,
		"reason":             true,
	}
)

// ValidateFindingsFile reads and validates findings.json from disk.
// If targetDir is non-empty, also verifies that every cited file and line in trace/evidence/remediation exists on disk.
func ValidateFindingsFile(path, targetDir string) ([]string, error) {
	raw, err := ReadFileNoFollow(path)
	if err != nil {
		return nil, err
	}
	return ValidateFindingsBytes(raw, targetDir), nil
}

// ValidateFindingsBytes validates raw JSON bytes of findings.json against report-schema.json and semantic rules.
func ValidateFindingsBytes(raw []byte, targetDir string) []string {
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
			addErr("$: expected array")
			return errs
		}
		addErr(fmt.Sprintf("$: invalid JSON syntax: %v", err))
		return errs
	}
	if len(rawList) > MaxListItems {
		addErr(fmt.Sprintf("$: exceeds %d item array limit", MaxListItems))
		return errs
	}

	var findings []Finding
	_ = json.Unmarshal(raw, &findings)

	fingerprints := make(map[string]int)
	var previousFingerprint string

	for i, rawItem := range rawList {
		if len(errs) >= MaxValidationErrors {
			break
		}
		base := fmt.Sprintf("$[%d]", i)
		if i >= len(findings) {
			continue
		}
		f := findings[i]
		itemErrs := ValidateSingleFinding(f, rawItem, base, targetDir, false)
		for _, e := range itemErrs {
			addErr(e)
		}

		if f.Fingerprint != "" {
			if prevIdx, exists := fingerprints[f.Fingerprint]; exists {
				addErr(fmt.Sprintf("%s.fingerprint: duplicate of $[%d].fingerprint", base, prevIdx))
			} else {
				fingerprints[f.Fingerprint] = i
			}
			if previousFingerprint != "" && previousFingerprint > f.Fingerprint {
				addErr(fmt.Sprintf("%s.fingerprint: findings must be sorted lexicographically", base))
			}
			previousFingerprint = f.Fingerprint
		}
	}

	return errs
}

// ValidateSingleFinding validates a single Finding object against its verdict branch and semantic rules.
// If isCandidate is true, checks proposed_verdict ("confirmed" or "needs_validation") instead of verdict.
func ValidateSingleFinding(f Finding, rawItem map[string]any, base, targetDir string, isCandidate bool) []string {
	var errs []string
	addErr := func(msg string) {
		if len(errs) < MaxValidationErrors {
			errs = append(errs, msg)
		}
	}

	verdict := f.Verdict
	verdictField := "verdict"
	if isCandidate {
		verdictField = "proposed_verdict"
		if pv, ok := rawItem["proposed_verdict"].(string); ok {
			verdict = pv
		}
	}

	if verdict != "confirmed" && verdict != "needs_validation" && (isCandidate || verdict != "rejected") {
		addErr(fmt.Sprintf("%s.%s: invalid verdict %q", base, verdictField, verdict))
		return errs
	}

	var allowed map[string]bool
	var required []string
	switch verdict {
	case "confirmed":
		allowed = confirmedAllowed
		required = []string{verdictField, "fingerprint", "title", "description", "root_cause", "intended_behavior", "trace", "evidence", "conditions", "execution", "remediation", "severity", "confidence"}
	case "needs_validation":
		allowed = needsValidationAllowed
		required = []string{verdictField, "fingerprint", "title", "description", "claimed_root_cause", "trace", "evidence", "blockers", "validation_plan"}
	case "rejected":
		allowed = rejectedAllowed
		required = []string{verdictField, "fingerprint", "title", "description", "claimed_root_cause", "trace", "evidence", "reason"}
	}

	for _, req := range required {
		if _, ok := rawItem[req]; !ok {
			addErr(fmt.Sprintf("%s: missing required field %q", base, req))
		}
	}
	for k := range rawItem {
		if isCandidate && k == "proposed_verdict" {
			continue
		}
		if !allowed[k] {
			addErr(fmt.Sprintf("%s: unexpected field %q for verdict %q", base, k, verdict))
		}
	}

	if !FingerprintPattern.MatchString(f.Fingerprint) {
		addErr(fmt.Sprintf("%s.fingerprint: must match pattern %q", base, FingerprintPattern.String()))
	}
	if !HasVisibleProse(f.Title) {
		addErr(fmt.Sprintf("%s.title: must contain a visible character", base))
	}
	if !HasVisibleProse(f.Description) {
		addErr(fmt.Sprintf("%s.description: must contain a visible character", base))
	}

	// Validate trace
	if len(f.Trace) == 0 {
		addErr(fmt.Sprintf("%s.trace: must have at least 1 item(s), got 0", base))
	} else {
		seenTrace := make(map[string]bool)
		for idx, t := range f.Trace {
			tbase := fmt.Sprintf("%s.trace[%d]", base, idx)
			if t.Kind != "entrypoint" && t.Kind != "propagation" && t.Kind != "sink" {
				addErr(fmt.Sprintf("%s.kind: invalid value %q", tbase, t.Kind))
			}
			if !IsSafeRelativePath(t.File) {
				addErr(fmt.Sprintf("%s.file: must be a safe repository-relative source path", tbase))
			} else if targetDir != "" {
				if err := VerifyRepoFileAndLine(targetDir, t.File, t.Line); err != nil {
					addErr(fmt.Sprintf("%s: %v", tbase, err))
				}
			}
			if t.Line < 1 {
				addErr(fmt.Sprintf("%s.line: must be a positive integer", tbase))
			}
			if !HasVisibleProse(t.Scope) {
				addErr(fmt.Sprintf("%s.scope: must contain a visible character", tbase))
			}
			if !HasVisibleProse(t.Description) {
				addErr(fmt.Sprintf("%s.description: must contain a visible character", tbase))
			}
			key := CanonicalJSONKey(t)
			if seenTrace[key] {
				addErr(fmt.Sprintf("%s.trace: items must be unique; duplicate at index %d", base, idx))
			}
			seenTrace[key] = true
		}
		if len(f.Trace) == 1 {
			if f.Trace[0].Kind != "entrypoint" && f.Trace[0].Kind != "sink" {
				addErr(fmt.Sprintf("%s.trace[0].kind: a one-line trace must be \"entrypoint\" or \"sink\"", base))
			}
		} else {
			last := len(f.Trace) - 1
			if f.Trace[0].Kind != "entrypoint" {
				addErr(fmt.Sprintf("%s.trace[0].kind: must be \"entrypoint\", got %q", base, f.Trace[0].Kind))
			}
			if f.Trace[last].Kind != "sink" {
				addErr(fmt.Sprintf("%s.trace[%d].kind: must be \"sink\", got %q", base, last, f.Trace[last].Kind))
			}
			for idx := 1; idx < last; idx++ {
				if f.Trace[idx].Kind != "propagation" {
					addErr(fmt.Sprintf("%s.trace[%d].kind: must be \"propagation\", got %q", base, idx, f.Trace[idx].Kind))
				}
			}
		}
	}

	// Validate evidence
	if len(f.Evidence) == 0 {
		addErr(fmt.Sprintf("%s.evidence: must have at least 1 item(s), got 0", base))
	} else {
		seenEv := make(map[string]bool)
		for idx, ev := range f.Evidence {
			ebase := fmt.Sprintf("%s.evidence[%d]", base, idx)
			if !IsSafeRelativePath(ev.File) {
				addErr(fmt.Sprintf("%s.file: must be a safe repository-relative source path", ebase))
			} else if targetDir != "" {
				if err := VerifyRepoFileAndLine(targetDir, ev.File, ev.Line); err != nil {
					addErr(fmt.Sprintf("%s: %v", ebase, err))
				}
			}
			if ev.Line < 1 {
				addErr(fmt.Sprintf("%s.line: must be a positive integer", ebase))
			}
			if !HasVisibleProse(ev.Description) {
				addErr(fmt.Sprintf("%s.description: must contain a visible character", ebase))
			}
			key := CanonicalJSONKey(ev)
			if seenEv[key] {
				addErr(fmt.Sprintf("%s.evidence: items must be unique; duplicate at index %d", base, idx))
			}
			seenEv[key] = true
		}
	}

	switch verdict {
	case "confirmed":
		if !HasVisibleProse(f.RootCause) {
			addErr(fmt.Sprintf("%s.root_cause: must contain a visible character", base))
		}
		if !HasVisibleProse(f.IntendedBehavior) {
			addErr(fmt.Sprintf("%s.intended_behavior: must contain a visible character", base))
		}
		seenCond := make(map[string]bool)
		for idx, c := range f.Conditions {
			cbase := fmt.Sprintf("%s.conditions[%d]", base, idx)
			if !conditionKinds[c.Kind] {
				addErr(fmt.Sprintf("%s.kind: invalid value %q", cbase, c.Kind))
			}
			if !HasVisibleProse(c.Description) {
				addErr(fmt.Sprintf("%s.description: must contain a visible character", cbase))
			}
			key := CanonicalJSONKey(c)
			if seenCond[key] {
				addErr(fmt.Sprintf("%s.conditions: items must be unique; duplicate at index %d", base, idx))
			}
			seenCond[key] = true
		}
		if f.Execution == nil {
			addErr(fmt.Sprintf("%s: confirmed finding requires execution block", base))
		} else {
			if !HasVisibleProse(f.Execution.AttackerPerspective) {
				addErr(fmt.Sprintf("%s.execution.attacker_perspective: must contain a visible character", base))
			}
			if len(f.Execution.Payloads) == 0 {
				addErr(fmt.Sprintf("%s.execution.payloads: must have at least 1 item(s)", base))
			}
			if len(f.Execution.Instructions) == 0 {
				addErr(fmt.Sprintf("%s.execution.instructions: must have at least 1 item(s)", base))
			}
			for idx, inst := range f.Execution.Instructions {
				if !HasVisibleProse(inst) {
					addErr(fmt.Sprintf("%s.execution.instructions[%d]: must contain a visible character", base, idx))
				}
			}
			if !HasVisibleProse(f.Execution.ObservedResult) {
				addErr(fmt.Sprintf("%s: confirmed finding requires a visible execution observed_result", base))
			}
		}
		if f.Remediation == nil || !HasVisibleProse(f.Remediation.Strategy) {
			addErr(fmt.Sprintf("%s: confirmed finding requires visible remediation", base))
		} else {
			for idx, cc := range f.Remediation.CodeChanges {
				if !IsSafeRelativePath(cc.FileName) {
					addErr(fmt.Sprintf("%s.remediation.code_changes[%d].file_name: must be a safe repository-relative source path", base, idx))
				} else if targetDir != "" {
					if err := VerifyRepoFileAndLine(targetDir, cc.FileName, 0); err != nil {
						addErr(fmt.Sprintf("%s.remediation.code_changes[%d].file_name: %v", base, idx, err))
					}
				}
			}
		}
		if f.Severity == nil {
			addErr(fmt.Sprintf("%s: confirmed finding requires severity", base))
		} else {
			if _, ok := severityRank[f.Severity.Likelihood.Score]; !ok {
				addErr(fmt.Sprintf("%s.severity.likelihood.score: invalid value %q", base, f.Severity.Likelihood.Score))
			}
			if !HasVisibleProse(f.Severity.Likelihood.Reason) {
				addErr(fmt.Sprintf("%s.severity.likelihood.reason: must contain a visible character", base))
			}
			impRank, impOk := severityRank[f.Severity.Impact.Score]
			if !impOk {
				addErr(fmt.Sprintf("%s.severity.impact.score: invalid value %q", base, f.Severity.Impact.Score))
			}
			if !HasVisibleProse(f.Severity.Impact.Reason) {
				addErr(fmt.Sprintf("%s.severity.impact.reason: must contain a visible character", base))
			}
			ovRank, ovOk := severityRank[f.Severity.OverallSeverity]
			if !ovOk {
				addErr(fmt.Sprintf("%s.severity.overall_severity: invalid value %q", base, f.Severity.OverallSeverity))
			}
			if impOk && ovOk && ovRank > impRank {
				addErr(fmt.Sprintf("%s.severity.overall_severity: cannot exceed demonstrated impact %q", base, f.Severity.Impact.Score))
			}
		}
		if f.Confidence == nil {
			addErr(fmt.Sprintf("%s: confirmed finding requires confidence", base))
		} else {
			if !confidenceScores[f.Confidence.Score] {
				addErr(fmt.Sprintf("%s.confidence.score: invalid value %q", base, f.Confidence.Score))
			}
			if !HasVisibleProse(f.Confidence.Reason) {
				addErr(fmt.Sprintf("%s.confidence.reason: must contain a visible character", base))
			}
		}

	case "needs_validation":
		if !HasVisibleProse(f.ClaimedRootCause) {
			addErr(fmt.Sprintf("%s.claimed_root_cause: must contain a visible character", base))
		}
		if len(f.Blockers) == 0 {
			addErr(fmt.Sprintf("%s.blockers: must have at least 1 item(s)", base))
		} else {
			seenB := make(map[string]bool)
			for idx, b := range f.Blockers {
				if !HasVisibleProse(b) {
					addErr(fmt.Sprintf("%s.blockers[%d]: must contain a visible character", base, idx))
				}
				if seenB[b] {
					addErr(fmt.Sprintf("%s.blockers: items must be unique; duplicate at index %d", base, idx))
				}
				seenB[b] = true
			}
		}
		hasLocal := f.ValidationPlan != nil && HasVisibleProse(f.ValidationPlan.Local)
		hasDep := f.ValidationPlan != nil && HasVisibleProse(f.ValidationPlan.Deployment)
		if !hasLocal && !hasDep {
			addErr(fmt.Sprintf("%s.validation_plan: requires at least one visible local or deployment plan", base))
		}

	case "rejected":
		if !HasVisibleProse(f.ClaimedRootCause) {
			addErr(fmt.Sprintf("%s.claimed_root_cause: must contain a visible character", base))
		}
		if !HasVisibleProse(f.Reason) {
			addErr(fmt.Sprintf("%s.reason: must contain a visible character", base))
		}
	}

	return errs
}
