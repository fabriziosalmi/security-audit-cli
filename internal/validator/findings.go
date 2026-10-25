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
	traceAllowedFields     = map[string]bool{"kind": true, "file": true, "line": true, "scope": true, "description": true}
	evidenceAllowedFields  = map[string]bool{"file": true, "line": true, "description": true}
	conditionAllowedFields = map[string]bool{"kind": true, "description": true}
	executionAllowedFields = map[string]bool{"attacker_perspective": true, "payloads": true, "instructions": true, "observed_result": true}
	remediationAllowed     = map[string]bool{"strategy": true, "code_changes": true}
	codeChangeAllowed      = map[string]bool{"file_name": true, "fixed_code": true}
	severityAllowed        = map[string]bool{"likelihood": true, "impact": true, "overall_severity": true}
	scoreReasonAllowed     = map[string]bool{"score": true, "reason": true}
	validationPlanAllowed  = map[string]bool{"local": true, "deployment": true}
)

// ValidateFindingsFile reads and validates findings.json from disk.
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

	if err := ValidateJSONPreflight(raw); err != nil {
		addErr(err.Error())
		return errs
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
		required = []string{
			verdictField, "fingerprint", "title", "description", "root_cause",
			"intended_behavior", "trace", "evidence", "conditions", "execution",
			"remediation", "severity", "confidence",
		}
	case "needs_validation":
		allowed = needsValidationAllowed
		required = []string{
			verdictField, "fingerprint", "title", "description",
			"claimed_root_cause", "trace", "evidence", "blockers", "validation_plan",
		}
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

	validateTrace(f.Trace, rawItem["trace"], base, targetDir, addErr)
	validateEvidence(f.Evidence, rawItem["evidence"], base, targetDir, addErr)

	switch verdict {
	case "confirmed":
		validateConfirmedBranch(f, rawItem, base, targetDir, addErr)
	case "needs_validation":
		validateNeedsValidationBranch(f, rawItem, base, addErr)
	case "rejected":
		validateRejectedBranch(f, base, addErr)
	}

	return errs
}

func checkAdditionalProps(raw any, allowed map[string]bool, loc string, addErr func(string)) {
	m, ok := raw.(map[string]any)
	if !ok {
		return
	}
	for k := range m {
		if !allowed[k] {
			addErr(fmt.Sprintf("%s: unexpected field %q", loc, k))
		}
	}
}
