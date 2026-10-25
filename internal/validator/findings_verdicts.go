package validator

import "fmt"

func validateTrace(trace []TraceEntry, rawTrace any, base, targetDir string, addErr func(string)) {
	rawSlice, _ := rawTrace.([]any)
	if len(trace) == 0 {
		addErr(fmt.Sprintf("%s.trace: must have at least 1 item(s), got 0", base))
		return
	}
	seenTrace := make(map[string]bool)
	for idx, t := range trace {
		tbase := fmt.Sprintf("%s.trace[%d]", base, idx)
		if idx < len(rawSlice) {
			checkAdditionalProps(rawSlice[idx], traceAllowedFields, tbase, addErr)
		}
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
	if len(trace) == 1 {
		if trace[0].Kind != "entrypoint" && trace[0].Kind != "sink" {
			addErr(fmt.Sprintf("%s.trace[0].kind: a one-line trace must be \"entrypoint\" or \"sink\"", base))
		}
		return
	}
	last := len(trace) - 1
	if trace[0].Kind != "entrypoint" {
		addErr(fmt.Sprintf("%s.trace[0].kind: must be \"entrypoint\", got %q", base, trace[0].Kind))
	}
	if trace[last].Kind != "sink" {
		addErr(fmt.Sprintf("%s.trace[%d].kind: must be \"sink\", got %q", base, last, trace[last].Kind))
	}
	for idx := 1; idx < last; idx++ {
		if trace[idx].Kind != "propagation" {
			addErr(fmt.Sprintf("%s.trace[%d].kind: must be \"propagation\", got %q", base, idx, trace[idx].Kind))
		}
	}
}

func validateEvidence(evidence []EvidenceEntry, rawEvidence any, base, targetDir string, addErr func(string)) {
	rawSlice, _ := rawEvidence.([]any)
	if len(evidence) == 0 {
		addErr(fmt.Sprintf("%s.evidence: must have at least 1 item(s), got 0", base))
		return
	}
	seenEv := make(map[string]bool)
	for idx, ev := range evidence {
		ebase := fmt.Sprintf("%s.evidence[%d]", base, idx)
		if idx < len(rawSlice) {
			checkAdditionalProps(rawSlice[idx], evidenceAllowedFields, ebase, addErr)
		}
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

func validateConfirmedBranch(f Finding, rawItem map[string]any, base, targetDir string, addErr func(string)) {
	if !HasVisibleProse(f.RootCause) {
		addErr(fmt.Sprintf("%s.root_cause: must contain a visible character", base))
	}
	if !HasVisibleProse(f.IntendedBehavior) {
		addErr(fmt.Sprintf("%s.intended_behavior: must contain a visible character", base))
	}
	rawConds, _ := rawItem["conditions"].([]any)
	seenCond := make(map[string]bool)
	for idx, c := range f.Conditions {
		cbase := fmt.Sprintf("%s.conditions[%d]", base, idx)
		if idx < len(rawConds) {
			checkAdditionalProps(rawConds[idx], conditionAllowedFields, cbase, addErr)
		}
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
		checkAdditionalProps(rawItem["execution"], executionAllowedFields, base+".execution", addErr)
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
		checkAdditionalProps(rawItem["remediation"], remediationAllowed, base+".remediation", addErr)
		var rawCC []any
		if remMap, ok := rawItem["remediation"].(map[string]any); ok {
			rawCC, _ = remMap["code_changes"].([]any)
		}
		for idx, cc := range f.Remediation.CodeChanges {
			ccBase := fmt.Sprintf("%s.remediation.code_changes[%d]", base, idx)
			if idx < len(rawCC) {
				checkAdditionalProps(rawCC[idx], codeChangeAllowed, ccBase, addErr)
			}
			if !IsSafeRelativePath(cc.FileName) {
				addErr(fmt.Sprintf("%s.file_name: must be a safe repository-relative source path", ccBase))
			} else if targetDir != "" {
				if err := VerifyRepoFileAndLine(targetDir, cc.FileName, 0); err != nil {
					addErr(fmt.Sprintf("%s.file_name: %v", ccBase, err))
				}
			}
		}
	}

	if f.Severity == nil {
		addErr(fmt.Sprintf("%s: confirmed finding requires severity", base))
	} else {
		checkAdditionalProps(rawItem["severity"], severityAllowed, base+".severity", addErr)
		if sevMap, ok := rawItem["severity"].(map[string]any); ok {
			checkAdditionalProps(sevMap["likelihood"], scoreReasonAllowed, base+".severity.likelihood", addErr)
			checkAdditionalProps(sevMap["impact"], scoreReasonAllowed, base+".severity.impact", addErr)
		}
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
		checkAdditionalProps(rawItem["confidence"], scoreReasonAllowed, base+".confidence", addErr)
		if !confidenceScores[f.Confidence.Score] {
			addErr(fmt.Sprintf("%s.confidence.score: invalid value %q", base, f.Confidence.Score))
		}
		if !HasVisibleProse(f.Confidence.Reason) {
			addErr(fmt.Sprintf("%s.confidence.reason: must contain a visible character", base))
		}
	}
}

func validateNeedsValidationBranch(f Finding, rawItem map[string]any, base string, addErr func(string)) {
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
	checkAdditionalProps(rawItem["validation_plan"], validationPlanAllowed, base+".validation_plan", addErr)
	hasLocal := f.ValidationPlan != nil && HasVisibleProse(f.ValidationPlan.Local)
	hasDep := f.ValidationPlan != nil && HasVisibleProse(f.ValidationPlan.Deployment)
	if !hasLocal && !hasDep {
		addErr(fmt.Sprintf("%s.validation_plan: requires at least one visible local or deployment plan", base))
	}
}

func validateRejectedBranch(f Finding, base string, addErr func(string)) {
	if !HasVisibleProse(f.ClaimedRootCause) {
		addErr(fmt.Sprintf("%s.claimed_root_cause: must contain a visible character", base))
	}
	if !HasVisibleProse(f.Reason) {
		addErr(fmt.Sprintf("%s.reason: must contain a visible character", base))
	}
}
