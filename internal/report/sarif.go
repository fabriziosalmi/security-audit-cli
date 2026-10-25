package report

import (
	"encoding/json"

	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// BuildSARIF generates a deterministic SARIF 2.1.0 document for confirmed findings.
func BuildSARIF(confirmed []validator.Finding) ([]byte, error) {
	rules := make([]map[string]any, 0, len(confirmed))
	results := make([]map[string]any, 0, len(confirmed))

	for _, f := range confirmed {
		level := "warning"
		if f.Severity.OverallSeverity == "high" || f.Severity.OverallSeverity == "critical" {
			level = "error"
		} else if f.Severity.OverallSeverity == "low" || f.Severity.OverallSeverity == "informational" {
			level = "note"
		}
		sink := f.Trace[len(f.Trace)-1]
		rules = append(rules, map[string]any{
			"id":               f.Fingerprint,
			"shortDescription": map[string]any{"text": f.Title},
			"fullDescription":  map[string]any{"text": f.Description},
			"help":             map[string]any{"text": f.Remediation.Strategy},
		})
		results = append(results, map[string]any{
			"ruleId":  f.Fingerprint,
			"level":   level,
			"message": map[string]any{"text": f.RootCause + " — Observed: " + f.Execution.ObservedResult},
			"locations": []map[string]any{
				{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{"uri": sink.File},
						"region":           map[string]any{"startLine": sink.Line},
					},
				},
			},
		})
	}

	sarifDoc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":           "sec-audit",
						"informationUri": "https://github.com/fabriziosalmi/security-audit-cli",
						"rules":          rules,
					},
				},
				"results": results,
			},
		},
	}
	out, err := json.MarshalIndent(sarifDoc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
