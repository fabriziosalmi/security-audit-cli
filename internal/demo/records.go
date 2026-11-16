package demo

import (
	"fmt"
	"strings"

	"github.com/fabriziosalmi/security-audit-cli/internal/engine"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// lineOf returns the 1-based line of the only line in content that contains
// needle. Citations are computed from the fixture so they cannot go stale.
func lineOf(content, needle string) int {
	found := 0
	for i, l := range strings.Split(content, "\n") {
		if strings.Contains(l, needle) {
			if found != 0 {
				panic(fmt.Sprintf("demo fixture: %q matches more than one line", needle))
			}
			found = i + 1
		}
	}
	if found == 0 {
		panic(fmt.Sprintf("demo fixture: %q not found", needle))
	}
	return found
}

func at(file, content, needle, kind, scope, desc string) map[string]any {
	return map[string]any{"kind": kind, "file": file, "line": lineOf(content, needle), "scope": scope, "description": desc}
}

func ev(file, content, needle, desc string) map[string]any {
	return map[string]any{"file": file, "line": lineOf(content, needle), "description": desc}
}

func seedUnits() []engine.SeedUnitInput {
	unit := func(surface, boundary, block string) engine.SeedUnitInput {
		b := block
		return engine.SeedUnitInput{
			CanonicalRefs: validator.CanonicalRefs{
				Surface: mainPath + "#" + surface, Boundary: handlerPath + "#" + boundary,
				Subsystem: "internal/notes", AttackClass: block,
			},
			Surface:                  surface,
			Boundary:                 boundary,
			Subsystem:                "internal/notes",
			AttackClass:              block,
			StartingPaths:            []string{mainPath, handlerPath},
			OrdinaryAttackClassBlock: &b,
			SelectedCompanionBlocks:  []string{},
			ExcludedBlocks:           []validator.ExcludedBlock{},
		}
	}
	return []engine.SeedUnitInput{
		unit("GET /notes/{id}", "Handler.Get owner binding", "ATTACK-CLASSES.md#Access control"),
		unit("GET /export", "Handler.Export ExportDir confinement", "ATTACK-CLASSES.md#Resource and file handling"),
		unit("GET /search", "Handler.Search query construction", "ATTACK-CLASSES.md#Injection"),
	}
}

func severity(likelihood, impact, overall, impactReason string) map[string]any {
	return map[string]any{
		"likelihood":       map[string]any{"score": likelihood, "reason": "Any logged-in user can send the request"},
		"impact":           map[string]any{"score": impact, "reason": impactReason},
		"overall_severity": overall,
	}
}

func idorCandidate() map[string]any {
	return map[string]any{
		"proposed_verdict":  "confirmed",
		"fingerprint":       fpIDOR,
		"title":             "Any user can read any note by id",
		"description":       "GET /notes/{id} loads the note and its owner, then returns the body without comparing the owner to the caller.",
		"root_cause":        "Handler.Get reads the owner column but never checks it against auth.CurrentUser.",
		"intended_behavior": "A note is returned only to its owner; other callers get 404.",
		"trace": []map[string]any{
			at(mainPath, fixtureMain, `"GET /notes/{id}"`, "entrypoint", "main", "Route registered for authenticated note reads"),
			at(handlerPath, fixtureHandler, `id := r.PathValue("id")`, "propagation", "Handler.Get", "Note id taken from the URL"),
			at(handlerPath, fixtureHandler, `h.DB.QueryRow(`, "propagation", "Handler.Get", "Row loaded by id only"),
			at(handlerPath, fixtureHandler, `"id": id, "body": body`, "sink", "Handler.Get", "Body written to the response"),
		},
		"evidence": []map[string]any{
			ev(handlerPath, fixtureHandler, `var owner, body string`, "owner is scanned and then never read"),
		},
		"conditions": []map[string]any{
			{"kind": "authentication_level", "description": "Any authenticated user"},
		},
		"execution": map[string]any{
			"attacker_perspective": "Authenticated user alice requesting a note owned by bob",
			"payloads":             []string{"GET /notes/42 with alice's session cookie"},
			"instructions":         []string{"Log in as alice", "Request a note id that belongs to bob"},
			"observed_result":      "The response contains bob's note body",
		},
		"remediation": map[string]any{
			"strategy": "Compare owner with the caller and return 404 on mismatch, or add owner = ? to the query.",
			"code_changes": []map[string]any{{
				"file_name":  handlerPath,
				"fixed_code": "row := h.DB.QueryRow(\"SELECT body FROM notes WHERE id = ? AND owner = ?\", id, user)",
			}},
		},
		"severity":   severity("high", "medium", "medium", "Reads other users' notes, no write access"),
		"confidence": map[string]any{"score": "high", "reason": "Reproduced against a local build"},
	}
}

func traversalCandidate() map[string]any {
	return map[string]any{
		"proposed_verdict": "confirmed",
		"fingerprint":      fpTraversal,
		"title":            "Export reads any file the server can read",
		"description":      "GET /export joins the name query parameter onto ExportDir; ../ segments leave the directory.",
		"root_cause": "filepath.Join cleans ../ segments, so a relative name can resolve outside ExportDir, " +
			"and nothing checks the result.",
		"intended_behavior": "Export only serves files that resolve inside ExportDir.",
		"trace": []map[string]any{
			at(mainPath, fixtureMain, `"GET /export"`, "entrypoint", "main", "Route registered for exports"),
			at(handlerPath, fixtureHandler, `name := r.URL.Query().Get("name")`,
				"propagation", "Handler.Export", "File name taken from the query string"),
			at(handlerPath, fixtureHandler, `os.ReadFile(filepath.Join(h.ExportDir, name))`, "sink", "Handler.Export", "Joined path read from disk"),
		},
		"evidence": []map[string]any{
			ev(handlerPath, fixtureHandler, `os.ReadFile(filepath.Join(h.ExportDir, name))`, "No containment check between Join and ReadFile"),
		},
		"conditions": []map[string]any{
			{"kind": "authentication_level", "description": "Any authenticated user"},
		},
		"execution": map[string]any{
			"attacker_perspective": "Authenticated user alice",
			"payloads":             []string{"GET /export?name=../../../../etc/hostname"},
			"instructions":         []string{"Log in as alice", "Request an export name with ../ segments"},
			"observed_result":      "The response contains the server's /etc/hostname",
		},
		"remediation": map[string]any{
			"strategy": "Open exports through os.OpenRoot(h.ExportDir) so the kernel refuses paths that leave it.",
			"code_changes": []map[string]any{{
				"file_name":  handlerPath,
				"fixed_code": "root, err := os.OpenRoot(h.ExportDir)\nif err != nil { ... }\ndefer root.Close()\nf, err := root.Open(name)",
			}},
		},
		"severity":   severity("high", "high", "high", "Reads any file the service account can read, including credentials"),
		"confidence": map[string]any{"score": "high", "reason": "Reproduced against a local build"},
	}
}

func sqliCandidate() map[string]any {
	return map[string]any{
		"proposed_verdict":  "confirmed",
		"fingerprint":       fpSQLi,
		"title":             "SQL injection in search",
		"description":       "The q parameter is concatenated with % wildcards and passed to the search query.",
		"root_cause":        "User input reaches DB.Query in Handler.Search.",
		"intended_behavior": "Search input is never interpreted as SQL.",
		"trace": []map[string]any{
			at(mainPath, fixtureMain, `"GET /search"`, "entrypoint", "main", "Route registered for search"),
			at(handlerPath, fixtureHandler, `term := r.URL.Query().Get("q")`,
				"propagation", "Handler.Search", "Search term from the query string"),
			at(handlerPath, fixtureHandler, `pattern := "%" + term + "%"`,
				"propagation", "Handler.Search", "Term concatenated into the LIKE pattern"),
			at(handlerPath, fixtureHandler, `h.DB.Query("SELECT id FROM notes WHERE owner = ?`,
				"sink", "Handler.Search", "Pattern passed to the query"),
		},
		"evidence": []map[string]any{
			ev(handlerPath, fixtureHandler, `pattern := "%" + term + "%"`, "User input concatenated just before a SQL query"),
		},
		"conditions": []map[string]any{
			{"kind": "authentication_level", "description": "Any caller"},
		},
		"execution": map[string]any{
			"attacker_perspective": "Any caller",
			"payloads":             []string{"GET /search?q=' OR 1=1 --"},
			"instructions":         []string{"Send the payload as q"},
			"observed_result":      "Expected every note to be returned",
		},
		"remediation": map[string]any{"strategy": "Use placeholders for every user-controlled value."},
		"severity":    severity("high", "high", "high", "Would expose every note"),
		"confidence":  map[string]any{"score": "low", "reason": "Pattern match only, not reproduced"},
	}
}

func rejectedSQLiRecord() map[string]any {
	c := sqliCandidate()
	return map[string]any{
		"verdict":            "rejected",
		"fingerprint":        fpSQLi,
		"title":              c["title"],
		"description":        c["description"],
		"claimed_root_cause": c["root_cause"],
		"trace":              c["trace"],
		"evidence":           c["evidence"],
		"reason": "The concatenation builds the bound argument, not the SQL text: both values go through ? placeholders, " +
			"so the driver never parses q as SQL. The payload returned no extra rows locally.",
	}
}

func confirmedRecord(candidate map[string]any) map[string]any {
	rec := make(map[string]any, len(candidate))
	for k, v := range candidate {
		if k != "proposed_verdict" {
			rec[k] = v
		}
	}
	rec["verdict"] = "confirmed"
	return rec
}

func hunterResult(cids []string, artifact string) engine.HunterStructuredResult {
	fps := []string{fpIDOR, fpTraversal, fpSQLi}
	checks := []string{
		"Get returns a note only to its owner",
		"Export never reads outside ExportDir",
		"Search input never becomes SQL text",
	}
	// cids come back from ledger-seed sorted by coverage_id; map them back to
	// their surface through the same derivation the engine uses.
	byCID := map[string]int{}
	for i, u := range seedUnits() {
		if id, err := validator.DeriveCoverageID(u.CanonicalRefs); err == nil {
			byCID[id] = i
		}
	}
	units := make([]engine.HunterUnitResult, 0, len(cids))
	for _, cid := range cids {
		i := byCID[cid]
		a := artifact
		units = append(units, engine.HunterUnitResult{
			CoverageID:    cid,
			Disposition:   "candidate",
			ReviewedPaths: []string{mainPath, handlerPath},
			Checks: []validator.LocalCheck{{
				AgentID:       hunterID,
				ReviewedPaths: []string{mainPath, handlerPath},
				Invariant:     checks[i],
				Method:        "local",
				Result:        "Violated in a local build, see the promoted output",
				Artifact:      &a,
			}},
			CandidateFingerprints: []string{fps[i]},
			Unresolved:            []string{},
		})
	}
	return engine.HunterStructuredResult{
		Units:      units,
		Candidates: []map[string]any{idorCandidate(), traversalCandidate(), sqliCandidate()},
		Hardening:  []string{"Set HttpOnly, Secure and SameSite on the session cookie."},
	}
}
