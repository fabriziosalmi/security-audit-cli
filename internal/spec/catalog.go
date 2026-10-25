package spec

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed assets/*
var assetsFS embed.FS

// Block represents an extractable section from ATTACK-CLASSES.md or a companion file.
type Block struct {
	File    string `json:"file"`
	Name    string `json:"name"`
	Ref     string `json:"ref"`
	Kind    string `json:"kind"` // "ordinary_class", "companion_section", "companion_group", "companion_class"
	Content string `json:"content"`
}

// CompanionFile describes one embedded Markdown reference file and its parsed blocks.
type CompanionFile struct {
	File        string   `json:"file"`
	Title       string   `json:"title"`
	WhenToUse   string   `json:"when_to_use,omitempty"`
	BlockRefs   []string `json:"block_refs"`
	ClassBlocks []string `json:"class_blocks"`
}

// Catalog holds all parsed Markdown blocks and the report JSON schema.
type Catalog struct {
	Files      map[string]*CompanionFile
	Blocks     map[string]*Block
	FileOrder  []string
	SchemaRaw  string
	SchemaJSON map[string]any
}

var CompanionFilenames = []string{
	"ATTACK-CLASSES.md",
	"MEMORY-SAFETY-AND-BINARY.md",
	"AI-AND-LLM.md",
	"WEB-PROTOCOL-AND-AUTH.md",
	"CLIENT-SIDE.md",
	"SUPPLY-CHAIN-AND-RELEASE.md",
	"CLOUD-AND-DEPLOYMENT.md",
	"PROTOCOLS-RPC-AND-MESSAGING.md",
	"RESOURCE-EXHAUSTION-AND-AVAILABILITY.md",
	"DATA-ISOLATION-AND-LIFECYCLE.md",
	"DESKTOP-MOBILE-AND-LOCAL-IPC.md",
}

const PromotionProcedureBlock = `Artifact promotion procedure (trusted parent-side code only):
Reference only for you: the parent performs these steps; you never perform them.

Before execution, the parent opens and retains trusted, non-inheritable directory
descriptors for the agent's scratch/ and artifacts/ roots, and records an allowlist
of expected scratch-relative artifact files plus explicit per-file and cumulative
byte limits. Never pass those descriptors to the agent or sandbox. After the sandbox
and all its processes terminate, trusted parent-side code promotes each allowlisted
file separately:

1. Validate the declared relative path: reject absolute, empty, ` + "`.`" + `, ` + "`..`" + `, or
   symlinked components.
2. Walk each parent component from the retained scratch-root descriptor with
   no-follow directory-relative operations; never reopen by path.
3. Open the leaf no-follow and nonblocking.
4. Verify with ` + "`fstat`" + ` that it is a regular file with link count exactly one and
   within the recorded per-file and cumulative byte limits.
5. Enforce those limits again while reading from that descriptor.
6. Copy exactly the verified size, repeat ` + "`fstat`" + `, and reject a changed identity,
   type, link count, or size.
7. For the destination, walk every parent component from the retained
   artifacts-root descriptor with no-follow directory-relative operations; require
   each existing component to be a real directory, and create any missing directory
   exclusively before reopening and verifying it no-follow.
8. Create the leaf exclusively without following links, verify that the opened
   destination is a regular file with link count exactly one, and copy from the
   verified source descriptor without reopening either path.
9. Use equivalent race-safe APIs on non-POSIX systems.
10. Never recursively copy or glob scratch, extract an archive into artifacts, or
    open or promote a symlink, FIFO, socket, device, directory, hard-linked file,
    changing file, or file that exceeds its bound.
11. If any check is unavailable, cannot be enforced, or fails, discard the scratch
    entry; if it is decisive evidence, retain ` + "`needs_validation`" + ` with the exact
    promotion blocker.`

const CoreHuntingMethodBlock = `## Defensive vulnerability-finding method

Your goal is to find source-grounded security invariant failures and the smallest fix,
not to expand harm beyond the boundary result. Stay within source review and bounded local execution.
Do not contact deployed endpoints, provider APIs, registries, identity systems,
message brokers, shared services, or other users. Use local dummy data only.

READ THE CODE AT DEPTH. Follow each assigned input through parsing, identity,
authorization, normalization, state, derived copies, and the final sink. Read sibling,
legacy, batch, retry, cancellation, migration, and error paths that produce the same
effect. Compare sibling controls for equivalence, not only presence, and compare what
one component guarantees with what the next component assumes.

WORK FROM A CONCRETE INVARIANT:
1. Name the lower-trust principal and starting capability.
2. Name the accepted value, action, state transition, or resource selector.
3. Locate the control that should reject, bind, isolate, limit, or revoke it.
4. Trace the exact source path after that decision.
5. Stop at the smallest affected dummy record, wrong return value, process-integrity
   effect, or locally observable shared-resource effect.
6. State a source-level change and regression case that enforce the invariant.

DEPTH BOUND: trace only paths that can reach your assigned boundary or whose
guarantees that boundary relies on. Stop a line of investigation as soon as the
invariant is settled either way, and record the result in your structured output —
a covered, candidate, or blocked disposition, or an ` + "`uncovered`" + ` entry — instead of
continuing to search.

TEST SAD PATHS AND DISAGREEMENTS. Check absent, empty, zero, negative, maximum,
over-limit, duplicate, mixed encoding, stale, revoked, reordered, concurrent,
partially migrated, failed dependency, and rollback state only where the interface
accepts them. Compare canonicalization and units at every parser or policy handoff.
For multi-step issues, treat each output as a prerequisite and do not assume a later
boundary. If any prerequisite is not established, record a blocker.

When a proposed high or critical candidate reveals a reusable root cause, search paths
owned by the assigned coverage IDs for lexical, structural, and logical variants.
Consolidate the same root cause, but establish each variant's conditions and impact
independently. Do not investigate peer-owned units. Return a variant with no current
coverage unit as ` + "`uncovered`" + `.

USE THE NARROWEST LOCAL CHECK THAT SETTLES THE CLAIM. Target-controlled builds,
tests, processes, browsers, emulators, fuzzers, and fixture processing may run only
inside the parent-approved OS-enforced sandbox. It must disable external networking,
start from an empty allowlisted environment, expose target and tools read-only, permit
writes only to your scratch directory, and apply low CPU, memory, process, file-size,
disk, and wall-clock limits. Isolated loopback is allowed only for a local fixture.
If any control is unavailable, do not execute: return needs_validation with that exact
blocker. Prefer an existing unit test, minimal function harness, dummy-tenant service
call, small malformed fixture, deterministic race schedule, or locally rendered policy.
Do not install or fetch tools.

Record the exact input, command, limits, and minimum result. For the environment,
record only allowlisted variable names and safe non-secret values needed to reproduce
the check. Never capture the ambient environment, inherited variables, credentials,
authentication state, or unrelated host paths. The target-controlled process writes
only in scratch. After the sandbox and all its processes terminate, only trusted
parent-side code may promote predeclared scratch-relative files, following the
promotion procedure block included verbatim in this prompt. You and target code never
write retained artifacts. If promotion is unavailable or fails for decisive evidence,
return needs_validation with the exact promotion blocker.
Never stress availability, invoke a live target, use a real credential, publish an
artifact, or continue past the minimum observed effect.

A deployment, browser, provider, broker, OS, proxy, package, secret, or identity fact
outside source is not proof either way. If one such fact is decisive, return a
needs_validation record with the exact missing observation and safe owner-observed check.`

const CandidateGateBlock = `## Candidate gate

1. A candidate needs a complete repository-relative source trace and evidence for the
   claimed root cause, including the strongest source-visible control.
2. A proposed confirmed record needs a bounded local observed result, meaningful impact
   across a stated boundary, complete conditions, and no visible preventing layer.
3. Do not strengthen a crash into code execution, ordinary work into shared availability,
   or a same-principal action into privilege gain.
4. If a required fact is not source-visible or locally observable, use
   needs_validation. Name exact blockers; do not give it severity or speculative completion.
5. A missing best practice with no affected principal/resource is excluded or hardening,
   not a finding. A candidate disproved by source is not needs_validation.
6. Use the same source-derived fingerprint for the same root cause in every state.
   It must match ` + "`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`" + ` and must not include a line,
   wave, agent, severity, or verdict.
7. Return an empty candidate array when nothing survives these gates.`

// LoadCatalog parses all embedded assets into a deterministic Catalog.
func LoadCatalog() (*Catalog, error) {
	cat := &Catalog{
		Files:     make(map[string]*CompanionFile),
		Blocks:    make(map[string]*Block),
		FileOrder: append([]string(nil), CompanionFilenames...),
	}

	schemaBytes, err := assetsFS.ReadFile("assets/report-schema.json")
	if err != nil {
		return nil, fmt.Errorf("read report-schema.json: %w", err)
	}
	cat.SchemaRaw = string(schemaBytes)
	if err := json.Unmarshal(schemaBytes, &cat.SchemaJSON); err != nil {
		return nil, fmt.Errorf("parse report-schema.json: %w", err)
	}

	for _, filename := range CompanionFilenames {
		raw, err := assetsFS.ReadFile("assets/" + filename)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filename, err)
		}
		cf, blocks := parseMarkdownCompanion(filename, string(raw))
		cat.Files[filename] = cf
		for _, b := range blocks {
			cat.Blocks[b.Ref] = b
		}
	}
	return cat, nil
}

func parseMarkdownCompanion(filename, content string) (*CompanionFile, []*Block) {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	cf := &CompanionFile{
		File: filename,
	}
	var blocks []*Block

	isOrdinary := filename == "ATTACK-CLASSES.md"

	type marker struct {
		name string
		kind string
		line int
	}
	var markers []marker
	var whenStart, whenEnd int = -1, -1

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# ") && cf.Title == "" {
			cf.Title = strings.TrimSpace(strings.TrimPrefix(trimmed, "# "))
			continue
		}
		if strings.HasPrefix(trimmed, "#### When to use this file") {
			whenStart = i + 1
			continue
		}
		if whenStart != -1 && whenEnd == -1 && strings.HasPrefix(trimmed, "## ") {
			whenEnd = i
		}

		// Check ## Heading in companion files
		if !isOrdinary && strings.HasPrefix(trimmed, "## ") {
			heading := strings.TrimSpace(strings.TrimPrefix(trimmed, "## "))
			if idx := strings.Index(heading, " ("); idx != -1 {
				heading = strings.TrimSpace(heading[:idx])
			}
			kind := "companion_group"
			if heading == "Core discipline" || heading == "Universal moves" || heading == "Validation rules" {
				kind = "companion_section"
			}
			markers = append(markers, marker{name: heading, kind: kind, line: i})
			continue
		}

		// Check top-level bold block: **Name** or **Name** (subagent_type: `general`)
		if strings.HasPrefix(line, "**") {
			rest := line[2:]
			endBold := strings.Index(rest, "**")
			if endBold > 0 {
				name := rest[:endBold]
				after := strings.TrimSpace(rest[endBold+2:])
				// Ignore "**Important**:" note at bottom of ATTACK-CLASSES.md
				if name == "Important" || strings.HasPrefix(after, ":") {
					continue
				}
				kind := "companion_class"
				if isOrdinary {
					kind = "ordinary_class"
				}
				markers = append(markers, marker{name: name, kind: kind, line: i})
			}
		}
	}

	if whenStart != -1 {
		if whenEnd == -1 {
			whenEnd = len(lines)
		}
		cf.WhenToUse = strings.TrimSpace(strings.Join(lines[whenStart:whenEnd], "\n"))
	}

	for idx, m := range markers {
		endLine := len(lines)
		for nextIdx := idx + 1; nextIdx < len(markers); nextIdx++ {
			nextM := markers[nextIdx]
			if m.kind == "companion_group" {
				// A group extends until the next group or companion_section
				if nextM.kind == "companion_group" || nextM.kind == "companion_section" {
					endLine = nextM.line
					break
				}
			} else {
				endLine = nextM.line
				break
			}
		}
		blockText := strings.TrimSpace(strings.Join(lines[m.line:endLine], "\n"))
		// Strip trailing "**Important**:" paragraph from Obvious things if present? No, keep it in Obvious things!
		ref := filename + "#" + m.name
		b := &Block{
			File:    filename,
			Name:    m.name,
			Ref:     ref,
			Kind:    m.kind,
			Content: blockText,
		}
		blocks = append(blocks, b)
		cf.BlockRefs = append(cf.BlockRefs, ref)
		if m.kind == "ordinary_class" || m.kind == "companion_class" {
			cf.ClassBlocks = append(cf.ClassBlocks, ref)
		}
	}

	return cf, blocks
}

// SchemaBranches returns the confirmed, needs_validation, and rejected branches of report-schema.json.
func (c *Catalog) SchemaBranches(includeRejected bool) (string, error) {
	items, ok := c.SchemaJSON["items"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("invalid report-schema.json: missing items")
	}
	oneOf, ok := items["oneOf"].([]any)
	if !ok || len(oneOf) < 3 {
		return "", fmt.Errorf("invalid report-schema.json: expected 3 oneOf branches")
	}
	branches := oneOf[:2]
	if includeRejected {
		branches = oneOf[:3]
	}
	out, err := json.MarshalIndent(branches, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ExpandCompanionBlocks takes a list of companion class blocks and ensures their file's
// Core discipline, Universal moves, and Validation rules blocks are included in canonical order.
func (c *Catalog) ExpandCompanionBlocks(selected []string) []string {
	seen := make(map[string]bool)
	filesUsed := make(map[string]bool)
	var orderedFiles []string

	for _, ref := range selected {
		seen[ref] = true
		if parts := strings.SplitN(ref, "#", 2); len(parts) == 2 {
			f := parts[0]
			if f != "ATTACK-CLASSES.md" && !filesUsed[f] {
				filesUsed[f] = true
				orderedFiles = append(orderedFiles, f)
			}
		}
	}
	sort.Strings(orderedFiles)

	var result []string
	added := make(map[string]bool)
	add := func(r string) {
		if !added[r] && c.Blocks[r] != nil {
			added[r] = true
			result = append(result, r)
		}
	}

	for _, f := range orderedFiles {
		add(f + "#Core discipline")
		for _, ref := range selected {
			if strings.HasPrefix(ref, f+"#") &&
				!strings.HasSuffix(ref, "#Core discipline") &&
				!strings.HasSuffix(ref, "#Universal moves") &&
				!strings.HasSuffix(ref, "#Validation rules") {
				add(ref)
			}
		}
		add(f + "#Universal moves")
		add(f + "#Validation rules")
	}
	for _, ref := range selected {
		add(ref)
	}
	return result
}
