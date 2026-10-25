package spec

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
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

var loadCatalogOnce = sync.OnceValues(func() (*Catalog, error) {
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
})

// LoadCatalog returns the immutable embedded Catalog (parsed once via sync.OnceValues).
func LoadCatalog() (*Catalog, error) {
	return loadCatalogOnce()
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

		if strings.HasPrefix(line, "**") {
			rest := line[2:]
			endBold := strings.Index(rest, "**")
			if endBold > 0 {
				name := rest[:endBold]
				after := strings.TrimSpace(rest[endBold+2:])
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

// ValidBlockMap returns a set of all valid canonical block references in the catalog.
func (c *Catalog) ValidBlockMap() map[string]bool {
	m := make(map[string]bool, len(c.Blocks))
	for k := range c.Blocks {
		m[k] = true
	}
	return m
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
