package main

import (
	"archive/zip"
	"path/filepath"
	"testing"
)

func TestBuildDeterministicVSIX(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sec-audit.vsix")
	extDir := filepath.Join("..")
	if err := buildVSIX(extDir, out); err != nil {
		t.Fatalf("buildVSIX failed: %v", err)
	}
	r, err := zip.OpenReader(out)
	if err != nil {
		t.Fatalf("open vsix zip: %v", err)
	}
	defer r.Close()

	want := map[string]bool{
		"[Content_Types].xml":       false,
		"extension.vsixmanifest":    false,
		"extension/package.json":    false,
		"extension/extension.js":    false,
		"extension/README.md":       false,
		"extension/media/icon.svg":  false,
	}
	for _, f := range r.File {
		if _, ok := want[f.Name]; ok {
			want[f.Name] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Fatalf("missing required VSIX entry %q", k)
		}
	}
}
