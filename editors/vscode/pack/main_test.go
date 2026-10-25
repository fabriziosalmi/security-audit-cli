package main

import (
	"archive/zip"
	"encoding/xml"
	"io"
	"os"
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
		"[Content_Types].xml":      false,
		"extension.vsixmanifest":   false,
		"extension/package.json":   false,
		"extension/extension.js":   false,
		"extension/README.md":      false,
		"extension/media/icon.svg": false,
	}
	for _, f := range r.File {
		if _, ok := want[f.Name]; ok {
			want[f.Name] = true
		}
		if f.Name == "extension.vsixmanifest" {
			rc, oerr := f.Open()
			if oerr != nil {
				t.Fatalf("open extension.vsixmanifest: %v", oerr)
			}
			var anyXML struct{}
			if derr := xml.NewDecoder(rc).Decode(&anyXML); derr != nil && derr != io.EOF {
				t.Fatalf("extension.vsixmanifest is not valid XML: %v", derr)
			}
			_ = rc.Close()
		}
	}
	for k, found := range want {
		if !found {
			t.Fatalf("missing required VSIX entry %q", k)
		}
	}

	// Break-test FIND-0011: symlinked package.json must be rejected by ReadFileNoFollow
	symDir := t.TempDir()
	_ = os.Symlink(filepath.Join(extDir, "package.json"), filepath.Join(symDir, "package.json"))
	if err := buildVSIX(symDir, filepath.Join(t.TempDir(), "bad.vsix")); err == nil {
		t.Fatalf("expected buildVSIX to reject symlinked package.json")
	}
}
