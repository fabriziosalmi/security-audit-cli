package spec

import (
	"strings"
	"testing"
)

func TestCatalogLoadAndExpand(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	if len(cat.Files) != 11 {
		t.Fatalf("expected 11 embedded files (ATTACK-CLASSES + 10 companions), got %d", len(cat.Files))
	}
	vb := cat.ValidBlockMap()
	if !vb["ATTACK-CLASSES.md#Injection"] {
		t.Fatalf("missing ATTACK-CLASSES.md#Injection")
	}

	expanded := cat.ExpandCompanionBlocks([]string{"WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF"})
	if len(expanded) != 4 {
		t.Fatalf("expected 4 blocks (Core discipline + selected + Universal moves + Validation rules), got %v", expanded)
	}
	if expanded[0] != "WEB-PROTOCOL-AND-AUTH.md#Core discipline" || expanded[3] != "WEB-PROTOCOL-AND-AUTH.md#Validation rules" {
		t.Fatalf("unexpected canonical ordering: %v", expanded)
	}

	s2, err := cat.SchemaBranches(false)
	if err != nil || !strings.Contains(s2, "confirmed") {
		t.Fatalf("SchemaBranches(false) failed: %v", err)
	}
	s3, err := cat.SchemaBranches(true)
	if err != nil || !strings.Contains(s3, "rejected") {
		t.Fatalf("SchemaBranches(true) failed: %v", err)
	}
}
