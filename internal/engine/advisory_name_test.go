package engine

import (
	"path/filepath"
	"testing"
)

func TestAdvisoryFileNameIsOneFileInsideAdvisories(t *testing.T) {
	if got := advisoryFileName("FIND-A.1_x"); got != "GHSA-FIND-A.1_x.md" {
		t.Fatalf("a plain fingerprint was renamed: %s", got)
	}
	seen := map[string]string{}
	for _, fp := range []string{"a/b", "a_b", "a:b", "x/../../../etc/passwd", "lmget/oci-token", "a@b+c"} {
		name := advisoryFileName(fp)
		if filepath.Base(name) != name || filepath.Dir(filepath.Join("advisories", name)) != "advisories" {
			t.Fatalf("%q -> %q is not one file inside advisories/", fp, name)
		}
		if other, dup := seen[name]; dup {
			t.Fatalf("%q and %q share %s", fp, other, name)
		}
		seen[name] = fp
	}
}
