package store

import (
	"os"
	"strings"
	"testing"

	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

func TestRunStoreAtomicLifecycle(t *testing.T) {
	tmp := t.TempDir()
	st := New(tmp)

	// 1. Metadata roundtrip
	budget := 10
	meta := &RunMetadata{
		RunID:     "run-1",
		Repo:      "demo",
		Target:    tmp,
		Profile:   "standard",
		Budget:    &budget,
		RunStatus: "in_progress",
	}
	if err := st.SaveMetadata(meta); err != nil {
		t.Fatalf("SaveMetadata: %v", err)
	}
	loadedMeta, err := st.LoadMetadata()
	if err != nil {
		t.Fatalf("LoadMetadata: %v", err)
	}
	if loadedMeta.RunID != "run-1" || *loadedMeta.Budget != 10 {
		t.Fatalf("unexpected metadata: %+v", loadedMeta)
	}

	// 2. Architecture validation and word cap
	if _, _, err := st.SaveArchitecture("   "); err == nil {
		t.Fatalf("expected empty architecture prose to fail")
	}
	tooManyWords := strings.Repeat("word ", 1105)
	if _, _, err := st.SaveArchitecture(tooManyWords); err == nil {
		t.Fatalf("expected >1100 words architecture to fail")
	}
	archPath, wc, err := st.SaveArchitecture("# Arch\n\nValid summary prose.")
	if err != nil || wc != 5 || archPath == "" {
		t.Fatalf("SaveArchitecture failed: path=%q wc=%d err=%v", archPath, wc, err)
	}
	archBytes, err := st.LoadArchitecture()
	if err != nil || !strings.Contains(string(archBytes), "Valid summary prose.") {
		t.Fatalf("LoadArchitecture failed: %v", err)
	}

	// 3. Ledger & State roundtrip
	if err := st.SaveLedger([]validator.CoverageUnit{}); err != nil {
		t.Fatalf("SaveLedger: %v", err)
	}
	units, err := st.LoadLedger()
	if err != nil || len(units) != 0 {
		t.Fatalf("LoadLedger: %v", err)
	}

	state := &InternalState{CurrentWave: 2}
	if err := st.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	loadedState, err := st.LoadState()
	if err != nil || loadedState.CurrentWave != 2 || loadedState.Agents == nil || loadedState.Candidates == nil {
		t.Fatalf("LoadState: %+v err=%v", loadedState, err)
	}

	// 4. Findings missing file returns empty slice
	fList, err := st.LoadFindings()
	if err != nil || len(fList) != 0 {
		t.Fatalf("expected empty findings when file does not exist, got %v, %v", fList, err)
	}

	// Verify file permissions are 0600
	info, err := os.Stat(st.MetadataPath())
	if err != nil {
		t.Fatalf("stat metadata: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}
