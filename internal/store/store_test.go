package store

import (
	"os"
	"path/filepath"
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

	// 5. SyncFindings + LoadFindings roundtrip
	_ = os.WriteFile(filepath.Join(tmp, "auth.go"), []byte("package main\nfunc Verify() {}\n"), 0o644)
	validFinding := validator.Finding{
		Verdict:          "rejected",
		Fingerprint:      "FIND-0001",
		Title:            "Refuted claim",
		Description:      "Checked token signature",
		ClaimedRootCause: "None",
		Trace:            []validator.TraceEntry{{Kind: "sink", File: "auth.go", Line: 2, Scope: "Verify", Description: "Checks sig"}},
		Evidence:         []validator.EvidenceEntry{{File: "auth.go", Line: 2, Description: "Signature verified"}},
		Reason:           "Signature check is mandatory",
	}
	state.Candidates = map[string]*CandidateEnvelope{
		"FIND-0002": {
			Fingerprint: "FIND-0002",
			FinalRecord: &validator.Finding{
				Verdict:          "rejected",
				Fingerprint:      "FIND-0002",
				Title:            "Second",
				Description:      "Second",
				ClaimedRootCause: "None",
				Trace:            []validator.TraceEntry{{Kind: "sink", File: "auth.go", Line: 2, Scope: "Verify", Description: "Checks sig"}},
				Evidence:         []validator.EvidenceEntry{{File: "auth.go", Line: 2, Description: "Signature verified"}},
				Reason:           "Signature check is mandatory",
			},
		},
		"FIND-0001": {
			Fingerprint: "FIND-0001",
			FinalRecord: &validFinding,
		},
	}
	if err := st.SyncFindings(tmp, state); err != nil {
		t.Fatalf("SyncFindings failed: %v", err)
	}
	loadedFindings, err := st.LoadFindings()
	if err != nil || len(loadedFindings) != 2 || loadedFindings[0].Fingerprint != "FIND-0001" {
		t.Fatalf("LoadFindings after SyncFindings failed: %+v err=%v", loadedFindings, err)
	}

	if err := WriteFileAtomic(filepath.Join(tmp, "missing-dir", "f.json"), []byte("{}"), 0o600); err == nil {
		t.Fatalf("expected WriteFileAtomic in missing directory to fail")
	}

	// Corrupt JSON parse error branches
	_ = os.WriteFile(st.MetadataPath(), []byte("{bad"), 0o600)
	if _, err := st.LoadMetadata(); err == nil {
		t.Fatalf("expected LoadMetadata parse error")
	}
	_ = os.WriteFile(st.LedgerPath(), []byte("{bad"), 0o600)
	if _, err := st.LoadLedger(); err == nil {
		t.Fatalf("expected LoadLedger parse error")
	}
	_ = os.WriteFile(st.FindingsPath(), []byte("{bad"), 0o600)
	if _, err := st.LoadFindings(); err == nil {
		t.Fatalf("expected LoadFindings parse error")
	}
	_ = os.WriteFile(st.StatePath(), []byte("{bad"), 0o600)
	if _, err := st.LoadState(); err == nil {
		t.Fatalf("expected LoadState parse error")
	}

	// Invalid finding in SyncFindings must return error
	badFinding := validFinding
	badFinding.Reason = ""
	state.Candidates["FIND-0001"].FinalRecord = &badFinding
	if err := st.SyncFindings(tmp, state); err == nil {
		t.Fatalf("expected SyncFindings to fail on invalid finding")
	}

	// Error paths on nonexistent store directory
	badStore := New(filepath.Join(tmp, "nonexistent"))
	if _, err := badStore.LoadMetadata(); err == nil {
		t.Fatalf("expected LoadMetadata error")
	}
	if _, err := badStore.LoadLedger(); err == nil {
		t.Fatalf("expected LoadLedger error")
	}
	if _, err := badStore.LoadState(); err == nil {
		t.Fatalf("expected LoadState error")
	}
	if _, err := badStore.LoadArchitecture(); err == nil {
		t.Fatalf("expected LoadArchitecture error")
	}
}
