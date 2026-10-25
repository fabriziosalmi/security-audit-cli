package promote

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPromoteAllowlistAndBreakTests(t *testing.T) {
	outDir := t.TempDir()
	agentID := "hunter-1"
	scratch := filepath.Join(outDir, "agents", agentID, "scratch")
	artifacts := filepath.Join(outDir, "agents", agentID, "artifacts")
	if err := os.MkdirAll(filepath.Join(scratch, "sub", "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}

	// Valid regular files in nested directories + default limits (0, 0)
	validPath := filepath.Join(scratch, "sub", "deep", "proof.txt")
	if err := os.WriteFile(validPath, []byte("verified evidence\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secondPath := filepath.Join(scratch, "second.txt")
	if err := os.WriteFile(secondPath, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}

	promoted, err := PromoteAllowlist(outDir, agentID, []string{"sub/deep/proof.txt"}, 0, 0)
	if err != nil || len(promoted) != 1 || !promoted[0].Promoted {
		t.Fatalf("PromoteAllowlist failed: %+v err=%v", promoted, err)
	}
	if promoted[0].ArtifactPath != "agents/hunter-1/artifacts/sub/deep/proof.txt" || promoted[0].Bytes != 18 {
		t.Fatalf("unexpected promoted metadata: %+v", promoted[0])
	}

	// Promote a second file in the same existing nested directory (covers existing destination directory branch)
	validPath2 := filepath.Join(scratch, "sub", "deep", "proof2.txt")
	_ = os.WriteFile(validPath2, []byte("second proof\n"), 0o600)
	promoted2, err := PromoteAllowlist(outDir, agentID, []string{"sub/deep/proof2.txt"}, 0, 0)
	if err != nil || len(promoted2) != 1 || !promoted2[0].Promoted {
		t.Fatalf("PromoteAllowlist second nested file failed: %+v err=%v", promoted2, err)
	}

	// Break-test 0: Re-promoting an already promoted file must be blocked by exclusive create (O_EXCL)
	dupProm, err := PromoteAllowlist(outDir, agentID, []string{"sub/deep/proof.txt"}, 0, 0)
	if err != nil || len(dupProm) != 1 || dupProm[0].Promoted {
		t.Fatalf("expected duplicate promotion to fail exclusive create, got %+v", dupProm)
	}

	// Break-test 1: Symlink leaf and symlink parent directory inside scratch must be rejected
	symPath := filepath.Join(scratch, "evil-link.txt")
	_ = os.Symlink(validPath, symPath)
	resSym, err := PromoteAllowlist(outDir, agentID, []string{"evil-link.txt"}, 1024, 4096)
	if err != nil || len(resSym) != 1 || resSym[0].Promoted || resSym[0].Blocker == "" {
		t.Fatalf("expected symlink leaf promotion to be blocked, got %+v err=%v", resSym, err)
	}
	symParent := filepath.Join(scratch, "symparent")
	_ = os.Symlink(filepath.Join(scratch, "sub"), symParent)
	resSymParent, err := PromoteAllowlist(outDir, agentID, []string{"symparent/deep/proof.txt"}, 1024, 4096)
	if err != nil || len(resSymParent) != 1 || resSymParent[0].Promoted {
		t.Fatalf("expected symlink parent promotion to be blocked, got %+v", resSymParent)
	}

	// Break-test 2: Hardlink (nlink > 1) must be rejected
	hardPath := filepath.Join(scratch, "hardlink.txt")
	if err := os.Link(validPath, hardPath); err == nil {
		resHard, perr := PromoteAllowlist(outDir, agentID, []string{"hardlink.txt"}, 1024, 4096)
		if perr != nil || len(resHard) != 1 || resHard[0].Promoted || !strings.Contains(resHard[0].Blocker, "link count") {
			t.Fatalf("expected hardlink promotion to be blocked with link count error, got %+v err=%v", resHard, perr)
		}
		_ = os.Remove(hardPath)
	}

	// Break-test 3: Per-file byte cap and cumulative byte cap exceeded
	resCap, err := PromoteAllowlist(outDir, agentID, []string{"second.txt"}, 5, 4096)
	if err != nil || len(resCap) != 1 || resCap[0].Promoted || !strings.Contains(resCap[0].Blocker, "exceeds") {
		t.Fatalf("expected per-file byte limit to block promotion, got %+v err=%v", resCap, err)
	}
	resTotalCap, err := PromoteAllowlist(outDir, agentID, []string{"second.txt"}, 100, 5)
	if err != nil || len(resTotalCap) != 1 || resTotalCap[0].Promoted || !strings.Contains(resTotalCap[0].Blocker, "cumulative") {
		t.Fatalf("expected cumulative byte limit to block promotion, got %+v err=%v", resTotalCap, err)
	}

	// Break-test 4: Invalid agent ID, missing scratch dir, path traversal, or binary/NUL content
	nulPath := filepath.Join(scratch, "binary.bin")
	_ = os.WriteFile(nulPath, []byte("text\x00with-nul"), 0o600)
	resNul, err := PromoteAllowlist(outDir, agentID, []string{"binary.bin"}, 1024, 4096)
	if err != nil || len(resNul) != 1 || resNul[0].Promoted || !strings.Contains(resNul[0].Blocker, "UTF-8") {
		t.Fatalf("expected NUL-byte file promotion to be blocked, got %+v err=%v", resNul, err)
	}
	if _, err := PromoteAllowlist(outDir, "../bad", []string{"second.txt"}, 1024, 4096); err == nil {
		t.Fatalf("expected invalid agent_id to fail")
	}
	if _, err := PromoteAllowlist(outDir, "nonexistent-agent", []string{"second.txt"}, 1024, 4096); err == nil {
		t.Fatalf("expected missing scratch root to fail")
	}
	resTrav, err := PromoteAllowlist(outDir, agentID, []string{"../escape.txt", "missing-file.txt"}, 1024, 4096)
	if err != nil || len(resTrav) != 2 || resTrav[0].Promoted || resTrav[1].Promoted {
		t.Fatalf("expected path traversal and missing file to be blocked, got %+v err=%v", resTrav, err)
	}
}
