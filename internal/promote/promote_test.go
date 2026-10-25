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
	if err := os.MkdirAll(filepath.Join(scratch, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}

	// Valid regular file
	validPath := filepath.Join(scratch, "sub", "proof.txt")
	if err := os.WriteFile(validPath, []byte("verified evidence\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	promoted, err := PromoteAllowlist(outDir, agentID, []string{"sub/proof.txt"}, 1024, 4096)
	if err != nil || len(promoted) != 1 || !promoted[0].Promoted {
		t.Fatalf("PromoteAllowlist failed: %+v err=%v", promoted, err)
	}
	if promoted[0].ArtifactPath != "agents/hunter-1/artifacts/sub/proof.txt" || promoted[0].Bytes != 18 {
		t.Fatalf("unexpected promoted metadata: %+v", promoted[0])
	}

	// Break-test 1: Symlink inside scratch must be rejected with Promoted=false & Blocker
	symPath := filepath.Join(scratch, "evil-link.txt")
	_ = os.Symlink(validPath, symPath)
	resSym, err := PromoteAllowlist(outDir, agentID, []string{"evil-link.txt"}, 1024, 4096)
	if err != nil || len(resSym) != 1 || resSym[0].Promoted || resSym[0].Blocker == "" {
		t.Fatalf("expected symlink promotion to be blocked, got %+v err=%v", resSym, err)
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

	// Break-test 3: Per-file byte cap exceeded
	resCap, err := PromoteAllowlist(outDir, agentID, []string{"sub/proof.txt"}, 5, 4096)
	if err != nil || len(resCap) != 1 || resCap[0].Promoted || !strings.Contains(resCap[0].Blocker, "exceeds") {
		t.Fatalf("expected per-file byte limit to block promotion, got %+v err=%v", resCap, err)
	}

	// Break-test 4: Invalid agent ID or path traversal
	if _, err := PromoteAllowlist(outDir, "../bad", []string{"sub/proof.txt"}, 1024, 4096); err == nil {
		t.Fatalf("expected invalid agent_id to fail")
	}
	resTrav, err := PromoteAllowlist(outDir, agentID, []string{"../escape.txt"}, 1024, 4096)
	if err != nil || len(resTrav) != 1 || resTrav[0].Promoted {
		t.Fatalf("expected path traversal to be blocked, got %+v err=%v", resTrav, err)
	}
}
