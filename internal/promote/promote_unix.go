package promote

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

// PromotedArtifact describes the result of promoting one scratch-relative file.
type PromotedArtifact struct {
	ScratchPath  string `json:"scratch_path"`
	ArtifactPath string `json:"artifact_path"`
	Bytes        int64  `json:"bytes"`
	Promoted     bool   `json:"promoted"`
	Blocker      string `json:"blocker,omitempty"`
}

// PromoteAllowlist promotes predeclared scratch-relative files from scratchDir to artifactsDir
// using the 11-step OS race-safe descriptor-relative procedure defined in SKILL.md.
func PromoteAllowlist(outputDir, agentID string, relPaths []string, maxFileBytes, maxTotalBytes int64) ([]PromotedArtifact, error) {
	if !validator.IsSafeAgentID(agentID) {
		return nil, fmt.Errorf("invalid canonical agent_id %q", agentID)
	}
	if maxFileBytes <= 0 {
		maxFileBytes = 1 * 1024 * 1024 // 1 MiB default per-file
	}
	if maxTotalBytes <= 0 {
		maxTotalBytes = 5 * 1024 * 1024 // 5 MiB default cumulative
	}

	scratchPath := fmt.Sprintf("%s/agents/%s/scratch", strings.TrimRight(outputDir, "/"), agentID)
	artifactsPath := fmt.Sprintf("%s/agents/%s/artifacts", strings.TrimRight(outputDir, "/"), agentID)

	scratchRoot, err := os.OpenRoot(scratchPath)
	if err != nil {
		return nil, fmt.Errorf("open scratch root: %w", err)
	}
	defer scratchRoot.Close()

	artifactsRoot, err := os.OpenRoot(artifactsPath)
	if err != nil {
		return nil, fmt.Errorf("open artifacts root: %w", err)
	}
	defer artifactsRoot.Close()

	var cumulative int64
	results := make([]PromotedArtifact, 0, len(relPaths))

	for _, rel := range relPaths {
		res := promoteOne(scratchRoot, artifactsRoot, agentID, rel, maxFileBytes, maxTotalBytes, &cumulative)
		results = append(results, res)
	}

	return results, nil
}

func promoteOne(scratchRoot, artifactsRoot *os.Root, agentID, rel string, maxFileBytes, maxTotalBytes int64, cumulative *int64) PromotedArtifact {
	fail := func(reason string) PromotedArtifact {
		return PromotedArtifact{
			ScratchPath: rel,
			Promoted:    false,
			Blocker:     reason,
		}
	}

	// Step 1: Validate declared relative path: reject absolute, empty, `.`, `..`, or unsafe components.
	if !validator.IsSafeRelativePath(rel) {
		return fail("invalid relative path: rejected absolute, empty, dot, dot-dot, or unsafe component")
	}

	segments := strings.Split(rel, "/")
	parents := segments[:len(segments)-1]
	leaf := segments[len(segments)-1]

	// Step 2: Walk each parent component from retained scratch-root descriptor with no-follow checks.
	currSrc := scratchRoot
	var openedSrcParents []*os.Root
	defer func() {
		for i := len(openedSrcParents) - 1; i >= 0; i-- {
			_ = openedSrcParents[i].Close()
		}
	}()

	for _, seg := range parents {
		fi, err := currSrc.Lstat(seg)
		if err != nil {
			return fail(fmt.Sprintf("scratch parent %q lstat failed: %v", seg, err))
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fail(fmt.Sprintf("scratch parent %q is not a real directory", seg))
		}
		nextRoot, err := currSrc.OpenRoot(seg)
		if err != nil {
			return fail(fmt.Sprintf("scratch parent %q openroot failed: %v", seg, err))
		}
		openedSrcParents = append(openedSrcParents, nextRoot)
		currSrc = nextRoot
	}

	// Verify leaf via Lstat before opening no-follow
	leafLstat, err := currSrc.Lstat(leaf)
	if err != nil {
		return fail(fmt.Sprintf("scratch leaf %q lstat failed: %v", leaf, err))
	}
	if leafLstat.Mode()&os.ModeSymlink != 0 || !leafLstat.Mode().IsRegular() {
		return fail(fmt.Sprintf("scratch leaf %q is not a regular non-symlink file", leaf))
	}

	// Step 3: Open the leaf no-follow and nonblocking.
	srcFile, err := currSrc.OpenFile(leaf, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fail(fmt.Sprintf("scratch leaf %q open no-follow failed: %v", leaf, err))
	}
	defer srcFile.Close()

	// Step 4: Verify with fstat that it is a regular file with link count == 1 and within byte limits.
	var st1 syscall.Stat_t
	if err := syscall.Fstat(int(srcFile.Fd()), &st1); err != nil {
		return fail(fmt.Sprintf("scratch leaf %q fstat failed: %v", leaf, err))
	}
	if (st1.Mode & syscall.S_IFMT) != syscall.S_IFREG {
		return fail("scratch leaf is not a regular file on fstat")
	}
	if st1.Nlink != 1 {
		return fail(fmt.Sprintf("scratch leaf has hard link count %d (expected 1)", st1.Nlink))
	}
	if st1.Size > maxFileBytes {
		return fail(fmt.Sprintf("scratch leaf size %d exceeds per-file limit %d", st1.Size, maxFileBytes))
	}
	if *cumulative+st1.Size > maxTotalBytes {
		return fail(fmt.Sprintf("scratch leaf size %d exceeds cumulative limit %d", st1.Size, maxTotalBytes))
	}

	// Step 5: Enforce limits again while reading from that descriptor.
	var buf bytes.Buffer
	chunk := make([]byte, 32*1024)
	var readBytes int64
	for {
		n, rerr := srcFile.Read(chunk)
		if n > 0 {
			readBytes += int64(n)
			if readBytes > maxFileBytes || *cumulative+readBytes > maxTotalBytes || readBytes > st1.Size {
				return fail("scratch file grew or exceeded byte limits during read")
			}
			buf.Write(chunk[:n])
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fail(fmt.Sprintf("scratch read error: %v", rerr))
		}
	}

	// Step 6: Copy exactly the verified size, repeat fstat, and reject a changed identity, type, link count, or size.
	if readBytes != st1.Size {
		return fail(fmt.Sprintf("read size %d did not match initial fstat size %d", readBytes, st1.Size))
	}
	var st2 syscall.Stat_t
	if err := syscall.Fstat(int(srcFile.Fd()), &st2); err != nil {
		return fail(fmt.Sprintf("second fstat failed: %v", err))
	}
	if st1.Dev != st2.Dev || st1.Ino != st2.Ino || st1.Mode != st2.Mode || st2.Nlink != 1 || st1.Size != st2.Size || st1.Mtimespec != st2.Mtimespec {
		return fail("scratch file changed identity, type, link count, size, or mtime during promotion")
	}

	// Step 7: Walk every parent component from retained artifacts-root descriptor with no-follow checks.
	currDst := artifactsRoot
	var openedDstParents []*os.Root
	defer func() {
		for i := len(openedDstParents) - 1; i >= 0; i-- {
			_ = openedDstParents[i].Close()
		}
	}()

	for _, seg := range parents {
		fi, err := currDst.Lstat(seg)
		if os.IsNotExist(err) {
			if mkErr := currDst.Mkdir(seg, 0o700); mkErr != nil {
				return fail(fmt.Sprintf("create destination directory %q failed: %v", seg, mkErr))
			}
			fi, err = currDst.Lstat(seg)
		}
		if err != nil {
			return fail(fmt.Sprintf("destination parent %q lstat failed: %v", seg, err))
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fail(fmt.Sprintf("destination parent %q is not a real directory", seg))
		}
		nextDst, err := currDst.OpenRoot(seg)
		if err != nil {
			return fail(fmt.Sprintf("destination parent %q openroot failed: %v", seg, err))
		}
		openedDstParents = append(openedDstParents, nextDst)
		currDst = nextDst
	}

	// Step 8: Create leaf exclusively without following links, verify regular file with link count 1, and write.
	dstFile, err := currDst.OpenFile(leaf, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fail(fmt.Sprintf("create exclusive destination leaf %q failed: %v", leaf, err))
	}
	defer dstFile.Close()

	var dstSt syscall.Stat_t
	if err := syscall.Fstat(int(dstFile.Fd()), &dstSt); err != nil {
		_ = currDst.Remove(leaf)
		return fail(fmt.Sprintf("destination fstat failed: %v", err))
	}
	if (dstSt.Mode&syscall.S_IFMT) != syscall.S_IFREG || dstSt.Nlink != 1 {
		_ = currDst.Remove(leaf)
		return fail("destination leaf is not a regular file with link count 1")
	}

	written, err := dstFile.Write(buf.Bytes())
	if err != nil || int64(written) != st1.Size {
		_ = currDst.Remove(leaf)
		return fail(fmt.Sprintf("destination write failed: %v", err))
	}

	*cumulative += st1.Size
	return PromotedArtifact{
		ScratchPath:  rel,
		ArtifactPath: fmt.Sprintf("agents/%s/artifacts/%s", agentID, rel),
		Bytes:        st1.Size,
		Promoted:     true,
	}
}
