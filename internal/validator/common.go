package validator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

const (
	MaxInputBytes       = 5 * 1024 * 1024
	MaxUnits            = 10000
	MaxListItems        = 1000
	MaxObjectFields     = 1000
	MaxNestingDepth     = 64
	MaxPreflightValues  = 500000
	MaxValidationErrors = 100
	MaxTextLength       = 4096
)

var (
	FingerprintPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`)
	AgentIDPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	WindowsReservedID  = regexp.MustCompile(`^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$`)
	WindowsReservedSeg = regexp.MustCompile(`(?i)^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9\x{00b9}\x{00b2}\x{00b3}]|lpt[1-9\x{00b9}\x{00b2}\x{00b3}])(?:\.|$)`)
)

func isDefaultIgnorable(r rune) bool {
	if r == 0x00AD || r == 0x034F || r == 0x061C || r == 0x115F || r == 0x1160 ||
		r == 0x17B4 || r == 0x17B5 || (r >= 0x180B && r <= 0x180F) ||
		(r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) ||
		(r >= 0x2060 && r <= 0x206F) || r == 0x3164 ||
		(r >= 0xFE00 && r <= 0xFE0F) || r == 0xFEFF || r == 0xFFA0 ||
		(r >= 0xFFF0 && r <= 0xFFF8) || (r >= 0x1BCA0 && r <= 0x1BCA3) ||
		(r >= 0x1D173 && r <= 0x1D17A) || (r >= 0xE0000 && r <= 0xE0FFF) {
		return true
	}
	return false
}

func isForbiddenPathRune(r rune) bool {
	if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) ||
		isDefaultIgnorable(r) {
		return true
	}
	return false
}

// HasVisibleProse checks that s is valid UTF-8 and has at least one visible character.
func HasVisibleProse(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == utf8.RuneError {
			return false
		}
		if !unicode.IsSpace(r) && !unicode.Is(unicode.Cc, r) && !unicode.Is(unicode.Cf, r) && !isDefaultIgnorable(r) {
			return true
		}
	}
	return false
}

// IsVisibleText mirrors isVisibleText(value, maxLength) from validate-coverage-ledger.cjs.
func IsVisibleText(s string, maxLen int) bool {
	if maxLen <= 0 {
		maxLen = MaxTextLength
	}
	if len(s) == 0 || len(s) > maxLen {
		return false
	}
	if strings.TrimSpace(s) != s {
		return false
	}
	return HasVisibleProse(s)
}

func isLikelyNFC(s string) bool {
	for _, r := range s {
		// Reject combining diacritical marks that indicate NFD decomposed strings
		if r >= 0x0300 && r <= 0x036F {
			return false
		}
	}
	return true
}

// IsCanonicalRef mirrors isCanonicalRef(value) from validate-coverage-ledger.cjs.
func IsCanonicalRef(s string) bool {
	if !IsVisibleText(s, 1024) {
		return false
	}
	for _, r := range s {
		if isForbiddenPathRune(r) {
			return false
		}
	}
	return isLikelyNFC(s)
}

// EncodeCanonicalRef encodes UTF-8 bytes with RFC 3986 percent encoding.
func EncodeCanonicalRef(s string) (string, error) {
	if !IsCanonicalRef(s) {
		return "", fmt.Errorf("invalid canonical reference %q", s)
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		unreserved := (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~'
		if unreserved {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String(), nil
}

// DeriveCoverageID computes the canonical coverage_id from CanonicalRefs.
func DeriveCoverageID(refs CanonicalRefs) (string, error) {
	parts := []string{refs.Surface, refs.Boundary, refs.Subsystem, refs.AttackClass}
	if refs.Lifecycle != nil {
		parts = append(parts, *refs.Lifecycle)
	}
	encoded := make([]string, len(parts))
	for i, p := range parts {
		enc, err := EncodeCanonicalRef(p)
		if err != nil {
			return "", err
		}
		encoded[i] = enc
	}
	return strings.Join(encoded, "::"), nil
}

// IsSafeRelativePath mirrors isSafeRelativePath / isSafeRelativeSourcePath.
func IsSafeRelativePath(s string) bool {
	if len(s) == 0 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	if strings.Contains(s, "\\") || strings.Contains(s, ":") {
		return false
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") {
		return false
	}
	for _, r := range s {
		if isForbiddenPathRune(r) {
			return false
		}
	}
	segments := strings.Split(s, "/")
	for _, seg := range segments {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		if strings.HasSuffix(seg, " ") || strings.HasSuffix(seg, ".") {
			return false
		}
		if WindowsReservedSeg.MatchString(seg) {
			return false
		}
	}
	return true
}

// IsSafeAgentID mirrors isSafeAgentId(value).
func IsSafeAgentID(s string) bool {
	return AgentIDPattern.MatchString(s) && !WindowsReservedID.MatchString(s)
}

// IsOwnedArtifactPath checks if value is under agents/<agentId>/artifacts/<leaf>.
func IsOwnedArtifactPath(value, agentID string) bool {
	if !IsSafeAgentID(agentID) || !IsSafeRelativePath(value) {
		return false
	}
	prefix := "agents/" + agentID + "/artifacts/"
	return strings.HasPrefix(value, prefix) && len(value) > len(prefix)
}

// ReadFileNoFollow reads a regular file using O_NOFOLLOW | O_NONBLOCK within MaxInputBytes.
func ReadFileNoFollow(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if err == syscall.ELOOP || err == syscall.EMLINK {
			return nil, fmt.Errorf("input must not be a symlink")
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer syscall.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("fstat %s: %w", path, err)
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFREG {
		return nil, fmt.Errorf("input must be a regular file")
	}
	if st.Size > MaxInputBytes {
		return nil, fmt.Errorf("input exceeds %d byte limit", MaxInputBytes)
	}

	var buf bytes.Buffer
	chunk := make([]byte, 64*1024)
	var total int64
	for {
		n, rerr := syscall.Read(fd, chunk)
		if n > 0 {
			total += int64(n)
			if total > MaxInputBytes {
				return nil, fmt.Errorf("input exceeds %d byte limit", MaxInputBytes)
			}
			buf.Write(chunk[:n])
		}
		if rerr != nil {
			return nil, rerr
		}
		if n == 0 {
			break
		}
	}
	data := buf.Bytes()
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("input is not valid UTF-8")
	}
	return data, nil
}

// VerifyRepoFileAndLine checks that relPath exists inside targetDir (without escaping via symlinks)
// and, if line > 0, that 1 <= line <= number of lines in the file.
func VerifyRepoFileAndLine(targetDir, relPath string, line int) error {
	if !IsSafeRelativePath(relPath) {
		return fmt.Errorf("invalid repository-relative path %q", relPath)
	}
	absTarget, err := filepath.EvalSymlinks(targetDir)
	if err != nil {
		return fmt.Errorf("resolve target dir: %w", err)
	}
	joined := filepath.Join(absTarget, filepath.FromSlash(relPath))
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return fmt.Errorf("source path %q does not exist in target repository", relPath)
	}
	relToTarget, err := filepath.Rel(absTarget, resolved)
	if err != nil || strings.HasPrefix(relToTarget, "..") || relToTarget == "." {
		return fmt.Errorf("source path %q escapes target repository", relPath)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("stat %q: %w", relPath, err)
	}
	if line > 0 {
		if info.IsDir() {
			return fmt.Errorf("source path %q is a directory, cannot cite line %d", relPath, line)
		}
		content, err := os.ReadFile(resolved)
		if err != nil {
			return fmt.Errorf("read %q: %w", relPath, err)
		}
		lineCount := bytes.Count(content, []byte{'\n'}) + 1
		if len(content) == 0 {
			lineCount = 0
		}
		if line < 1 || line > lineCount {
			return fmt.Errorf("source path %q line %d out of range (file has %d lines)", relPath, line, lineCount)
		}
	}
	return nil
}

// CanonicalJSONKey produces a deterministic string key for JSON uniqueness checks.
func CanonicalJSONKey(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
