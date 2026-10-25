# Security Policy

## Supported Versions

`sec-audit` is pre-1.0. Only the latest commit on `main` and the latest tagged release receive security fixes.

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Email **fabrizio.salmi@gmail.com** with:
- A clear description of the boundary violation or invariant bypass
- Exact steps or input payloads to reproduce
- Affected version or commit hash
- Any proposed source-level mitigation

You can expect an acknowledgement within 7 days. Coordinated disclosure is appreciated; once a fix is released, credit will be given in the changelog unless you prefer to remain anonymous.

## Threat Model and Enforced Boundaries

- **Target Repository Containment (`*os.Root`)**: [`VerifyRepoFileAndLine`](internal/validator/common.go) opens the audited repository via `os.OpenRoot(targetDir)`, inspects every parent segment with `root.Lstat`, opens regular files with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, verifies `f.Stat()` on the opened descriptor, and bounds reads with `io.LimitReader(f, MaxInputBytes+1)`. Symlinks, FIFOs, device nodes, and path escapes outside `targetDir` are rejected by the OS kernel.
- **Race-Safe Artifact Promotion (`PromoteAllowlist`)**: [`PromoteAllowlist`](internal/promote/promote_unix.go) promotes files from an untrusted agent scratch directory (`<output-dir>/agents/<id>/scratch/`) into `<output-dir>/agents/<id>/artifacts/` using descriptor-relative `*os.Root` traversal, `O_NOFOLLOW | O_NONBLOCK`, `nlink == 1` (rejecting hardlinks), double-`Fstat` identity checks (`dev`/`ino`/`size`/`mtime`) before and after read, and strict per-file (`1 MiB`) and cumulative (`10 MiB`) byte caps.
- **JSON Preflight Guards (`ValidateJSONPreflight`)**: [`ValidateJSONPreflight`](internal/validator/preflight.go) scans raw JSON streams in a single $O(N)$ pass before `json.Unmarshal`, enforcing `MaxNestingDepth (64)`, `MaxObjectFields (1000)`, `MaxPreflightValues (500000)`, and rejecting duplicate object keys at any nesting depth to prevent parser-differential smuggling.
- **Crash-Safe Atomic Persistence (`WriteFileAtomic`)**: [`WriteFileAtomic`](internal/store/store.go) writes state files via temporary sibling files (`0600` inside `0700` directories), calls `Sync()`, and atomically renames over the destination path.
- **MCP Transport (`ServeStdio`)**: [`ServeStdio`](internal/mcp/server.go) communicates exclusively over newline-delimited `stdio` JSON-RPC 2.0 (bounded to `5 MiB` per message) with no network listener.
- **Supply Chain Integrity (SLSA, Cosign, SBOM, Scorecard, CodeQL)**: All GitHub Actions are pinned to immutable 40-char commit SHAs with `persist-credentials: false` and maintained via [`.github/dependabot.yml`](.github/dependabot.yml). Releases ([`.github/workflows/release.yml`](.github/workflows/release.yml)) generate SPDX + CycloneDX SBOMs, sign `SHA256SUMS.txt` and SBOMs with keyless Sigstore Cosign OIDC (`cosign sign-blob --bundle`), and emit SLSA build provenance (`actions/attest-build-provenance`) and SBOM attestations (`actions/attest-sbom`). Continuous security analysis runs via [`.github/workflows/security.yml`](.github/workflows/security.yml) (CodeQL Go SAST + OpenSSF Scorecard) and `govulncheck` + 4 fuzz targets in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Troubleshooting: macOS Provenance and In-Place Binary Overwrites

On macOS Apple Silicon (`darwin/arm64`), overwriting an existing Mach-O binary in place with `cp` invalidates the kernel vnode code-signature cache, causing `amfid` to terminate the process with `SIGKILL` (exit code `137`). Always remove the destination binary (`rm -f`) before installing a new build, and apply an ad-hoc signature:

```sh
rm -f ~/.local/bin/sec-audit
install -m 0755 sec-audit ~/.local/bin/sec-audit
codesign --sign - --force --timestamp=none ~/.local/bin/sec-audit
```

`make install` performs these steps automatically.
