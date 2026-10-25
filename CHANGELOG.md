# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-10-25

### Added

- **Supply Chain Integrity, SLSA Provenance, Keyless Cosign, and Dual SBOMs (`.github/workflows/release.yml`, `.github/workflows/security.yml`, `.github/dependabot.yml`)**:
  - Added reproducible `CGO_ENABLED=0` multi-architecture release workflow (`linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`) with macOS ad-hoc codesigning, `SHA256SUMS.txt`, SPDX + CycloneDX SBOM generation (`anchore/sbom-action`), keyless Sigstore Cosign OIDC signing and verification (`cosign sign-blob` / `cosign verify-blob`), and GitHub SLSA Build Provenance + SBOM attestations (`actions/attest-build-provenance`, `actions/attest-sbom`).
  - Added `.github/workflows/security.yml` running CodeQL Go SAST and OpenSSF Scorecard with SARIF upload, `govulncheck` + 4 fuzz targets in `ci.yml`, and `.github/dependabot.yml` for SHA-pinned actions and `gomod`.
- **Expanded Fuzzing and Adversarial E2E Test Matrix (`internal/validator`, `internal/engine`)**:
  - Added `FuzzValidateCoverageLedgerBytes`, `FuzzValidateJSONPreflight`, and `FuzzDeriveCoverageID` alongside `FuzzValidateFindingsBytes`.
  - Added `TestDraconianAdversarialMatrixAndManifestTamper` testing cross-fingerprint verifier isolation, Phase 5 `needs_validation -> confirmed` promotion gates, and cryptographic `manifest.sha256` verification.

### Fixed

- **Hardened `*os.Root` Containment, Symlink Resolution, and Store Preflight (`internal/validator`, `internal/scanner`, `internal/store`, `internal/promote`, `internal/engine`, `cmd/sec-audit`)**:
  - Added `validator.VerifyOutputRegularFile` using `*os.Root` + segment `Lstat` to verify promoted artifacts inside `outputDir` without following intermediate symlinks.
  - Resolved existing ancestor symlinks in `scanner.IsSubpath` (`resolvePathSymlinks`) so symlinked `output_dir` or `target` paths cannot bypass target-containment checks.
  - Enforced `store.ReadJSON` (`validator.ReadFileNoFollow` + `validator.ValidateJSONPreflight`) across `RunStore`, `scanner.EvaluatePriorRuns`, `scanner.FileHashSHA256`, and `prompt.CompileHunter`/`CompileCritic`.
  - Enforced UTF-8 / NUL-byte rejection, `dstFile.Sync()`, and `10 MiB` cumulative default cap in `promote.PromoteAllowlist`.
  - Enforced `assign.Completed` single-submission gates, `starting_paths` coverage in `SubmitHunter`, `SelectedCompanionFiles` membership in `SeedLedger`, `UncoveredQueue` drain check in `Render`, and top-level key inspection in `cmd/sec-audit` flag normalization.

## [0.1.1] - 2026-10-25

### Added

- **CamelCase / PascalCase Token Splitting & Expanded Language Coverage (`internal/scanner`)**:
  - Added `splitIdentifierTokens` to decompose CamelCase, PascalCase, and acronym boundaries (`PrivilegedHelper.swift`, `PACServer.swift`, `AuthHelper.c`, `BatchEndpoints.php`).
  - Added `.swift`, `.php`, `.rb`, `.sh`/`.bash`/`.zsh`, `.astro`, `.vue`, `.svelte`, `.gd`, `.cs` to `extLanguageMap`, `.mdx` to `docExtensions`, and `Package.swift`, `composer.json`, `Gemfile`, `Chart.yaml`, `wrangler.toml`, `wrangler.jsonc` to `manifestNames` (verified across 96 repositories in `3.19s`).
- **Explicit Companion Override & Auto-Derived Canonical References (`cmd/sec-audit`, `internal/engine`)**:
  - Added `--companions` flag to `sec-audit init` (`InitRequest.Companions`) for deterministic companion playbook selection.
  - Auto-derived `canonical_refs` in `SeedLedger` from top-level `surface`, `boundary`, `subsystem`, and `attack_class` when omitted.
  - Enabled merging CLI flags (such as `--output-dir`) into `--json` object payloads in `parseSubcommandFlags`.

### Fixed

- **Hardened Input & File-Read Boundaries (`FIND-0002` through `FIND-0007`, discovered via self-dogfooding Rounds 2–4)**:
  - Enforced `validator.ReadFileNoFollow` (`O_NOFOLLOW`, regular-file verification, and `MaxInputBytes` cap) across all CLI input flags (`--input`, `--file`) and `store.ReadJSON`.
  - Applied `ValidateJSONPreflight` inside generic `registry.Bind` so all CLI subcommands and MCP tools reject duplicate JSON keys (RFC 8259) and excessive nesting before `json.Unmarshal`.
  - Enforced `io.LimitReader(r, validator.MaxInputBytes+1)` on `stdio` MCP frames and `--json -` stdin reads.
  - Hardened `ValidateOutputDirNotInsideTarget` using `filepath.Rel` after symlink resolution and verified `local_check.reviewed_paths` in `SubmitVerifier`.
- **AI Worktree Pruning & Companion Precision (`internal/scanner`)**:
  - Ignored `.claude`, `.cursor`, `.gemini`, `.codex`, `.worktrees`, `worktrees`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.vitepress`, `.astro`, `_site`, `.terraform`, `dist-*`, `build-*`, `*.xcodeproj`, and `*.xcworkspace` during repository walks.
  - Prevented `LaunchAgent` and `user_agent` identifiers from triggering `AI-AND-LLM.md`, Go `*_unix.go` build-tag files from triggering `DESKTOP-MOBILE-AND-LOCAL-IPC.md`, and LLM `token_counter` files from triggering false-positive `auth_boundary_candidates`.
- **Linux `syscall.Stat_t` Portability (`internal/promote`)**:
  - Replaced Darwin-specific `Stat_t.Mtimespec` comparison in `promoteOne` with portable `os.FileInfo.ModTime().Equal(...)` alongside `Stat_t` device/inode/mode/nlink checks.

## [0.1.0] - 2026-10-25

### Added

- **1:1 CLI and MCP Server Architecture (`internal/registry`, `internal/mcp`, `cmd/sec-audit`)**:
  Generic `Bind[Req, Resp]` command registry binding all 12 audit operations simultaneously as CLI subcommands (`sec-audit <subcommand>`) and MCP JSON-RPC 2.0 `stdio` tools (`sec_audit_<subcommand>`).
- **6-Phase Security Audit State Machine (`internal/engine`)**:
  Deterministic orchestration of Phase 1 reconnaissance (`init`, `catalog`, `architecture`, `ledger-seed`), Phase 2 hunting and coverage-critic waves (`agent-assign`, `hunter-submit`, `critic-submit`), Phase 3 adversarial verification (`artifact-promote`, `verifier-submit`), Phase 5 fresh record verification (`record-verify-submit`), and Phase 6 validation and report generation (`validate`, `render`).
- **Embedded Attack-Class Catalog (`internal/spec`)**:
  Embedded `ATTACK-CLASSES.md`, 10 domain companion playbooks (`AI-AND-LLM.md`, `CLIENT-SIDE.md`, `CLOUD-AND-DEPLOYMENT.md`, `DATA-ISOLATION-AND-LIFECYCLE.md`, `DESKTOP-MOBILE-AND-LOCAL-IPC.md`, `MEMORY-SAFETY-AND-BINARY.md`, `PROTOCOLS-RPC-AND-MESSAGING.md`, `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`, `SUPPLY-CHAIN-AND-RELEASE.md`, `WEB-PROTOCOL-AND-AUTH.md`), and `report-schema.json`, parsed once via `sync.OnceValues`.
- **Single-Pass $O(N)$ JSON Preflight and Schema Validators (`internal/validator`)**:
  - `ValidateJSONPreflight` enforces `MaxNestingDepth (64)`, `MaxObjectFields (1000)`, `MaxPreflightValues (500000)`, and rejects duplicate JSON object keys at any nesting level before `json.Unmarshal`.
  - `DeriveCoverageID` implements single-allocation (`208 B/op`, `1 alloc/op`) RFC 3986 + Unicode NFC canonical `coverage_id` encoding.
  - `ValidateCoverageLedgerBytes` and `ValidateFindingsBytes` enforce strict schema, ordering, uniqueness, trace ordering (`entrypoint -> propagation* -> sink`), severity ceiling (`overall_severity <= impact`), and cross-file ledger/findings consistency.
- **Kernel-Enforced `*os.Root` Containment and 11-Step Race-Safe Promotion (`internal/validator`, `internal/promote`)**:
  - `VerifyRepoFileAndLine` validates repository-relative paths and line numbers using `os.OpenRoot`, segment-by-segment `Lstat`, `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, post-open `f.Stat()`, and `io.LimitReader(f, MaxInputBytes+1)`.
  - `PromoteAllowlist` promotes agent scratch artifacts using `*os.Root`, `O_NOFOLLOW | O_NONBLOCK`, `nlink == 1`, double-`Fstat` identity checks, and per-file/cumulative byte caps.
- **Crash-Safe Persistence and Cryptographic Run Manifest (`internal/store`, `internal/report`)**:
  - `WriteFileAtomic` writes state and report artifacts via temporary sibling files (`0600`), `Sync()`, and atomic `os.Rename`.
  - `Render` generates deterministic `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, SARIF 2.1.0 `findings.sarif`, and a `shasum -a 256 -c` compatible `manifest.sha256`.

### Fixed

- **Post-`Lstat` Unbounded Read in `VerifyRepoFileAndLine` (`FIND-0001`, discovered via self-audit)**:
  Added post-open `f.Stat()` verification and wrapped the file descriptor in `io.LimitReader(f, MaxInputBytes+1)` so concurrent file growth inside `targetDir` cannot trigger unbounded memory allocation.
- **Documentation Extension Filtering in `ScanRepository`**:
  Excluded `.md`, `.txt`, `.rst`, and `.adoc` files from substring companion matching so documentation filenames do not trigger false-positive companion playbook recommendations.
- **CLI Flag Preservation for `critic-submit`**:
  Changed `-critic-kind` flag default to `""` with fallback to `"post_wave"` only when `critic_kind` is absent from the `--input` JSON payload.
