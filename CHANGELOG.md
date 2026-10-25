# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
