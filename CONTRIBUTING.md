# Contributing to sec-audit

Thanks for your interest in contributing to `sec-audit`. The codebase is intentionally compact, deterministic, and free of external dependencies.

## Project Layout

- [`cmd/sec-audit/`](cmd/sec-audit/) - CLI entrypoint and flag-to-JSON normalizer.
- [`internal/registry/`](internal/registry/) - Generic `Bind[Req, Resp]` command registry enforcing 1:1 parity between CLI subcommands (`sec-audit <subcommand>`) and MCP tools (`sec_audit_<subcommand>`).
- [`internal/mcp/`](internal/mcp/) - JSON-RPC 2.0 `stdio` server delegating `tools/list` and `tools/call` to `internal/registry`.
- [`internal/engine/`](internal/engine/) - Phase 1 to Phase 6 audit state machine (`Init`, `CatalogQuery`, `WriteArchitecture`, `SeedLedger`, `AssignAgent`, `PromoteArtifacts`, `SubmitHunter`, `SubmitCritic`, `SubmitVerifier`, `SubmitRecordVerifier`, `Validate`, `Render`).
- [`internal/validator/`](internal/validator/) - Single-pass $O(N)$ JSON preflight, RFC 3986 + Unicode NFC `coverage_id` derivation, `coverage-ledger.json` and `findings.json` validators, cross-file consistency checks, and `*os.Root` repository file/line grounding.
- [`internal/promote/`](internal/promote/) - 11-step OS race-safe descriptor-relative artifact promotion (`*os.Root` + `O_NOFOLLOW | O_NONBLOCK`).
- [`internal/store/`](internal/store/) - `RunStore` persistence layer with crash-safe `WriteFileAtomic` (`0600` files, `Sync()`, atomic rename).
- [`internal/scanner/`](internal/scanner/) - Table-driven repository reconnaissance scanner, git status/ignore inspector, and prior-run carryover evaluator.
- [`internal/prompt/`](internal/prompt/) - Deterministic role prompt compiler (`recon`, `hunter`, `critic`, `verifier`, `record_verifier`).
- [`internal/report/`](internal/report/) - Deterministic generators for `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, `advisories/GHSA-<fingerprint>.md`, and SARIF 2.1.0 `findings.sarif`.
- [`internal/spec/`](internal/spec/) - Embedded `ATTACK-CLASSES.md`, 10 domain companion playbooks, and `report-schema.json` cached via `sync.OnceValues`.
- [`editors/vscode/`](editors/vscode/) - Optional zero-dependency VS Code / Cursor / Antigravity extension with 1:1:1 command parity and pure-Go `.vsix` packager ([`editors/vscode/pack/main.go`](editors/vscode/pack/main.go)).

## Development Workflow

```sh
make build    # compile ./sec-audit (with ad-hoc codesign on macOS)
make test     # run go vet ./... and go test -count=1 -race -cover ./...
make bench    # run validator and end-to-end benchmarks with -benchmem
make fuzz     # run all 4 deterministic fuzz targets (10,000 iterations each)
make vsix     # package deterministic dist/sec-audit-vscode-<version>.vsix
make install  # install cleanly into ~/.local/bin/sec-audit
```

## Pull Request Guidelines

1. **1:1:1 CLI, MCP, and VS Code Parity**: Every capability must be registered once in [`internal/registry/registry.go`](internal/registry/registry.go) via `Bind[Req, Resp]` and surfaced in [`editors/vscode/package.json`](editors/vscode/package.json) so CLI, MCP, and IDE behavior never diverge.
2. **Zero External Dependencies**: `go.mod` must remain pure Go standard library (`go 1.24+`).
3. **Break-Tests Required**: Every security invariant or bug fix must include a unit test that fails when the check is disabled.
4. **Conventional Commits**: Use scoped Conventional Commits stating the resulting behavior (for example, `fix(validator): enforce post-open io.LimitReader bound in VerifyRepoFileAndLine`).
5. **Formatting and Linting**: Run `gofmt -s -w .`, `make test`, and `lgit check .` before submitting.
