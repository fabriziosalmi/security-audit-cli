# sec-audit

Deterministic CLI and MCP server (`stdio` JSON-RPC 2.0) implementing Cloudflare's [`security-audit-skill`](https://github.com/cloudflare/security-audit-skill/tree/main/skills/security-audit) 6-phase workflow with strict 1:1 parity between CLI subcommands and MCP tools.

Zero external dependencies (`go 1.24+` standard library only). All 12 attack-class catalogs and companion files (`ATTACK-CLASSES.md` + 10 domain companions + `report-schema.json`) are embedded in the binary.

## Build

```bash
go build -o sec-audit ./cmd/sec-audit
```

## 1:1 CLI Subcommands & MCP Tools

| Phase | CLI Subcommand | MCP Tool | Deterministic Enforcement |
|---|---|---|---|
| 1 | `sec-audit init` | `sec_audit_init` | Scaffolds run directories, enforces pre-recon budget gate & out-of-tree `output_dir` (or git-ignored inside target), runs static repo scan, evaluates prior runs. |
| 1-2 | `sec-audit catalog` | `sec_audit_catalog` | Queries embedded `ATTACK-CLASSES.md` and 10 domain companions by `FILE.md#Block` reference or file name. |
| 1 | `sec-audit architecture` | `sec_audit_architecture` | Validates word cap (~1,000 words) and writes `<output-dir>/architecture.md`. |
| 1 | `sec-audit ledger-seed` | `sec_audit_ledger_seed` | Derives canonical RFC 3986 + NFC `coverage_id`, validates repo-relative `starting_paths` on disk and block references against catalog, writes `coverage-ledger.json`. |
| 1-5 | `sec-audit agent-assign` | `sec_audit_agent_assign` | Validates fresh canonical `agent_id`, enforces budget reserves and adversarial separation, creates `agents/<id>/scratch` & `artifacts`, compiles verbatim prompt. |
| 3-5 | `sec-audit artifact-promote` | `sec_audit_artifact_promote` | OS race-safe 11-step promotion (`*os.Root` + `O_NOFOLLOW\|O_NONBLOCK`, `nlink == 1`, per-file & cumulative byte caps, double-`Fstat` check). |
| 2 | `sec-audit hunter-submit` | `sec_audit_hunter_submit` | Validates `reviewed_paths` exist in repo and cover unit `starting_paths`, checks `file:line` citations on disk, updates `coverage-ledger.json`. |
| 2 | `sec-audit critic-submit` | `sec_audit_critic_submit` | Archives reopened attempts, adds missing units, advances hunting wave in `coverage-ledger.json`. |
| 3 | `sec-audit verifier-submit` | `sec_audit_verifier_submit` | Enforces `verifier != hunter`, validates promoted `verification_artifacts` and `trace` (`entrypoint -> propagation* -> sink`) on disk, updates `findings.json`. |
| 5 | `sec-audit record-verify-submit` | `sec_audit_record_verify_submit` | Enforces 3-way adversarial independence (`record_verifier != hunter` and `!= verifier`) and material-replacement gate in Phase 5. |
| 5-6 | `sec-audit validate` | `sec_audit_validate` | Runs full Go port of `validate-coverage-ledger.cjs` and `validate-findings.cjs` plus on-disk repository file/line verification. |
| 6 | `sec-audit render` | `sec_audit_render` | Blocks until `validate` passes, then deterministically generates `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, and SARIF 2.1.0 `findings.sarif`. |

## Running as an MCP Server

```bash
./sec-audit mcp
```

## Testing

```bash
go test -v ./...
```
