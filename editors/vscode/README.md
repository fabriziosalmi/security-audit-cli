# Sec-Audit for VS Code / Cursor / Antigravity

Thin, zero-dependency IDE cockpit with strict **1:1:1 parity** across the `sec-audit` CLI, MCP server (`sec-audit mcp`), and VS Code Command Palette (`sec-audit.<subcommand>`).

## Features

1. **Run Status & Next Actions (`secAuditStatusView`)**:
   - Real-time `FileSystemWatcher` over `<output-dir>`.
   - Displays current phase/wave, `agents_spent / budget`, source-file SHA-256 drift alerts, and `next_required_actions[]`.
2. **Findings & Source Trace (`secAuditFindingsView` + `Problems` Diagnostics)**:
   - Groups findings by `Confirmed`, `Needs Validation`, and `Rejected`.
   - Click any `[entrypoint]`, `[propagation]`, or `[sink]` item to jump directly to the verified `file:line` in the target repository.
   - Surfaces inline squiggles (`vscode.DiagnosticCollection`) with full trace `relatedInformation`.
   - One-click opening of generated `advisories/GHSA-<fingerprint>.md` documents.
3. **Coverage Ledger (`secAuditLedgerView`)**:
   - Inspects `coverage-ledger.json` grouped by unit status (`planned`, `in_progress`, `covered`, `candidate`, `blocked`, `deferred`, `out_of_scope`, `not_applicable`).
4. **Attack-Class Catalog (`secAuditCatalogView`)**:
   - Browse embedded `ATTACK-CLASSES.md` and all 10 domain companion playbooks directly inside the IDE.
5. **1:1:1 Command Palette Parity**:
   - Exposes all 13 `sec-audit` subcommands (`sec-audit.init`, `sec-audit.catalog`, `sec-audit.architecture`, `sec-audit.ledger-seed`, `sec-audit.agent-assign`, `sec-audit.artifact-promote`, `sec-audit.hunter-submit`, `sec-audit.critic-submit`, `sec-audit.verifier-submit`, `sec-audit.record-verify-submit`, `sec-audit.validate`, `sec-audit.render`, `sec-audit.status`).

## Installation

```sh
make vsix
code --install-extension dist/sec-audit-vscode-0.1.4.vsix
```
