"use strict";

const vscode = require("vscode");
const cp = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Resolves the sec-audit binary path from configuration, PATH, or ~/.local/bin/sec-audit.
 * @returns {string}
 */
function resolveBinaryPath() {
  const cfg = vscode.workspace.getConfiguration("secAudit");
  const custom = cfg.get("binaryPath", "sec-audit");
  if (custom && custom !== "sec-audit") {
    return custom;
  }
  const localBin = path.join(os.homedir(), ".local", "bin", "sec-audit");
  if (fs.existsSync(localBin)) {
    return localBin;
  }
  return "sec-audit";
}

/**
 * Executes `sec-audit <subcommand> --json <payload>` safely via execFile (no shell interpolation).
 * @param {string} subcommand
 * @param {Record<string, any>} payload
 * @returns {Promise<any>}
 */
function execSecAudit(subcommand, payload) {
  return new Promise((resolve, reject) => {
    const bin = resolveBinaryPath();
    const args = [subcommand];
    if (payload && Object.keys(payload).length > 0) {
      args.push("--json", JSON.stringify(payload));
    }
    cp.execFile(bin, args, { maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      const trimmedOut = (stdout || "").trim();
      const trimmedErr = (stderr || "").trim();
      if (err && !trimmedOut) {
        reject(new Error(trimmedErr || err.message));
        return;
      }
      try {
        const parsed = trimmedOut ? JSON.parse(trimmedOut) : {};
        resolve(parsed);
      } catch (parseErr) {
        reject(new Error(`Failed to parse sec-audit output: ${parseErr.message}`));
      }
    });
  });
}

/**
 * Safely resolves a relative path inside baseDir, rejecting path traversal, absolute paths, and symlinks.
 * @param {string} baseDir
 * @param {string} relPath
 * @returns {string}
 */
function resolveContainedPath(baseDir, relPath) {
  if (!baseDir || !relPath || typeof relPath !== "string" || path.isAbsolute(relPath)) {
    return "";
  }
  const absBase = path.resolve(baseDir);
  const candidate = path.resolve(absBase, relPath);
  const rel = path.relative(absBase, candidate);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) {
    return "";
  }
  try {
    const st = fs.lstatSync(candidate);
    if (st.isSymbolicLink()) {
      return "";
    }
  } catch (_) {
    return "";
  }
  return candidate;
}

/**
 * Auto-detects the latest run directory under ~/security-audit-skill/<workspaceName>/run-N
 * when secAudit.outputDir is not explicitly set.
 * @returns {string}
 */
function resolveOutputDir(currentDir) {
  if (currentDir && fs.existsSync(currentDir)) {
    return currentDir;
  }
  const cfg = vscode.workspace.getConfiguration("secAudit");
  const configured = cfg.get("outputDir", "");
  if (configured && fs.existsSync(configured)) {
    return configured;
  }
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    return "";
  }
  const repoName = path.basename(folders[0].uri.fsPath);
  const baseDir = path.join(os.homedir(), "security-audit-skill", repoName);
  if (!fs.existsSync(baseDir)) {
    return "";
  }
  try {
    const entries = fs.readdirSync(baseDir, { withFileTypes: true })
      .filter((d) => d.isDirectory() && /^run-\d+$/.test(d.name))
      .map((d) => ({ name: d.name, num: parseInt(d.name.slice(4), 10) }))
      .sort((a, b) => b.num - a.num);
    if (entries.length > 0) {
      return path.join(baseDir, entries[0].name);
    }
  } catch (_) {
    // ignore read errors
  }
  return "";
}

class AuditNode extends vscode.TreeItem {
  /**
   * @param {string} label
   * @param {vscode.TreeItemCollapsibleState} collapsibleState
   * @param {AuditNode[]} [children]
   * @param {vscode.Command} [command]
   * @param {string} [description]
   * @param {string} [tooltip]
   * @param {vscode.ThemeIcon} [iconPath]
   */
  constructor(label, collapsibleState, children, command, description, tooltip, iconPath) {
    super(label, collapsibleState);
    this.children = children || [];
    if (command) this.command = command;
    if (description) this.description = description;
    if (tooltip) this.tooltip = tooltip;
    if (iconPath) this.iconPath = iconPath;
  }
}

class SimpleTreeProvider {
  constructor() {
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    this.roots = [];
  }
  setRoots(roots) {
    this.roots = roots;
    this._onDidChangeTreeData.fire(undefined);
  }
  getTreeItem(element) {
    return element;
  }
  getChildren(element) {
    if (!element) {
      return this.roots;
    }
    return element.children || [];
  }
}

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  let activeOutputDir = resolveOutputDir("");
  const diagnostics = vscode.languages.createDiagnosticCollection("sec-audit");
  context.subscriptions.push(diagnostics);

  const statusProvider = new SimpleTreeProvider();
  const findingsProvider = new SimpleTreeProvider();
  const ledgerProvider = new SimpleTreeProvider();
  const catalogProvider = new SimpleTreeProvider();

  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("secAuditStatusView", statusProvider),
    vscode.window.registerTreeDataProvider("secAuditFindingsView", findingsProvider),
    vscode.window.registerTreeDataProvider("secAuditLedgerView", ledgerProvider),
    vscode.window.registerTreeDataProvider("secAuditCatalogView", catalogProvider)
  );

  let fsWatcher = null;
  function setupWatcher(dir) {
    if (fsWatcher) {
      fsWatcher.dispose();
      fsWatcher = null;
    }
    if (!dir || !fs.existsSync(dir)) {
      return;
    }
    const pattern = new vscode.RelativePattern(dir, "{run-metadata.json,coverage-ledger.json,findings.json,.sec-audit-state.json,REPORT.md}");
    fsWatcher = vscode.workspace.createFileSystemWatcher(pattern);
    fsWatcher.onDidChange(() => refreshAll());
    fsWatcher.onDidCreate(() => refreshAll());
    fsWatcher.onDidDelete(() => refreshAll());
    context.subscriptions.push(fsWatcher);
  }

  async function loadCatalogTree() {
    try {
      const files = await execSecAudit("catalog", {});
      if (!Array.isArray(files)) return;
      const nodes = files.map((cf) => {
        const refs = Array.isArray(cf.class_blocks) && cf.class_blocks.length > 0 ? cf.class_blocks : (cf.block_refs || []);
        const blockNodes = refs.map((ref) => {
          const shortName = ref.includes("#") ? ref.split("#")[1] : ref;
          return new AuditNode(
            shortName,
            vscode.TreeItemCollapsibleState.None,
            [],
            {
              command: "sec-audit.openCatalogBlock",
              title: "Open Playbook Block",
              arguments: [ref]
            },
            cf.file,
            ref,
            new vscode.ThemeIcon("symbol-method")
          );
        });
        return new AuditNode(
          cf.file,
          vscode.TreeItemCollapsibleState.Collapsed,
          blockNodes,
          undefined,
          `${blockNodes.length} blocks`,
          `${cf.title || cf.file}\n\n${cf.when_to_use || ""}`.trim(),
          new vscode.ThemeIcon("book")
        );
      });
      catalogProvider.setRoots(nodes);
    } catch (_) {
      catalogProvider.setRoots([
        new AuditNode("sec-audit binary not found on PATH / ~/.local/bin", vscode.TreeItemCollapsibleState.None)
      ]);
    }
  }

  async function refreshAll() {
    activeOutputDir = resolveOutputDir(activeOutputDir);
    if (!activeOutputDir || !fs.existsSync(activeOutputDir)) {
      statusProvider.setRoots([
        new AuditNode(
          "No active audit run selected",
          vscode.TreeItemCollapsibleState.None,
          [],
          { command: "sec-audit.selectOutputDir", title: "Select Run Directory" },
          "Click to select <output-dir>",
          undefined,
          new vscode.ThemeIcon("folder-opened")
        ),
        new AuditNode(
          "Initialize a new audit run...",
          vscode.TreeItemCollapsibleState.None,
          [],
          { command: "sec-audit.init", title: "Init Audit Run" },
          "Phase 1a",
          undefined,
          new vscode.ThemeIcon("play")
        )
      ]);
      findingsProvider.setRoots([]);
      ledgerProvider.setRoots([]);
      diagnostics.clear();
      return;
    }

    let targetRoot = "";
    try {
      const metaRaw = fs.readFileSync(path.join(activeOutputDir, "run-metadata.json"), "utf8");
      const meta = JSON.parse(metaRaw);
      targetRoot = meta.target || "";
    } catch (_) {
      // ignore
    }

    // 1. Populate Status Tree
    try {
      const st = await execSecAudit("status", { output_dir: activeOutputDir });
      const actionNodes = (st.next_required_actions || []).map((act) =>
        new AuditNode(act, vscode.TreeItemCollapsibleState.None, [], undefined, "", act, new vscode.ThemeIcon("arrow-right"))
      );
      const driftNodes = (st.source_drift_files || []).map((df) => {
        const safeDriftPath = resolveContainedPath(targetRoot, df);
        return new AuditNode(
          df,
          vscode.TreeItemCollapsibleState.None,
          [],
          safeDriftPath ? { command: "sec-audit.openLocation", title: "Open File", arguments: [safeDriftPath, 1] } : undefined,
          "SHA-256 drift",
          df,
          new vscode.ThemeIcon("warning")
        );
      });
      const budgetStr = st.budget !== undefined && st.budget !== null ? `${st.agents_spent} / ${st.budget}` : `${st.agents_spent} (unbounded)`;
      const roots = [
        new AuditNode(`Run: ${st.run_id}`, vscode.TreeItemCollapsibleState.None, [], undefined, `${st.repo} (${st.profile})`, activeOutputDir, new vscode.ThemeIcon("shield")),
        new AuditNode(`Status: ${st.run_status}`, vscode.TreeItemCollapsibleState.None, [], undefined, `Wave ${st.current_wave}`, undefined, new vscode.ThemeIcon(st.ready_to_render ? "pass" : "sync")),
        new AuditNode(`Agents Spent: ${budgetStr}`, vscode.TreeItemCollapsibleState.None, [], undefined, `Arch: ${st.architecture_written ? "ok" : "missing"}`, undefined, new vscode.ThemeIcon("hubot")),
        new AuditNode(`Next Actions (${actionNodes.length})`, vscode.TreeItemCollapsibleState.Expanded, actionNodes, undefined, st.ready_to_render ? "Ready" : "Pending", undefined, new vscode.ThemeIcon("checklist"))
      ];
      if (driftNodes.length > 0) {
        roots.push(new AuditNode(`Source Drift Detected (${driftNodes.length})`, vscode.TreeItemCollapsibleState.Expanded, driftNodes, undefined, "FAIL CLOSED", undefined, new vscode.ThemeIcon("error")));
      }
      const reportPath = path.join(activeOutputDir, "REPORT.md");
      if (fs.existsSync(reportPath)) {
        roots.push(new AuditNode("Open REPORT.md", vscode.TreeItemCollapsibleState.None, [], { command: "sec-audit.openReport", title: "Open REPORT.md" }, "Phase 6", reportPath, new vscode.ThemeIcon("book")));
      }
      statusProvider.setRoots(roots);
    } catch (err) {
      statusProvider.setRoots([
        new AuditNode(`Status error: ${err.message}`, vscode.TreeItemCollapsibleState.None, [], undefined, "", err.message, new vscode.ThemeIcon("error"))
      ]);
    }

    // 2. Populate Findings Tree + Diagnostics
    const findingsPath = path.join(activeOutputDir, "findings.json");
    diagnostics.clear();
    if (fs.existsSync(findingsPath)) {
      try {
        const findings = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
        const diagMap = new Map();
        const byVerdict = { confirmed: [], needs_validation: [], rejected: [] };

        for (const f of findings) {
          const traceNodes = (f.trace || []).map((t, idx) => {
            const absFile = resolveContainedPath(targetRoot, t.file);
            return new AuditNode(
              `${idx + 1}. [${t.kind}] ${t.file}:${t.line}`,
              vscode.TreeItemCollapsibleState.None,
              [],
              absFile ? { command: "sec-audit.openLocation", title: "Open Source Trace", arguments: [absFile, t.line] } : undefined,
              t.scope,
              t.description,
              new vscode.ThemeIcon(t.kind === "sink" ? "flame" : t.kind === "entrypoint" ? "sign-in" : "arrow-small-right")
            );
          });
          const evNodes = (f.evidence || []).map((ev) => {
            const absFile = resolveContainedPath(targetRoot, ev.file);
            return new AuditNode(
              `${ev.file}:${ev.line}`,
              vscode.TreeItemCollapsibleState.None,
              [],
              absFile ? { command: "sec-audit.openLocation", title: "Open Evidence", arguments: [absFile, ev.line] } : undefined,
              "evidence",
              ev.description,
              new vscode.ThemeIcon("file-code")
            );
          });

          const sev = f.severity && f.severity.overall_severity ? f.severity.overall_severity.toUpperCase() : f.verdict.toUpperCase();
          const detailChildren = [
            new AuditNode(`Root Cause: ${f.root_cause || f.claimed_root_cause || "n/a"}`, vscode.TreeItemCollapsibleState.None, [], undefined, "", f.description, new vscode.ThemeIcon("info")),
            new AuditNode(`Source Trace (${traceNodes.length})`, vscode.TreeItemCollapsibleState.Expanded, traceNodes, undefined, "", "", new vscode.ThemeIcon("debug-step-into")),
            new AuditNode(`Evidence (${evNodes.length})`, vscode.TreeItemCollapsibleState.Collapsed, evNodes, undefined, "", "", new vscode.ThemeIcon("references"))
          ];
          const safeFP = typeof f.fingerprint === "string" && /^[A-Za-z0-9._:-]{3,80}$/.test(f.fingerprint) ? f.fingerprint : "";
          const advFile = safeFP ? resolveContainedPath(activeOutputDir, path.join("advisories", `GHSA-${safeFP}.md`)) : "";
          if (advFile && fs.existsSync(advFile)) {
            detailChildren.push(
              new AuditNode(
                `Open GHSA-${safeFP}.md`,
                vscode.TreeItemCollapsibleState.None,
                [],
                { command: "sec-audit.openLocation", title: "Open GHSA Advisory", arguments: [advFile, 1] },
                "Advisory",
                advFile,
                new vscode.ThemeIcon("megaphone")
              )
            );
          }

          const fNode = new AuditNode(
            `[${sev}] ${f.title}`,
            vscode.TreeItemCollapsibleState.Collapsed,
            detailChildren,
            undefined,
            f.fingerprint,
            f.description,
            new vscode.ThemeIcon(f.verdict === "confirmed" ? "bug" : f.verdict === "needs_validation" ? "question" : "circle-slash")
          );
          if (byVerdict[f.verdict]) {
            byVerdict[f.verdict].push(fNode);
          }

          // Add VS Code inline diagnostic at the sink (last trace element) for confirmed & needs_validation
          if ((f.verdict === "confirmed" || f.verdict === "needs_validation") && targetRoot && Array.isArray(f.trace) && f.trace.length > 0) {
            const sink = f.trace[f.trace.length - 1];
            const safeSinkPath = resolveContainedPath(targetRoot, sink.file);
            if (!safeSinkPath) continue;
            const sinkUri = vscode.Uri.file(safeSinkPath);
            const lineZero = Math.max(0, (sink.line || 1) - 1);
            const range = new vscode.Range(lineZero, 0, lineZero, 200);
            let diagSev = vscode.DiagnosticSeverity.Information;
            if (f.verdict === "confirmed" && f.severity) {
              const s = f.severity.overall_severity;
              diagSev = (s === "critical" || s === "high") ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning;
            }
            const msg = `[sec-audit ${f.fingerprint}] ${f.title}: ${f.root_cause || f.claimed_root_cause || f.description}`;
            const diag = new vscode.Diagnostic(range, msg, diagSev);
            diag.source = "sec-audit";
            diag.code = f.fingerprint;
            diag.relatedInformation = f.trace
              .map((t) => {
                const tp = resolveContainedPath(targetRoot, t.file);
                if (!tp) return null;
                return new vscode.DiagnosticRelatedInformation(
                  new vscode.Location(vscode.Uri.file(tp), new vscode.Position(Math.max(0, (t.line || 1) - 1), 0)),
                  `[${t.kind}] ${t.description}`
                );
              })
              .filter(Boolean);
            const key = sinkUri.toString();
            if (!diagMap.has(key)) diagMap.set(key, { uri: sinkUri, list: [] });
            diagMap.get(key).list.push(diag);
          }
        }

        for (const entry of diagMap.values()) {
          diagnostics.set(entry.uri, entry.list);
        }

        findingsProvider.setRoots([
          new AuditNode(`Confirmed (${byVerdict.confirmed.length})`, vscode.TreeItemCollapsibleState.Expanded, byVerdict.confirmed, undefined, "", "", new vscode.ThemeIcon("error")),
          new AuditNode(`Needs Validation (${byVerdict.needs_validation.length})`, vscode.TreeItemCollapsibleState.Expanded, byVerdict.needs_validation, undefined, "", "", new vscode.ThemeIcon("warning")),
          new AuditNode(`Rejected (${byVerdict.rejected.length})`, vscode.TreeItemCollapsibleState.Collapsed, byVerdict.rejected, undefined, "", "", new vscode.ThemeIcon("pass"))
        ]);
      } catch (_) {
        findingsProvider.setRoots([]);
      }
    } else {
      findingsProvider.setRoots([new AuditNode("No findings.json written yet", vscode.TreeItemCollapsibleState.None)]);
    }

    // 3. Populate Coverage Ledger Tree
    const ledgerPath = path.join(activeOutputDir, "coverage-ledger.json");
    if (fs.existsSync(ledgerPath)) {
      try {
        const units = JSON.parse(fs.readFileSync(ledgerPath, "utf8"));
        const groups = {};
        for (const u of units) {
          if (!groups[u.status]) groups[u.status] = [];
          const pathNodes = (u.starting_paths || []).map((sp) => {
            const absFile = resolveContainedPath(targetRoot, sp);
            return new AuditNode(
              sp,
              vscode.TreeItemCollapsibleState.None,
              [],
              absFile ? { command: "sec-audit.openLocation", title: "Open Starting Path", arguments: [absFile, 1] } : undefined,
              "starting_path",
              sp,
              new vscode.ThemeIcon("file")
            );
          });
          const uChildren = [
            new AuditNode(`ID: ${u.coverage_id}`, vscode.TreeItemCollapsibleState.None),
            new AuditNode(`Attack Class: ${u.attack_class}`, vscode.TreeItemCollapsibleState.None, [], undefined, u.ordinary_attack_class_block || ""),
            new AuditNode(`Prior Status: ${u.prior_status}`, vscode.TreeItemCollapsibleState.None, [], undefined, `Wave ${u.wave}`),
            new AuditNode(`Starting Paths (${pathNodes.length})`, vscode.TreeItemCollapsibleState.Collapsed, pathNodes)
          ];
          groups[u.status].push(
            new AuditNode(
              `${u.surface} -> ${u.boundary}`,
              vscode.TreeItemCollapsibleState.Collapsed,
              uChildren,
              undefined,
              `${u.attack_class} (${u.agent_id || "unassigned"})`,
              u.coverage_id,
              new vscode.ThemeIcon(u.status === "covered" ? "pass" : u.status === "candidate" ? "flame" : "circle-outline")
            )
          );
        }
        const statusNodes = Object.keys(groups).sort().map((stKey) =>
          new AuditNode(`${stKey} (${groups[stKey].length})`, vscode.TreeItemCollapsibleState.Collapsed, groups[stKey])
        );
        ledgerProvider.setRoots(statusNodes);
      } catch (_) {
        ledgerProvider.setRoots([]);
      }
    } else {
      ledgerProvider.setRoots([]);
    }
  }

  // Register navigation & helper commands
  context.subscriptions.push(
    vscode.commands.registerCommand("sec-audit.openLocation", async (filePath, line) => {
      if (!filePath || !fs.existsSync(filePath)) {
        vscode.window.showWarningMessage(`File not found on disk: ${filePath}`);
        return;
      }
      try {
        const st = fs.lstatSync(filePath);
        if (st.isSymbolicLink() || !st.isFile()) {
          vscode.window.showWarningMessage(`Refusing to open non-regular or symlinked file: ${filePath}`);
          return;
        }
      } catch (_) {
        return;
      }
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
      const editor = await vscode.window.showTextDocument(doc, { preview: true });
      const lineZero = Math.max(0, (line || 1) - 1);
      const pos = new vscode.Position(lineZero, 0);
      editor.selection = new vscode.Selection(pos, pos);
      editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
    }),

    vscode.commands.registerCommand("sec-audit.openReport", async () => {
      if (!activeOutputDir) return;
      const rpt = resolveContainedPath(activeOutputDir, "REPORT.md");
      if (rpt && fs.existsSync(rpt)) {
        const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(rpt));
        await vscode.window.showTextDocument(doc);
      }
    }),

    vscode.commands.registerCommand("sec-audit.openCatalogBlock", async (blockRef) => {
      try {
        const blk = await execSecAudit("catalog", { block: blockRef });
        const content = `# ${blk.file} (${blk.name})\n\n- **Reference**: \`${blk.ref}\`\n- **Kind**: \`${blk.kind}\`\n\n---\n\n${blk.content || ""}`;
        const doc = await vscode.workspace.openTextDocument({ content, language: "markdown" });
        await vscode.window.showTextDocument(doc, { preview: true });
      } catch (err) {
        vscode.window.showErrorMessage(`Catalog error: ${err.message}`);
      }
    }),

    vscode.commands.registerCommand("sec-audit.selectOutputDir", async () => {
      const picked = await vscode.window.showOpenDialog({
        canSelectFiles: false,
        canSelectFolders: true,
        canSelectMany: false,
        openLabel: "Select sec-audit Run Directory"
      });
      if (picked && picked.length > 0) {
        activeOutputDir = picked[0].fsPath;
        await vscode.workspace.getConfiguration("secAudit").update("outputDir", activeOutputDir, vscode.ConfigurationTarget.Workspace);
        setupWatcher(activeOutputDir);
        await refreshAll();
      }
    })
  );

  // Register 1:1:1 commands for all 13 registry subcommands
  context.subscriptions.push(
    vscode.commands.registerCommand("sec-audit.status", async () => {
      await refreshAll();
      if (activeOutputDir) {
        vscode.window.showInformationMessage(`Refreshed sec-audit status for ${activeOutputDir}`);
      }
    }),

    vscode.commands.registerCommand("sec-audit.init", async () => {
      const folders = vscode.workspace.workspaceFolders;
      const defaultTarget = folders && folders.length > 0 ? folders[0].uri.fsPath : "";
      const target = await vscode.window.showInputBox({ prompt: "Target repository path", value: defaultTarget });
      if (!target) return;
      const profile = await vscode.window.showQuickPick(["standard", "quick", "deep"], { placeHolder: "Select audit profile" });
      if (!profile) return;
      try {
        const res = await execSecAudit("init", { target, profile });
        activeOutputDir = res.output_dir;
        setupWatcher(activeOutputDir);
        await refreshAll();
        vscode.window.showInformationMessage(`Initialized audit run at ${activeOutputDir}`);
      } catch (err) {
        vscode.window.showErrorMessage(`sec-audit init failed: ${err.message}`);
      }
    }),

    vscode.commands.registerCommand("sec-audit.catalog", async () => {
      await loadCatalogTree();
      vscode.window.showInformationMessage("Refreshed Attack-Class Catalog view.");
    }),

    vscode.commands.registerCommand("sec-audit.validate", async () => {
      if (!activeOutputDir) {
        vscode.window.showWarningMessage("Select an active audit run directory first.");
        return;
      }
      try {
        const res = await execSecAudit("validate", { output_dir: activeOutputDir });
        await refreshAll();
        if (res.valid) {
          vscode.window.showInformationMessage(`Validation PASSED (${res.units_count} units, ${res.findings_count} findings).`);
        } else {
          vscode.window.showErrorMessage(`Validation FAILED: ${(res.ledger_errors || []).concat(res.finding_errors || []).join("; ")}`);
        }
      } catch (err) {
        vscode.window.showErrorMessage(`sec-audit validate failed: ${err.message}`);
      }
    }),

    vscode.commands.registerCommand("sec-audit.render", async () => {
      if (!activeOutputDir) {
        vscode.window.showWarningMessage("Select an active audit run directory first.");
        return;
      }
      try {
        const res = await execSecAudit("render", { output_dir: activeOutputDir });
        await refreshAll();
        vscode.window.showInformationMessage(`Rendered Phase 6 reports (${res.confirmed_count} confirmed, ${(res.advisory_paths || []).length} GHSA advisories).`);
        if (res.report_path && fs.existsSync(res.report_path)) {
          const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(res.report_path));
          await vscode.window.showTextDocument(doc);
        }
      } catch (err) {
        vscode.window.showErrorMessage(`sec-audit render failed: ${err.message}`);
      }
    })
  );

  // Generic JSON-prompted handler for remaining 1:1 orchestration subcommands when invoked manually from Command Palette
  const interactiveSubcommands = [
    { sub: "architecture", prompt: "Enter JSON payload for architecture (e.g. {\"content\":\"# Arch...\"})" },
    { sub: "ledger-seed", prompt: "Enter JSON payload for ledger-seed (e.g. {\"units\":[...],\"carryover_unchanged\":true})" },
    { sub: "agent-assign", prompt: "Enter JSON payload for agent-assign (e.g. {\"role\":\"hunter\",\"agent_id\":\"hunt-1\",\"coverage_ids\":[...]})" },
    { sub: "artifact-promote", prompt: "Enter JSON payload for artifact-promote (e.g. {\"agent_id\":\"hunt-1\",\"files\":[\"out.txt\"]})" },
    { sub: "hunter-submit", prompt: "Enter JSON payload for hunter-submit (e.g. {\"agent_id\":\"hunt-1\",\"result\":{...}})" },
    { sub: "critic-submit", prompt: "Enter JSON payload for critic-submit (e.g. {\"agent_id\":\"critic-1\",\"critic_kind\":\"post_wave\",\"result\":{...}})" },
    { sub: "verifier-submit", prompt: "Enter JSON payload for verifier-submit (e.g. {\"agent_id\":\"ver-1\",\"fingerprint\":\"FIND-0001\",\"decision\":\"confirmed\",\"record\":{...}})" },
    { sub: "record-verify-submit", prompt: "Enter JSON payload for record-verify-submit (e.g. {\"agent_id\":\"rec-1\",\"fingerprint\":\"FIND-0001\",\"decision\":\"verified\"})" }
  ];

  for (const item of interactiveSubcommands) {
    context.subscriptions.push(
      vscode.commands.registerCommand(`sec-audit.${item.sub}`, async () => {
        if (!activeOutputDir) {
          vscode.window.showWarningMessage("Select an active audit run directory first.");
          return;
        }
        const raw = await vscode.window.showInputBox({ prompt: item.prompt, placeHolder: "{ ... }" });
        if (!raw) return;
        try {
          const payload = JSON.parse(raw);
          if (!payload.output_dir) payload.output_dir = activeOutputDir;
          const res = await execSecAudit(item.sub, payload);
          await refreshAll();
          if (item.sub === "agent-assign" && res && res.prompt) {
            await vscode.env.clipboard.writeText(res.prompt);
            vscode.window.showInformationMessage(`Assigned ${res.agent_id} (${res.role}) and copied compiled prompt to clipboard.`);
          } else {
            vscode.window.showInformationMessage(`sec-audit ${item.sub} succeeded.`);
          }
        } catch (err) {
          vscode.window.showErrorMessage(`sec-audit ${item.sub} failed: ${err.message}`);
        }
      })
    );
  }

  setupWatcher(activeOutputDir);
  loadCatalogTree();
  refreshAll();
}

function deactivate() {}

module.exports = { activate, deactivate };
