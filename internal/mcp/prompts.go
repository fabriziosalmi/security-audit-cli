package mcp

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Instructions is sent in the initialize result. Clients that support it
// (Claude Code among them) put it in the model's context, so an agent knows
// how to drive the tools without the user explaining the protocol.
const Instructions = `sec-audit runs a gated, multi-agent security audit of a source repository and writes REPORT.md, findings.sarif and
GHSA-style advisories.

You are the coordinator. You do not judge findings yourself: you start fresh subagents with the prompts sec-audit
compiles, and you submit their JSON back. Every submission is checked on disk (file:line citations, SHA-256 pins, role
separation); a rejected submission returns the reason, so send it back to the same subagent to fix.

Start with sec_audit_init, then after every step call sec_audit_status and do what next_required_actions says until it
reports "ready: run sec-audit render". For the full procedure, use the "audit" prompt.

Rules the tools enforce: output_dir is outside the target; every agent_id is new, lowercase, and used once; a verifier
is never the hunter of the same finding; a record_verifier is neither. Never edit files in output_dir by hand. Local
checks only: do not touch live systems without asking the user.`

type promptArg struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// PromptDefs returns the prompts/list entries.
func PromptDefs() []map[string]any {
	return []map[string]any{{
		"name":        "audit",
		"description": "Run a complete sec-audit security audit of a repository, from recon to REPORT.md",
		"arguments": []promptArg{
			{Name: "target", Description: "Absolute path of the repository to audit", Required: true},
			{Name: "profile", Description: "quick, standard (default) or deep"},
			{Name: "output_dir", Description: "Run directory outside the target (default: <target>-sec-audit next to it)"},
		},
	}}
}

// GetPrompt renders a prompt by name with its arguments.
func GetPrompt(name string, args map[string]string) (map[string]any, error) {
	if name != "audit" {
		return nil, fmt.Errorf("unknown prompt %q", name)
	}
	target := strings.TrimSpace(args["target"])
	if target == "" {
		return nil, fmt.Errorf("argument target is required")
	}
	profile := strings.TrimSpace(args["profile"])
	if profile == "" {
		profile = "standard"
	}
	switch profile {
	case "quick", "standard", "deep":
	default:
		return nil, fmt.Errorf("profile must be quick, standard or deep, got %q", profile)
	}
	outDir := strings.TrimSpace(args["output_dir"])
	if outDir == "" {
		outDir = filepath.Clean(target) + "-sec-audit"
	}
	text := strings.NewReplacer(
		"{{TARGET}}", target,
		"{{PROFILE}}", profile,
		"{{OUTPUT_DIR}}", outDir,
	).Replace(auditPlaybook)
	return map[string]any{
		"description": "sec-audit procedure for " + target,
		"messages": []map[string]any{{
			"role":    "user",
			"content": map[string]any{"type": "text", "text": text},
		}},
	}, nil
}

const auditPlaybook = `Run a sec-audit security audit of {{TARGET}} with the {{PROFILE}} profile, writing the run to {{OUTPUT_DIR}}.

You are the coordinator. Use the sec_audit_* tools for every state change and start a fresh subagent for every role
assignment (hunter, critic, verifier, record_verifier). Never reuse a subagent across assignments, and never write
findings yourself.

1. Init. Call sec_audit_init with target={{TARGET}}, output_dir={{OUTPUT_DIR}}, profile={{PROFILE}}. Read repo_brief:
   languages, entrypoint candidates, recommended companion playbooks.

2. Architecture. Read the repository (source only, no network) and call sec_audit_architecture with at most 1,000
   words covering trust boundaries, entrypoints, privileged sinks and subsystems. Cite real paths.

3. Coverage plan. Call sec_audit_catalog to see the attack-class blocks. Build one coverage unit per (entry surface,
   trust boundary, attack-class block) worth checking, with starting_paths that exist in the target. Each unit looks
   like:
   {"canonical_refs": {"surface": "<file>#<symbol>", "boundary": "<file>#<symbol>", "subsystem": "<dir>",
                       "attack_class": "ATTACK-CLASSES.md#<Block>"},
    "surface": "...", "boundary": "...", "subsystem": "...", "attack_class": "ATTACK-CLASSES.md#<Block>",
    "starting_paths": ["<repo-relative file>"], "ordinary_attack_class_block": "ATTACK-CLASSES.md#<Block>",
    "selected_companion_blocks": [], "excluded_blocks": []}
   Seed them with sec_audit_ledger_seed.

4. Hunting wave. Split planned units into groups of 2 to 4. For each group:
   a. sec_audit_agent_assign role=hunter, agent_id=hunter-w<wave>-<letter>, coverage_ids=[...].
   b. Start a subagent whose task is exactly the returned prompt. It may only write to its scratch_dir.
   c. When it returns, call sec_audit_artifact_promote for the scratch files its checks cite, then
      sec_audit_hunter_submit with agent_id and its JSON as result.
   d. If a submission is rejected, give the error to the same subagent, get a corrected result, and submit again.

5. Coverage critic. After each wave: sec_audit_agent_assign role=critic with a new agent_id, run a subagent on the
   prompt, and submit with sec_audit_critic_submit critic_kind=post_wave. If it added or reassigned units, run another
   wave (step 4). When a wave ends with nothing to add, run one more critic with critic_kind=final_clean and
   stop=true.

6. Verification. For every fingerprint in sec_audit_status.unvalidated_candidate_fingerprints: sec_audit_agent_assign
   role=verifier with a new agent_id and that fingerprint, run a subagent on the prompt (it tries to refute the
   candidate), and submit {decision, record} with sec_audit_verifier_submit.

7. Record verification. For every fingerprint in unverified_phase5_fingerprints: sec_audit_agent_assign
   role=record_verifier with a new agent_id, run a subagent, submit with sec_audit_record_verify_submit. A "replace"
   decision needs one more fresh record_verifier.

8. Render. Call sec_audit_validate, then sec_audit_render with output_dir={{OUTPUT_DIR}}. If the budget ran out,
   render with incomplete_reason instead of skipping work.

9. Report to the user: confirmed findings with severity and file:line, the rejected candidates and why, and the paths
   of REPORT.md, findings.sarif and advisories/.

Call sec_audit_status whenever you are unsure what comes next: next_required_actions is authoritative. Ask the user
before running anything against a live system.`
