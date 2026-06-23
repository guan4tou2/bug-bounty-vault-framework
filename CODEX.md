# Codex Workspace Guide

Codex must read these files when starting work:

1. [AGENTS_QUICK.md](./AGENTS_QUICK.md) -- token-light session start/end/minimal audit path
2. This file -- Codex-specific supplements
3. Deep-read [AGENTS.md](./AGENTS.md) / [STRUCTURE.md](./STRUCTURE.md) sections as triggered by task context

---

## Codex Skills

Codex-native skills live in `.codex/skills/`. They are synced from `.claude/skills/` (the source of truth).

### Sync and Install

```bash
# Sync skills from Claude source of truth
python3 automation/sync_codex_skills.py

# Install Codex skills (one-time setup)
bash automation/install_codex_skills.sh
```

Skills are functionally identical to the Claude versions. See [CLAUDE.md](CLAUDE.md) for the full skill trigger table.

> Note: the `.codex/skills/` mirror also includes a `bb-agent-prompts` router skill that does not exist in `.claude/skills/`. It is a CLI-specific add-on (see Agents below), not part of the Claude skill set, so it is absent from CLAUDE.md's trigger table.

## Agents

Claude Code ships 6 specialized agents in `.claude/agents/` (attack-chain-deep-dive, bbflow-runner, cvss-auto-scorer, pre-recon, report-writer, vault-sync). Codex CLI does not run these natively, but their prompts are plain Markdown you can load on demand. The generated `bb-agent-prompts` skill routes common requests (e.g. "run hunters", "pre-recon", "score CVSS") to the right agent prompt under `.claude/agents/*.md`.

**Subagent convention:** if you spawn subagents, they do **not** inherit this file or `AGENTS.md`. Inject the relevant rules into the subagent prompt by task tier (recon / analysis / output) — see the *Subagent Convention Injection* table and quick template in [CLAUDE.md](CLAUDE.md).

---

## Session Start

### Parallel Conflict Prevention

```bash
bash automation/check_active_sessions.sh
bash automation/claim.sh <scope> [--eta-minutes=N]
```

Scope formats: `_meta` (rules/automation/workspace docs), `<target>`, `<target>/<sub-service>`, or finer sub-scope.

For target work:

```bash
bash automation/session_start_brief.sh <target> "<keyword>" "<host_or_endpoint>"
```

Summarizes HANDOFF, FINDINGS_QUICK_REF, RECON_DB highlights. Only deep-read full files when the brief points to relevant sections.

Software/firmware/SaaS targets: run AGENTS.md section 0g version + CVE/advisory pre-flight before analysis.

For multi-surface, branching validation, decision-gate, or pentest-route work, create `07 - Templates/Template - Target Work DAG.md` and start with `bash automation/dag_gaps.sh <target>`. The DAG is for improving hunting and penetration effectiveness first; compact reading is secondary.

### Session End

```bash
bash automation/session_end_brief.sh <scope>
# Then by scope:
#   _meta: bash automation/audit_workspace.sh meta && bash automation/release.sh _meta
#   target: bash automation/session_end_checklist.sh <target>
```

---

## Workspace Rules Summary

### Finding Pipeline (every vulnerability)

1. **Finding** -- discovery note (what, when, how, evidence)
2. **Submission** -- platform-ready report draft
3. **FORM** -- platform-neutral disclosure draft or private downstream adapter output

Order is mandatory: Finding first, then Submission, then FORM. IDs must match across all three.

### Dedup Before New Finding

```bash
bash automation/vault_precheck.sh <target> "<keyword>" "<host_or_endpoint>"
```

If it matches an existing Finding/Submission, create an Attempt first, then decide whether to upgrade.

### Report Writing

- Include verified reproduction steps with complete curl/commands
- Distinguish verified vs potential impact
- Never write inference as verified fact
- Never include internal finding IDs in platform submissions
- Chain low-impact findings before reporting

### Knowledge Base

- New KB files use proper prefix: `Pattern -`, `Playbook -`, `Checklist -`, `Tool -`, `Resource -`, `Reference Card -`
- After creating/modifying KB: run validation

```bash
python3 automation/check_vault.py
```

---

## Operation Safety Summary

| Rule | Details |
|------|---------|
| **GET-first** | POST/PUT/PATCH/DELETE requires known consequence; uncertain = do not execute |
| **Isolated runner for risky ops** | VPS or another isolated runner is recommended for scanning, fuzzing, payload testing, and production writes |
| **Never-execute list** | stop/destroy/shutdown/kill/restart ops; bulk delete; email/SMS triggers |
| **Operation log** | Log non-scan commands to RECON_DB before executing |
| **Anti-exaggeration** | Theoretical chains are not facts; severity matches evidence level |

---

## Codex-Specific Notes

1. New report canonical location is in Vault `Submissions/Forms/`
2. PoC/payload files go to `workspace/workshop/<target>/poc/`
3. Do not create new `.md` files at the repository root
4. Never use `git add -A` -- stage specific files only
5. If Vault and workspace are separate git repos, commit independently

---

## Quick Pointer Table

| Topic | Location |
|-------|----------|
| Full workflow rules | [AGENTS.md](AGENTS.md) |
| Directory tree / naming / templates | [STRUCTURE.md](STRUCTURE.md) |
| Session lifecycle | [docs/session-lifecycle.md](docs/session-lifecycle.md) |
| Workspace audit | `python3 automation/check_vault.py` |
