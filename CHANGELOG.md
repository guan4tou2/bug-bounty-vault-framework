# Changelog

## 2.0.0 — 2026-05-22

### Breaking: Obsidian Vault-as-Top-Level Architecture

Complete restructuring from flat skeleton layout to production Obsidian vault structure.

**Removed:**
- `agents/`, `prompts/`, `skills/`, `hooks/`, `scripts/` (flat layout directories)

**Added:**
- Obsidian numbered folders: `00 - Dashboard/`, `01 - Targets/`, `01 - Dorks/`, `07 - Templates/`, `09 - Knowledge Base/`, `10 - Meta/`
- `.claude/agents/` — 5 specialized agents (bbflow-runner, cvss-auto-scorer, pre-recon, submit-form, vault-sync)
- `.claude/skills/` — 7 workflow skills (version-cve-precheck, dedup-finding, cve-citation, hitcon-form, context-handoff, triage-response, incident-response)
- `.codex/skills/` + `.gemini/skills/` — mirrored from Claude (source of truth)
- `automation/` — session lifecycle scripts (init_target.sh, start_session.py, end_session.py, check_vault.py, claim.sh, release.sh)
- `tools/` — scanner seed configs (Nuclei templates, Osmedeus profiles, BBOT presets)
- `_automation/lint_frontmatter.py` — pre-commit frontmatter validation
- `07 - Templates/` — 14 Obsidian templates (Finding, Submission, Target, Pattern, Kanban, etc.)
- `09 - Knowledge Base/` — 3 seed Patterns (IDOR, CORS, OAuth) + Lessons Learned + Wiki Schema
- `01 - Targets/_example/` — full target subfolder tree
- `STRUCTURE.md` — directory tree + naming conventions + frontmatter schema
- `VAULT_QUICK.md` — vault-level quick reference

**Changed:**
- `AGENTS.md` — rewritten as full workflow specification (§0-§9)
- `AGENTS_QUICK.md` — rewritten with session lifecycle commands
- `CLAUDE.md` — rewritten with skill trigger table + subagent injection rules
- `CODEX.md` / `GEMINI.md` — rewritten with platform-specific guides
- `README.md` — updated for vault-as-top-level architecture
- `.gitignore` — updated for Obsidian + workspace + automation runtime
- `workspace/` — restructured with reports/{platform}/, firmware_analysis/, workshop/
- `docs/session-lifecycle.md` — full claim/work/closeout protocol

### Migration from 1.x

The 1.x flat layout (`scripts/`, `agents/`, `prompts/`) is no longer used. If you adopted 1.x:
1. Back up your private vault
2. Clone the new 2.0 structure
3. Copy your target data into `01 - Targets/` and `workspace/workshop/`
4. Move any custom skills to `.claude/skills/`

---

## 1.x — 2026-05-22 (prior commits)

Initial public skeleton with flat layout: `scripts/`, `agents/`, `prompts/`, `skills/`, `hooks/`, `bbflow/`, `docs/`, `templates/`, `workspace/`, `tests/`.
