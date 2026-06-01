# Changelog

## v0.1.1 — 2026-05-23

### Candidate Lifecycle Skills

Added 6 lifecycle gate skills and 1 agent to formalize the candidate-to-submission pipeline.

**Added:**
- `.claude/skills/` — 6 new lifecycle skills:
  - `bb-scope-safety-check` — scope + safety gate before live verification
  - `bb-attack-chain-review` — chain potential assessment
  - `bb-evidence-readiness` — evidence completeness gate
  - `bb-attempt-recorder` — negative result preservation
  - `bb-submission-readiness` — final gate before report
  - `bb-knowledge-capture` — reusable learning capture
- `.claude/agents/attack-chain-deep-dive.md` — deep analysis agent for complex chains
- `09 - Knowledge Base/Reference Card - Testing Safety Rules.md` — safety quick reference
- `09 - Knowledge Base/Reference Card - Knowledge Capture Quality Rubric.md` — KB quality rubric
- `AGENTS.md §3e.1` — candidate lifecycle gates specification
- Codex + Gemini skill mirrors auto-synced

**Changed:**
- Skill count: 7 → 13; agent count: 5 → 6
- `CLAUDE.md` — skill trigger table expanded with 6 new entries
- `AGENTS_QUICK.md` — candidate lifecycle pipeline diagram added
- Private data safety test strengthened (case-insensitive + expanded forbidden list)

## v0.1.0 — 2026-05-22

### Public Seed Release

Initial public seed for an Obsidian vault-as-top-level bug bounty workflow framework.

This release contains architecture, workflow, SOP, templates, optional LLM entrypoints, and seed scanner configuration. It intentionally excludes private targets, findings, report drafts, screenshots, scan output, credentials, and personal knowledge-base content.

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
- `docs/post-clone-checklist.md` — optional setup checklist after cloning

**Positioning:**
- Obsidian is the primary vault interface.
- LLM use is optional; Claude Code, Codex, and Gemini entrypoints are included for users who want them.
- VPS or another isolated runner is recommended for aggressive scanning, but not required for note-taking, templates, or low-risk local validation.
- Users are expected to grow their own private vault from this public seed.
