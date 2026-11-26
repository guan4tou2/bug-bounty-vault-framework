---
name: bb-api-schema-diff
description: Use when target has OpenAPI/Swagger spec or API documentation. Compares documented API spec vs actual behavior to find undocumented endpoints, shadow APIs, parameter discrepancies, and auth mismatches.
---

# Bug Bounty — API Schema Diff

This is a Gemini CLI compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-api-schema-diff/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `GEMINI.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-api-schema-diff/SKILL.md` before acting.
3. Follow the canonical skill exactly, adapting Claude-specific tool names to Gemini tools:
   - Claude `Skill` call -> use `activate_skill` to load the referenced skill, or read the `SKILL.md` directly.
   - Claude subagent instruction -> do the work locally in this Gemini session.
   - `Read` / `Edit` / `Bash` -> Gemini file I/O and shell tools.
4. If the canonical file is unavailable, stop and report that the repo skill mirror is incomplete.

## Maintenance

Do not edit this wrapper by hand. Run:

```bash
python3 automation/sync_codex_skills.py
```
