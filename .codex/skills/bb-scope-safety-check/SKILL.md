---
name: bb-scope-safety-check
description: Use when scans, fuzzing, payloads, POST/PUT/PATCH/DELETE, bbflow hunt/flow, Osmedeus, Nuclei, BBOT, or live verification may write data or create service impact.
---

# Bug Bounty — Scope Safety Check

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-scope-safety-check/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-scope-safety-check/SKILL.md` before acting.
3. Follow the canonical skill exactly, adapting Claude-specific tool names to Codex tools:
   - Claude `Skill` call -> read the referenced `SKILL.md`.
   - Claude subagent instruction -> do the work locally unless the user explicitly requests Codex subagents.
   - `Read` / `Edit` / `Bash` -> Codex file tools and shell.
4. If the canonical file is unavailable, stop and report that the repo skill mirror is incomplete.

## Maintenance

Do not edit this wrapper by hand. Run:

```bash
python3 automation/sync_codex_skills.py
```
