---
name: bb-incident-response
description: Use when testing may have caused service impact, target returns sustained 502/503/504 after an action, vendor reports downtime, or user reports unintended impact.
---

# Bug Bounty — Accidental Service Disruption Response SOP

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-incident-response/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-incident-response/SKILL.md` before acting.
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
