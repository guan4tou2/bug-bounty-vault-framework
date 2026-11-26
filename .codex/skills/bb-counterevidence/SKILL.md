---
name: bb-counterevidence
description: Mandatory counterevidence gate before any Finding promotion or severity upgrade. Forces the strongest case AGAINST the finding being real or having its stated severity. Triggers: before creating Finding, before severity upgrade, before attack chain submission, before stakeholder report, 'challenge this finding', 'is this real'.
---

# Bug Bounty — Counterevidence Gate

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-counterevidence/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-counterevidence/SKILL.md` before acting.
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
