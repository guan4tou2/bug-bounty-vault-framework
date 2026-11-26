---
name: bb-reflexion-retry
description: Use when a tool call, exploit attempt, or validation step fails — structured reflection before retry instead of blind repetition. Triggers: tool failure, 'retry', 'try again', exploit returned unexpected result, scan error, authentication failure, repeated failure, 'why did that fail'.
---

# Bug Bounty — Reflexion Retry

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-reflexion-retry/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-reflexion-retry/SKILL.md` before acting.
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
