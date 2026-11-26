---
name: bb-reflexion-retry
description: Use when a tool call, exploit attempt, or validation step fails — structured reflection before retry instead of blind repetition. Triggers: tool failure, 'retry', 'try again', exploit returned unexpected result, scan error, authentication failure, repeated failure, 'why did that fail'.
---

# Bug Bounty — Reflexion Retry

This is a Gemini CLI compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-reflexion-retry/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `GEMINI.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-reflexion-retry/SKILL.md` before acting.
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
