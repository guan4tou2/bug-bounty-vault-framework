---
name: bb-race-condition
description: Use when testing race conditions, TOCTOU, single-packet attacks, or concurrency bugs. Covers limit bypass, state confusion, and check-then-act patterns in rate limits, balance operations, coupon redemption, token consumption, and file processing.
---

# Bug Bounty — Race Condition

This is a Gemini CLI compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-race-condition/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `GEMINI.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-race-condition/SKILL.md` before acting.
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
