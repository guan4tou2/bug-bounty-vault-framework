---
name: bb-attempt-recorder
description: Use when a test, hypothesis, attack chain idea, payload, endpoint, scan result, or verification path does not produce a Finding but should be recorded as a raw negative result or stop condition for THIS target. — distinct from bb-knowledge-capture: this logs a target-specific negative outcome as-is; that promotes a generalizable, reusable lesson or pattern to the KB.
---

# Bug Bounty — Attempt Recorder

This is a Gemini CLI compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-attempt-recorder/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `GEMINI.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-attempt-recorder/SKILL.md` before acting.
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
