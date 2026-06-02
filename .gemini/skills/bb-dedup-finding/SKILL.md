---
name: bb-dedup-finding
description: Use when opening a new Finding or FORM, checking duplicate likelihood, deciding whether to merge reports, handling same endpoint/different user evidence, or user says "wasn't this already found" / "same vulnerability" / "should I merge". Triggers: 這不是挖過了嗎/同一漏洞/該不該合併
---

# Bug Bounty — Duplicate Finding Determination (§3f Rules + 6 Steps)

This is a Gemini CLI compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-dedup-finding/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `GEMINI.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-dedup-finding/SKILL.md` before acting.
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
