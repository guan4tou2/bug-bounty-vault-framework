---
name: bb-gap-research
description: Use when filling a knowledge gap from the Learning Backlog — user says "fill gap", "research the backlog", "research gaps", or picks an open gap to turn into a playbook. Trigger-based (NOT autonomous): you dispatch parallel research subagents, write playbooks, and mark the backlog status table.
---

# Bug Bounty — Gap Research (Triggered Knowledge Gap Filling)

This is a Gemini CLI compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-gap-research/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `GEMINI.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-gap-research/SKILL.md` before acting.
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
