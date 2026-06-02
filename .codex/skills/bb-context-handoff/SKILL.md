---
name: bb-context-handoff
description: Use when session context is low, work needs checkpointing, takeover is needed, user says 快滿了/整理進度/handoff/checkpoint/context low/takeover/接手, or a long bug bounty session reaches a natural handoff point.
---

# Bug Bounty — Context Window Management + Takeover Protocol

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-context-handoff/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-context-handoff/SKILL.md` before acting.
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
