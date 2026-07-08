---
name: bb-knowledge-capture
description: Use when a session, finding candidate, failed attempt, attack chain review, tool result, triage reply, or new observation teaches something reusable that should update Pattern, Lessons Learned, Checklist, Tool notes, or bbflow templates — promotes a GENERALIZABLE lesson/pattern to the KB. — distinct from bb-attempt-recorder: that records a raw target-specific negative result; this promotes reusable knowledge across targets.
---

# Bug Bounty — Knowledge Capture

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-knowledge-capture/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-knowledge-capture/SKILL.md` before acting.
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
