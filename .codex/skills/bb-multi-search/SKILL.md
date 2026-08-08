---
name: bb-multi-search
description: Use when mid-hunt and need quick ad-hoc research — fans out 4-6 query variations across security sources (NVD, H1, PortSwigger, exploit-db, GitHub) via parallel subagents, deduplicates, and returns a synthesized briefing. Local only, no third-party search API. Triggers: "research this", "any writeups for", "search for", "look this up", "is there prior art".
---

# bb-multi-search — Parallel Multi-Source Security Search

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-multi-search/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-multi-search/SKILL.md` before acting.
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
