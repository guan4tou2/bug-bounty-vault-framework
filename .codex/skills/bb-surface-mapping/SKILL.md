---
name: bb-surface-mapping
description: Use when starting work on any target — after recon, before any pattern/hunter/scan/dedup — to force vuln-agnostic full attack-surface mapping that counters the streetlight effect (pattern tunnel vision). Triggers include start recon, explore, map the attack surface.
---

# Bug Bounty — Surface Mapping (explore-first, anti-streetlight)

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-surface-mapping/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-surface-mapping/SKILL.md` before acting.
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
