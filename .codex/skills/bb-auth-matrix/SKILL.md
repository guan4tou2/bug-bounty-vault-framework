---
name: bb-auth-matrix
description: Use when testing authorization, IDOR, privilege escalation, role confusion, multi-tenant isolation, JWT/session scope, or any access control boundary. Builds a Role × Endpoint × Operation matrix and tests every cell systematically.
---

# Bug Bounty — Auth Matrix

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-auth-matrix/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-auth-matrix/SKILL.md` before acting.
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
