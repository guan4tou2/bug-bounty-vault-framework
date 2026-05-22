---
name: bb-dedup-finding
description: Use when opening a new Finding or FORM, checking duplicate likelihood, deciding whether to merge reports, handling same endpoint/different user evidence, or user says 這不是挖過了嗎/同一漏洞/該不該合併.
---

# Bug Bounty — 重複 Finding 判定（§3f 規則 + 6 步驟）

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-dedup-finding/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-dedup-finding/SKILL.md` before acting.
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
