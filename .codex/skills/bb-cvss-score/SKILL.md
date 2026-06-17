---
name: bb-cvss-score
description: Use when creating or reviewing a Finding and you need a CVSS 3.1 vector + base score. Stateless desc→vector transform for common BB vuln classes (IDOR, SSRF, XSS, SQLi, RCE, auth bypass, file upload, business logic, OAuth, GraphQL). Triggers include 算 CVSS, CVSS 評分, severity 多少.
---

# Bug Bounty — CVSS 3.1 Scoring

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-cvss-score/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-cvss-score/SKILL.md` before acting.
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
