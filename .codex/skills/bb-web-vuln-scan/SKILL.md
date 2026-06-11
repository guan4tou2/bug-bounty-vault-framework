---
name: bb-web-vuln-scan
description: Use when testing a web target's endpoints/params for vulnerabilities — enforces OWASP Top 10 coverage, version→CVE lookup, the full injection matrix, WAF-bypass discipline, and dynamic (not hardcoded) parameter discovery. Triggers include scan, test, pentest, find vulns.
---

# Bug Bounty — Web Vulnerability Scan (OWASP coverage + version→CVE + injection matrix)

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-web-vuln-scan/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-web-vuln-scan/SKILL.md` before acting.
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
