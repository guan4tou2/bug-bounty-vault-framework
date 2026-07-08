---
name: bb-actuator-cloud-chain
description: Use when auditing exposed Spring Boot management endpoints (Actuator / Eureka / Jolokia / Nacos) for config/credential disclosure and, in cloud deployments, cloud-metadata reachability — the management-endpoint → config → cloud-metadata AUDIT chain (detect, validate, severity, writeup), distinct from generic SSRF and from batch debug-endpoint scanning. Triggers: actuator / X-Application-Context / eureka / nacos / jolokia / gateway routes / spring boot / cloud metadata / heapdump.
---

# Bug Bounty — Actuator/Nacos/Eureka → Cloud-Metadata Chain Audit

This is a Gemini CLI compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-actuator-cloud-chain/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `GEMINI.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-actuator-cloud-chain/SKILL.md` before acting.
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
