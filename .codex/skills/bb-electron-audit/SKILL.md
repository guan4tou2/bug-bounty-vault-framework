---
name: bb-electron-audit
description: Use when auditing an Electron / desktop app statically — asar extraction, shell.openExternal, preload / contextBridge, contextIsolation, custom scheme handler, IPC senderFrame. This is the ELECTRON-SPECIFIC audit PROCEDURE (10-min grading → 3-tier defense classification → delivery-chain gate), distinct from generic bb-exploit-chain / bb-attack-chain-review. Triggers: Electron / asar / shell.openExternal / preload / contextIsolation / desktop app static audit.
---

# Bug Bounty — Electron Static Audit (desktop-app-specific procedure)

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-electron-audit/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-electron-audit/SKILL.md` before acting.
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
