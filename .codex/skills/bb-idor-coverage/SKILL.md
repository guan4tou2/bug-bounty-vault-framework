---
name: bb-idor-coverage
description: Use when an IDOR is found or being tested — BEFORE marking it complete for a resource type — to enforce the full HTTP verb / coverage matrix (read AND write: GET + POST/PUT/PATCH/DELETE, object-ID variants, cross-tenant) so testing does not stop at GET and miss higher-severity write-path IDOR. The coverage / stop-condition GATE; complements (not replaces) the idor-broken-object-authorization technique skill. Triggers: IDOR / resource ID / object reference / before closing IDOR test.
---

# Bug Bounty — IDOR Coverage Matrix (Full Verb Stop-Condition Gate)

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-idor-coverage/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-idor-coverage/SKILL.md` before acting.
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
