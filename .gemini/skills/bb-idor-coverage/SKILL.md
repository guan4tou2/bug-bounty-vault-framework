---
name: bb-idor-coverage
description: Use when an IDOR is found or being tested — BEFORE marking it complete for a resource type — to enforce the full HTTP verb / coverage matrix (read AND write: GET + POST/PUT/PATCH/DELETE, object-ID variants, cross-tenant) so testing does not stop at GET and miss higher-severity write-path IDOR. The coverage / stop-condition GATE; complements (not replaces) the idor-broken-object-authorization technique skill. Triggers: IDOR / resource ID / object reference / before closing IDOR test.
---

# Bug Bounty — IDOR Coverage Matrix (Full Verb Stop-Condition Gate)

This is a Gemini CLI compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-idor-coverage/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `GEMINI.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-idor-coverage/SKILL.md` before acting.
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
