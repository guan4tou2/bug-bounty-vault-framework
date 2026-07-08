---
name: bb-attack-chain-review
description: Use when a new finding candidate, interesting observation, info leak, auth bug, IDOR, CORS, SSRF, token leak, debug endpoint, source map, or unauth API may chain into higher impact — the lightweight review AFTER dedup that decides whether a candidate warrants escalating to the attack-chain-deep-dive agent. — distinct from bb-exploit-chain: that is the inline 6-question reflex run the moment a vuln is found; this runs after dedup to gate escalation.
---

# Bug Bounty — Attack Chain Review

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-attack-chain-review/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-attack-chain-review/SKILL.md` before acting.
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
