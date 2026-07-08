---
name: bb-attack-chain-review
description: Use when a new finding candidate, interesting observation, info leak, auth bug, IDOR, CORS, SSRF, token leak, debug endpoint, source map, or unauth API may chain into higher impact — the lightweight review AFTER dedup that decides whether a candidate warrants escalating to the attack-chain-deep-dive agent. — distinct from bb-exploit-chain: that is the inline 6-question reflex run the moment a vuln is found; this runs after dedup to gate escalation.
---

# Bug Bounty — Attack Chain Review

This is a Gemini CLI compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-attack-chain-review/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `GEMINI.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-attack-chain-review/SKILL.md` before acting.
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
