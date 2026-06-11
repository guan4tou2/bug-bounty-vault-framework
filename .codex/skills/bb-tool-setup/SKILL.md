---
name: bb-tool-setup
description: Use when the zero-LLM tool layer (Ring 2) is not yet established or needs configuring — before the first hunter/scanner run on a machine, when the bbflow CLI or your scanner is not found, or when no candidates.jsonl is being produced. Triggers include set up scanner, establish tool layer, configure bbflow, run hunters (first time), no candidates.
---

# Bug Bounty — Tool Layer Setup (establish Ring 2 and wire it into the loop)

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-tool-setup/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-tool-setup/SKILL.md` before acting.
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
