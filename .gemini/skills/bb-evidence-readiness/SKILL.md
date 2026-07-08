---
name: bb-evidence-readiness
description: Use when creating or reviewing a Finding, Submission, FORM, attack chain, or report evidence to verify reproducibility, Discovery Log completeness, audit references, and anti-overclaim discipline — the SUBSET check of whether the evidence alone is complete and reproducible. — distinct from bb-submission-readiness: that is the SUPERSET final gate (dedupe + scope + evidence + chain + severity + hygiene); this covers only the evidence portion inside it.
---

# Bug Bounty — Evidence Readiness

This is a Gemini CLI compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-evidence-readiness/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `GEMINI.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-evidence-readiness/SKILL.md` before acting.
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
