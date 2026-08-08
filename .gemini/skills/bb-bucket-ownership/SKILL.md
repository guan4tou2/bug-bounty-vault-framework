---
name: bb-bucket-ownership
description: Use when a LISTABLE / publicly-accessible cloud bucket (S3 / GCS / Azure Blob / CDN origin) is found — BEFORE attributing it to the target or opening a Finding/Submission. LISTABLE does not equal owned-by-target; verify content-based ownership to avoid false attribution to a third party / CDN / shared bucket. Triggers: LISTABLE bucket / public S3 / GCS bucket / azure blob / bucket ACL misconfig / scanner reports bucket.
---

# Bug Bounty — Cloud Bucket Ownership Verification Gate

This is a Gemini CLI compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-bucket-ownership/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `GEMINI.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-bucket-ownership/SKILL.md` before acting.
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
