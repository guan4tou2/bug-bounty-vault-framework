---
name: bb-bucket-ownership
description: Use when a LISTABLE / publicly-accessible cloud bucket (S3 / GCS / Azure Blob / CDN origin) is found — BEFORE attributing it to the target or opening a Finding/Submission. LISTABLE does not equal owned-by-target; verify content-based ownership to avoid false attribution to a third party / CDN / shared bucket. Triggers: LISTABLE bucket / public S3 / GCS bucket / azure blob / bucket ACL misconfig / scanner reports bucket.
---

# Bug Bounty — Cloud Bucket Ownership Verification Gate

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-bucket-ownership/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-bucket-ownership/SKILL.md` before acting.
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
