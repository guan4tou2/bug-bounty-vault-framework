---
name: bb-context-handoff
description: Use when session context is low, work needs checkpointing, takeover is needed, user says 快滿了/整理進度/handoff/checkpoint/context low/takeover/接手, or a long bug bounty session reaches a natural handoff point.
---

# Bug Bounty — Context Window Management + Takeover Protocol

> **Promoted from AGENTS.md (the bb-context-handoff skill) to a standalone skill (2026-05-16):** A handoff is a high-risk operation — done incorrectly it causes loss of work-in-progress. A standalone skill forces the full process to run.

## When to Trigger a Handoff

**The LLM cannot sense how many tokens remain.** Trigger on any of the following:

| Trigger | Situation |
|---|---|
| Explicit user request | "running out of context / summarize progress / handoff / checkpoint / takeover" |
| Natural LLM milestone | Finished writing a report, completed a large PoC, confirmed or ruled out a hypothesis — natural breakpoint |
| Structural check | Same session has run >= 30 turns or >= 1.5 hours — check whether a handoff is appropriate |
| System signal | Claude Code displays a context warning |

## Handoff Process (current session — context nearly full)

### Step 1: Verify lock is alive

```bash
jq . automation/active_sessions/<scope>.lock
# Check last_heartbeat is recent; update if needed:
python3 -c "
import json, datetime, pathlib
p = pathlib.Path('automation/active_sessions/<scope>.lock')
d = json.loads(p.read_text())
d['last_heartbeat'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
p.write_text(json.dumps(d, indent=2))
"
```

Ensure the lock is still alive. A stale lock may be claimed by another session using `--force`.

### Step 2: Do NOT release the lock

Leave it for the takeover session to claim with `--takeover`; otherwise another session may grab it.

### Step 3: Write an In-Progress block to HANDOFF.md

Edit `workspace/workshop/<target>/HANDOFF.md` and add:

```markdown
<!-- BEGIN_INPROGRESS — written by the handoff process; a new dump will overwrite this block -->
## In-Progress (session <short-id> → next session takeover)

> Handoff time: <ISO timestamp>
> Reason: <context-low / explicit-handoff / milestone>
> Model: <claude-sonnet-4-6 / claude-opus-4-7>
> Scope: <lock scope>

### Completed (do not redo)
- [x] ...

### In Progress (takeover session's first step)
- [ ] **next**: <command / URL precise enough to copy-paste and execute>

### Confirmed hypotheses
- ...

### Ruled-out hypotheses
- ...

### Pending decisions (confirm in takeover session)
- ...

### File locations
- workspace/workshop/<target>/recon/...
- Vault 01 - Targets/<t>/Findings/Finding - <t> - <ID>.md

### DO NOT do (avoid repeating)
- ...
<!-- END_INPROGRESS -->
```

### Step 4: Commit and close

```bash
git add workspace/workshop/<target>/HANDOFF.md
git commit -m "[handoff] <target>: context-low @ <milestone>"
```

## Takeover Process (new session)

### Step 1: Read the environment

```bash
bash automation/check_active_sessions.sh
cat workspace/workshop/<target>/HANDOFF.md
```

### Step 2: Check the `## In-Progress` block

**If an In-Progress block exists:**

```bash
bash automation/claim.sh <scope> --takeover --owner=<new model>
# claim.sh verifies that HANDOFF.md contains BEGIN_INPROGRESS; rejects if not found.
# On success, moves the previous session lock to _expired/<scope>.takeover-from-<sid>
```

**If no In-Progress block exists:** use `claim.sh <scope>` for a normal claim (the previous session completed naturally; this is not a takeover scenario).

### Step 3: First message to the user

```
Takeover from session `<previous-id>`. Immediate next step: `<first item from In-Progress>`
```

### Step 4: Update In-Progress as work proceeds

The In-Progress block can be updated at any point during work (replace content between the BEGIN/END markers). The markers isolate this block; other automation scripts will not touch it.

### Step 5: After all In-Progress items are complete

Delete the block content (keep the markers but leave the content empty), then run vault-sync to write `## Last Completed Session`.

## `--takeover` vs `--force`

| Option | Purpose | HANDOFF.md requirement |
|---|---|---|
| `--takeover` | Cooperative handoff (previous session context full, left handoff notes) | Must have BEGIN_INPROGRESS block |
| `--force` | Forced grab (previous session crashed, expired without auto-cleanup, left no handoff) | No check; risk of data loss |

## Manual Operations for Abnormal Terminations

| Situation | Action |
|---|---|
| Session ended but `session_end_checklist.sh` was not run | `bash automation/release.sh <scope>` to release manually |
| Lock expired 30+ minutes ago and still in active_sessions/ (sweep did not fire) | `bash automation/release.sh --all` to clear all + notify maintenance |
| Want to see recent history | `git log --oneline --grep "<target>:" -20` (HANDOFF.md does not store Recent Activity to avoid accidental `git add -A` inclusion) |
| Vault Dashboard out of sync | Update `00 - Dashboard/Dashboard.md` manually (or implement a regen script) |

## Quick Reference Commands

```bash
# See what is currently active
bash automation/check_active_sessions.sh

# See recent activity for <target> (replaces Recent Activity)
git log --oneline --grep "<target>:" -20

# Inspect a single lock
jq . automation/active_sessions/<scope>.lock
```

## Cross-reference

- automation/start_session.py (claim + brief)
- automation/end_session.py (checklist + release)
- automation/check_vault.py (health check)
- automation/claim.sh / release.sh (bash wrappers)
- automation/templates/HANDOFF_template.md
- skill bb-triage-response (if the handoff coincides with a pending triage response)
