# Automation Conventions

> 2026-06-04: clarifies the roles of `automation/` vs `_automation/`, and the retained scope of the cross-session communication layer.

## Division of the two automation directories

| Directory | Purpose | Naming example | Called by |
|---|---|---|---|
| **`automation/`** | **Workflow runners** — session lifecycle, locks, audit, init, release, broadcast. Usually `.sh`, meant for the user to run directly within a session | `claim.sh` / `release.sh` / `init_target.sh` / `audit_workspace.sh` / `session_start_brief.sh` / `session_end_checklist.sh` / `status.sh` / `broadcast.sh` / `session_brief.sh` | user manually / agent command |
| **`_automation/`** | **KB-write helpers + lint / sync** — small Python scripts, mostly idempotent, usually triggered by the `pre-commit` hook or used for `staging_status`-style review | `sync_pattern_index.py` / `staging_status.py` / `check_tool_arsenal.py` / `split_lessons.py` / `split_writeups.py` / `lint_frontmatter.py` / `platform_form.py` (after the 2026-06-04 merge) | pre-commit hook / maintenance scripts |

**Three questions to decide:**

1. Is this a command the user will type directly within a session? → `automation/`
2. Is this a lint / sync / KB-write tool, hooked or run periodically? → `_automation/`
3. Is it `.sh` or `.py`? Preference (not enforced): `.sh` in `automation/`, `.py` in `_automation/`

**Exception notes:** `automation/` also has some `.py` (`lint_platform_form_types.py` — mid historical migration); long-term goal: move all `<Platform>` lint into `_automation/` (as of 2026-06-04, merged into `_automation/platform_form.py`).

---

## Retained scope of the cross-session communication layer (2026-06-04 review)

Usage statistics measured over 3 hours:

| Subsystem | event count | assessment | disposition |
|---|---|---|---|
| `claim.sh` / `release.sh` lock | 4 + 5 | ✅ high | keep |
| `status.sh` heartbeat + lock.current_task | 4 | ✅ medium | keep — written into the lock JSON, cheap |
| `SESSION_LOG.jsonl` append | 23 total | ✅ medium | keep — auto-appended, append-only |
| `session_brief.sh` snapshot | (used on query) | ✅ medium | keep — read-only, no write cost |
| `release.sh` handoff capsule | 5 | ✅ medium | keep — useful for the next session's takeover |
| **`broadcast.sh` + `_inbox/`** | **1 (smoke test)** | 🟡 low | **keep but mark experimental** — only triggered once there's a real cross-person/cross-session sync need (e.g. parallel opus-4.6 + pipeline running at once) |

**Conclusion:** the communication layer is **not cut** (multi-session/multi-agent scenarios will arise and the infrastructure needs to be in place), but the README marks broadcast/inbox as experimental to avoid the impression that it's part of the daily workflow.

---

## Decision tree for adding new automation

```
Add a new script?
│
├─ Something the user types directly within a session (claim/release/audit)
│  └─ automation/<name>.sh
│
├─ lint / sync / KB maintenance (idempotent, hook-triggered)
│  └─ _automation/<name>.py
│
├─ Already 3+ scripts in the same domain (e.g. <Platform>)
│  └─ Merge into a single file + subcommand, don't add the (N+1)th
│
└─ Cross-session communication?
   ├─ status / handoff → use the existing status.sh / session_brief.sh
   └─ New feature → check whether there's a real need, otherwise file an issue and wait for an actual hit
```

---

## Related

- `automation/active_sessions/README.md` — lock / comm layer design
- `_automation/staging_status.py` — staging triage helper
- `_automation/check_tool_arsenal.py` / `sync_pattern_index.py` — KB drift check
- CLAUDE.md §"🚨 Session start" — scope-file entry point
