# Active Sessions Lock Registry

**Purpose**: a coordination mechanism for hunting across multiple parallel sessions. The lock file is the machine source of truth; the `## Active Sessions` section of HANDOFF.md is a mirror (human-readable).

## Schema

Each lock is a `<safe_scope>.lock` file containing JSON:

```json
{
  "session_id": "uuid",
  "owner": "claude-opus-4-7",
  "scope": "example-target/sub-service/idor",
  "target": "example-target",
  "claimed_at": "2026-05-07T09:11:00Z",
  "last_heartbeat": "2026-05-07T09:25:00Z",
  "expected_release": "2026-05-07T11:00:00Z",
  "host": "example-host"
}
```

`<safe_scope>` = the scope with `/` replaced by `--`, e.g. `example-target--sub-service--idor.lock`.

## Scope hierarchy and conflict rules

Scopes are layered with `/`, split into **target scopes** and **shared-resource scopes** (leading underscore):

### Target scopes
| Scope example | Meaning |
|---|---|
| `example-target` | whole-target lock |
| `example-target/sub-service` | sub-service lock |
| `example-target/sub-service/idor` | sub-service + vuln-class lock |

### Shared-resource scopes (added 2026-06-04 — protection for multiple sessions writing shared files in parallel)

When multiple Claude sessions / pipelines / agents run in parallel, writes to shared high-frequency files (Pattern Index, Lessons Learned, Tool Arsenal, Skills…) race. The scopes below partition these writes into mutually exclusive regions:

| Scope example | Locked range | Typical user |
|---|---|---|
| `_meta` | architecture/doc patches, no target | editing AGENTS.md / STRUCTURE.md / repo conventions |
| `_kb` | any write to `09 - Knowledge Base/` | large-scale KB overhaul (SOTA refresh, batch upgrade) |
| `_kb/<area>` | a specific KB area | e.g. `_kb/Pattern-Index`, `_kb/Lessons-Learned`, `_kb/Tool-Arsenal` |
| `_pipeline` | session-learning pipeline run | automatic proposal extraction / promotion to KB |
| `_staging` | `_staging/proposed/` review flow | manually reviewing proposals for KB promotion |
| `_automation` | changes to `automation/` scripts | editing claim.sh / audit_workspace.sh and other core scripts |
| `_skill` | changes to the `.claude/skills/` series | adding/editing a skill (auto-syncs .codex/.gemini) |
| `_agent` | changes to `.claude/agents/` | adding/editing an agent prompt |
| `_dashboard` | `00 - Dashboard/` (Kanban Board, etc.) | cross-target write hotspot; triage, progress sync |

Examples:
- When designing web-vuln-scan, claim `_skill`; a pipeline claiming `_pipeline` during that time doesn't collide (siblings)
- But if the pipeline wants to claim `_kb` (batch KB promotion) while you're editing `_kb/Pattern-Index` → collision (parent/child, conflict rule #3)
- Target work (`example-target`) and a shared resource (`_kb`) don't collide (entirely different branches)

Conflict logic is handled uniformly by `_lock_lib.sh::conflicts_with()`; new scopes automatically inherit the prefix-based parent/child rules.

**Conflict determination (at claim time)**:

1. **Exactly identical** → collision
2. **New scope is a prefix of an existing scope** (claiming a parent whose child is locked) → collision
3. **Existing scope is a prefix of the new scope** (claiming a child whose parent is locked) → collision
4. **Entirely different branches** (siblings, different targets) → no collision

Example: `example-target/sub-service` is already locked
- claim `example-target` → collision (#2)
- claim `example-target/sub-service/idor` → collision (#3)
- claim `example-target/example-msg-app` → no collision (#4)
- claim `example-target` → no collision (#4)

## Expiry mechanism

- `last_heartbeat` older than 30 minutes → treated as a dead session
- the post-commit hook triggers a heartbeat update (matched when the commit message contains the target name)
- expired locks are automatically swept into `_expired/` by `claim.sh` / `check_active_sessions.sh` and do not block new claims

## Directory

- `*.lock` — active locks (.gitignored; local only)
- `_expired/` — archive of expired/released locks, for debugging
- `_completed/` — handoff capsules auto-generated at release time (scope/commits/files/last_task)
- `_inbox/<scope-or-session>/msg-*.md` — messages delivered by broadcast.sh; once read they are renamed `*.read`
- `SESSION_LOG.jsonl` — cross-session event bus (claim/release/status/broadcast/commit); append-only
- `.gitkeep` — preserves the directory structure

## Cross-session communication (2026-06-04 Full layer)

The lock tells others "which scope I hold"; `status` + `broadcast` + `SESSION_LOG` tell others "how far I've got, and what I need to pass along."

> **Usage-tier guidance** (after the 2026-06-04 review)
> - 🟢 **Everyday**: lock + `status.sh` + `session_brief.sh` + `SESSION_LOG` + handoff capsule (auto-generated at release) — enough for 90% of cases
> - 🟡 **Advanced**: `broadcast.sh` + `_inbox/` — **experimental**, only for real-time cross-person/cross-session messaging when actually needed; used once in 3 hours of testing (smoke test)
> - Still retained because: parallel opus-4.6 / parallel session-learning pipeline = cross-session scenarios will happen

```bash
# Heartbeat + announce what you're currently doing (updates lock.current_task + SESSION_LOG)
bash automation/status.sh "fixing Pattern Index drift"

# Check your own current status
bash automation/status.sh --read

# Drop a message into another session's inbox (scope or session_id both work)
bash automation/broadcast.sh --to=_kb "I'm working on Lessons/, hold off for now"
bash automation/broadcast.sh --to=all "lint hook is broken, wait until it's fixed before committing"

# Check your own inbox
bash automation/broadcast.sh --inbox
bash automation/broadcast.sh --ack <msg-path>   # mark as read

# Full-picture snapshot (self/others/inbox/recent events/handoff)
bash automation/session_brief.sh
bash automation/session_brief.sh --window=2h
```

At release time, a `_completed/<ts>_<scope>_<sid>.md` handoff capsule is auto-generated, recording the commits + files_changed + last_task during the claim period, so the next session can take over without asking.

## Usage

```bash
# Session start
bash automation/check_active_sessions.sh           # list all active
bash automation/claim.sh example-target/sub-service/idor     # claim scope

# During the session
# (post-commit hook auto-updates the heartbeat)

# Session end
bash automation/session_end_checklist.sh example-target  # auto-release
# or manually:
bash automation/release.sh example-target/sub-service/idor
```

## Vault cross-repo compatibility

The `target` part of the scope (the first segment) is shared across the parent + Vault. Example: claiming `example-target/sub-service` locks both:
- parent repo `workshop/example-target/`
- Vault repo `01 - Targets/ExampleTarget/`

Both repos trigger a heartbeat at commit time.
