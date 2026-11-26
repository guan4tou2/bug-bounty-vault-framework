# {{TARGET}} — Session Handoff

> Updated automatically at session end during the session-end review.
> Read automatically at session start during the pre-session review.
> Record only information **not already captured in FINDINGS_QUICK_REF and RECON_DB**.
> **The Continuation Point is the entry for the next session — make it exact to an ID.**
> **Reference blockers and tasks by short ID (`B-n`, `T-n`, `R-n`) instead of expanding technical detail**, so the handoff stays small and does not pollute the next session's context.
> Evidence summaries follow [[Reference Card - Evidence Retention Policy]]: cite the record ID, the current result and the canonical note; read full URLs, identities and raw evidence from that record rather than copying them here.

---

## Continuation Point

> The first thing the next session should do. Exact to an ID, so nobody has to guess between "continue A" and "continue B".

| Field | Value |
|-------|-------|
| **target** | `{{TARGET}}` |
| **scope_id** | `<finding ID, ASG node ID, or edge ID>` — exact locator |
| **action** | `hunt` / `verify` / `submit` / `retest` / `chain` / `recon` |
| **context** | One sentence: why this one and not another |
| **blocked_by** | (empty = not blocked) what is missing before it can continue |
| **priority** | `P0-now` / `P1-next` / `P2-backlog` |

### Parked Items

> Findings or leads that exist but are blocked. IDs must be exact.

| ID | Type | Status | Blocked By | Resume When |
|----|------|--------|------------|-------------|
| — | — | — | — | — |

---

## Last Session

- **Date:** {{DATE}}
- **Duration:** —
- **Status:** active / blocked / parked
- **Audit log:** `logs/claude_audit_<UTC_YYYYMMDD>.log`
  - Session ID prefix (first 8 chars, for grep): `<filled in at session end; obtain with head -1>`
  - Multi-day sessions: reference multiple dated audit log files in the Discovery Log

---

## What Was Being Worked On

> One sentence: the hypothesis or direction being tested. **Include an ID** (finding ID / ASG node ID / endpoint path).

(Fill in — e.g. "Testing whether /api/v2/send accepts a raw password hash in place of credentials (node svc-api)")

---

## Immediate Next Steps

> Specific enough to copy and execute directly; the command for the Continuation Point's `scope_id`.

```bash
# Fill in the next curl / command / URL
```

---

## Blockers

> If blocked, describe what you are waiting for. Tag each blocker `B-n`.

- (none)

---

## Artifact Handles

> Large tool outputs saved on disk this session (scan JSON, logs, source dumps). One line each: `path — size — fingerprint (hit count / timestamp / first-bytes)`. The next session verifies the fingerprint before trusting the file (see bb-context-handoff → Artifact Handle Discipline). Never paste raw output here.

- (none)

---

## Open Leads (no Vault Finding created yet)

> Found, worth pursuing, but not confirmed or turned into a Vault Finding. Give each lead a temporary ID (`L-001`, …) so a continuation can name it.

| Lead ID | Description | Location / Endpoint | Status | Priority |
|---------|-------------|---------------------|--------|----------|
| — | — | — | pending verification | — |

---

## Learned This Session

> Not a finding — understanding gained (architecture, behavior, bypass technique)

- —

---

## Notes / Context

> Any important background that the next session would miss without reading git log

- —

---

## Pending Tasks

> Stable IDs: append new `T-n`; never renumber existing references.

- (none)

## Review Items

> Stable `R-n` IDs; review decisions stay manual.

- (none)
