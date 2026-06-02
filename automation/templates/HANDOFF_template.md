# {{TARGET}} — Session Handoff

> Updated automatically at session end during the session-end review.
> Read automatically at session start during the pre-session review.
> Record only information **not already captured in FINDINGS_QUICK_REF and RECON_DB**.

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

> One sentence: the hypothesis or direction being tested

(Fill in — e.g. "Testing whether /api/v2/send accepts a raw password hash in place of credentials")

---

## Immediate Next Steps

> Specific enough to copy and execute directly

```bash
# Fill in the next curl / command / URL
```

---

## Blockers

> If blocked, describe what you are waiting for

- (none)

---

## Open Leads (no Vault Finding created yet)

> Things that have been found, are worth pursuing, but have not been confirmed or turned into a Vault Finding

| Lead | Location / Endpoint | Status | Priority |
|------|---------------------|--------|----------|
| — | — | pending verification | — |

---

## Learned This Session

> Not a finding — understanding gained (architecture, behavior, bypass technique)

- —

---

## Notes / Context

> Any important background that the next session would miss without reading git log

- —
