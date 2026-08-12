---
type: wiki
category: workflow
tool: manual
status: active
last-updated: 2026-06-04
---

# Finding Lifecycle State Machine (Reference Card)

> **Purpose:** the decision point for any "what should this finding do now", "is it ready to submit", "is the state correct" question.
> The existing `Reference Card - Workflow State Machine and Gates` only records gate names, not the valid
> input/output transitions for each state, which leads to repeated back-and-forth questions. This card fills in the complete transition table.

## Valid States

```
CANDIDATE → OPEN → SUBMISSION_READY → FORM_READY → SUBMITTED → CLOSED / WITHDRAWN
```

## Valid Transitions per State

| Current State | Allowed Action | Next State | Forbidden Action |
|------|---------|--------|---------|
| CANDIDATE | surface-map gate passed | OPEN | Creating a FORM directly |
| OPEN | Complete 5 gates (safety / chain / evidence / dedup / submission) | SUBMISSION_READY | Skipping any gate |
| SUBMISSION_READY | Create Submission.md | FORM_READY | Submitting while still drafting |
| FORM_READY | bb-submission-readiness passed | SUBMITTED | Submitting without passing the gate |
| SUBMITTED | Wait for triage reply | CLOSED or WITHDRAWN | Modifying already-submitted content |
| CLOSED | Write Lesson / backfill KB | (terminal) | Reopening for submission |
| WITHDRAWN | Record withdrawn reason | (terminal) | Treating it as if it never existed |

## State Detection Shortcuts

Infer the current state from the filesystem (no need to ask):

- `Finding.md` exists but no `Submission.md` → **OPEN**
- `Submission.md` exists but no FORM → **SUBMISSION_READY**
- FORM exists and `status: ready` → **FORM_READY**
- FORM exists and `status: submitted` → **SUBMITTED**

## Related Documents

- `09 - Knowledge Base/Reference Card - Workflow State Machine and Gates.md` — gate name definitions
- `09 - Knowledge Base/Reference Card - New Target and Finding Creation SOP.md`
- `09 - Knowledge Base/Reference Card - Triage Response Lifecycle.md` — handling after SUBMITTED
