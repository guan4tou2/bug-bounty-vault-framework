---
type: reference-card
title: "Finding Lifecycle State Machine"
tags: [lifecycle, finding, submission, workflow, state-machine]
status: draft
last_updated: 2026-08-12
---

# Reference Card - Finding Lifecycle State Machine

> **TL;DR**: Defines the legal states a finding moves through from first observation to closure, and which transitions are valid at each state — so "is this ready to submit yet?" has a mechanical answer instead of a repeated judgment call.

## Quick Reference

### Legal states

```
CANDIDATE → OPEN → SUBMISSION_READY → FORM_READY → SUBMITTED → CLOSED / WITHDRAWN
```

### Valid transitions per state

| Current state | Allowed action | Next state | Forbidden action |
|---|---|---|---|
| **CANDIDATE** | Passes a vuln-agnostic surface-mapping gate | OPEN | Jumping straight to a submission form |
| **OPEN** | Completes all required gates (safety / chaining review / evidence completeness / dedup / submission readiness) | SUBMISSION_READY | Skipping any one gate |
| **SUBMISSION_READY** | A structured submission draft is written | FORM_READY | Submitting while still writing |
| **FORM_READY** | The final pre-submit readiness check passes | SUBMITTED | Submitting without that check passing |
| **SUBMITTED** | Wait for triage response | CLOSED or WITHDRAWN | Editing content that has already been submitted |
| **CLOSED** | Write up the lesson / feed it back to the knowledge base | (terminal) | Reopening for resubmission |
| **WITHDRAWN** | Record the withdrawal reason | (terminal) | Treating it as if it never existed |

### Inferring state from artifact presence

| Artifact state | Inferred state |
|---|---|
| A finding record exists but no submission draft | OPEN |
| A submission draft exists but no platform-specific form | SUBMISSION_READY |
| A form exists with status `ready_to_submit` | FORM_READY |
| A form exists with status `submitted` | SUBMITTED |
| A form's triage status is `triaged_resolved` / `closed` | CLOSED |
| A form's triage status is `withdrawn` | WITHDRAWN |

## Details

### Common invalid transitions to watch for

- ❌ CANDIDATE → FORM_READY (skips OPEN/SUBMISSION_READY entirely, which means skipping every required gate)
- ❌ OPEN → SUBMITTED (no form was ever built — this is effectively submitting the raw finding notes directly)
- ❌ SUBMITTED → FORM_READY (editing content after it has already gone out)
- ❌ CLOSED → SUBMITTED (resubmitting something already closed)

The value of treating this as a strict state machine rather than a checklist is that it makes "can I submit this now" a lookup instead of a judgment call: if the artifact trail doesn't show every required gate having passed in order, the finding is not ready, regardless of how confident anyone feels about the underlying vulnerability.

## Related

- [[Reference Card - Vulnerability Type Classification]]
- [[bb-submission-readiness]]
- [[bb-evidence-readiness]]
