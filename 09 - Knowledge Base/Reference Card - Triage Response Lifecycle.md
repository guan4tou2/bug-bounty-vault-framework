---
fileClass: ReferenceCard
type: reference-card
title: Triage Response Lifecycle
last_updated: 2026-05-22
tags: [triage, submission, form, kanban, workflow, bb-referencecard]
source: internal
added: 2026-05-22
---

# Reference Card - Triage Response Lifecycle

> Purpose: After receiving a platform / vendor reply, update the Submission, FORM, Kanban, KB / Lessons, and Pattern update in a fixed order, to avoid updating only one of them.

---

## Status Handling

| Triage status | Submission | FORM | Kanban | KB / Lessons | Pattern update |
|---|---|---|---|---|---|
| accepted | status = accepted; add bounty / case id | sync platform status | moved to accepted / resolved | record success conditions | add Pattern if reusable |
| duplicate | status = duplicate; add duplicate id / reason | sync duplicate | moved to closed / duplicate | record collision reason | add false-positive / prior-disclosure rule |
| n_a | status = n_a; add rejection reason | sync n_a | moved to closed / N/A | record downgrade lesson | add "invalidation conditions" |
| informative | status = informative | sync informative | moved to low-priority closed | record platform stance | add Pattern as needed |
| resolved | status = resolved | sync resolved | moved to resolved | record fix and verification | add remediation note |
| wont_fix | status = wont_fix | sync wont_fix | moved to closed | record policy reason | add stop condition |

---

## Update Order

1. Update memory / session note if the response changes future behavior.
2. Update Submission.
3. Update FORM.
4. Update Kanban.
5. Update KB / Lessons.
6. Update Pattern if the response changes exploitability, false-positive rules, severity, or platform posture.
7. Commit.

do not delete rejected findings. Duplicate / N/A / informative findings are calibration data.

---

## Required Fields

- platform case id / duplicate id
- triage date
- triage status
- quoted reason or summarized reason
- follow-up deadline if any
- linked Finding / Submission / FORM

---

## Related Notes

- [[Reference Card - Workflow State Machine and Gates]]
- [[Reference Card - Audit Warning Policy]]
- [[Skill - triage-validation]]
- [[Pattern - Triage Calibration]]
