---
type: reference
category: checklist
tags: [checklist, submission, state-tracking, quick-ref, session-end]
added: 2026-10-12
---

# Checklist — Submission State Integrity

> **Trigger:** before any session-end sync (`vault-sync` agent / `automation/end_session.py`), and after any manual change to a Submission's status.
> **Guiding principle:** State that drifts between the Finding, the Submission, the FORM, the quick-reference index, and the Kanban board causes duplicate submissions, missed submissions, and wrong counts. Check the links, not just the files.

State names and transitions: [[Reference Card - Finding Lifecycle State Machine]].

---

## Lifecycle field completeness

- [ ] The Finding's frontmatter `status` reflects reality (e.g. verified → ready → submitted → triaged → closed).
- [ ] The Submission's `status`, `submitted_at`, and the channel's case/report reference (stored in `outcome` or the metadata table) are filled in **immediately** after sending — not at the end of the session.
- [ ] If a FORM was used, the FORM file exists and its case/reference field is not empty.
- [ ] `FINDINGS_QUICK_REF.md` for the target reflects the same status (regenerate it rather than hand-editing; then spot-check the changed rows).

## Count reconciliation

- [ ] When comparing counts, count **finding rows only** — exclude header, total, attempt, and submission rows.
- [ ] Take headline numbers from `python3 automation/asg.py status <target>` (the ledger is the source of truth), not from a hand-maintained number in a Target note.
- [ ] A mismatch between the Target note's `findings_total`, the ledger, and the quick-reference row count is a FAIL signal: check whether attempts or submissions were mixed into the finding list before "fixing" any number.

## Cross-reference consistency

- [ ] Every Finding ID a Submission lists actually exists and is committed.
- [ ] The Finding's `related_submission` and the Submission's `finding_id` point at each other.
- [ ] The target's Kanban card (`01 - Targets/<target>/Kanban - <target>.md`) and the master board in `00 - Dashboard/Kanban Board.md` are in the matching column — readiness gates block on state but do not move cards for you.

## After batch operations

- [ ] Withdrawn Submissions are removed from ready/submitted counts.
- [ ] If the recipient asked for a title or classification change, the FORM, the Submission, and the Finding all carry the new value.
- [ ] Re-run `bb-submission-readiness` on anything whose status moved back to `ready`.

## Related

- [[Checklist - Pre-Submission Validation]]
- [[Reference Card - Triage Response Lifecycle]]
