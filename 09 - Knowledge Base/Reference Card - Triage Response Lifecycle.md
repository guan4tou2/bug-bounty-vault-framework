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

> 目的：收到平台 / 廠商回覆後，用固定順序更新 Submission、FORM、Kanban、KB / Lessons 與 Pattern update，避免只改其中一處。

---

## Status Handling

| Triage status | Submission | FORM | Kanban | KB / Lessons | Pattern update |
|---|---|---|---|---|---|
| accepted | status = accepted；補 bounty / case id | 同步平台狀態 | moved to accepted / resolved | 記錄成功條件 | 若可重用則補 Pattern |
| duplicate | status = duplicate；補 duplicate id / reason | 同步 duplicate | moved to closed / duplicate | 記錄撞題原因 | 補 false-positive / prior-disclosure rule |
| n_a | status = n_a；補 rejection reason | 同步 n_a | moved to closed / N/A | 記錄降級教訓 | 補「不成立條件」 |
| informative | status = informative | 同步 informative | moved to low-priority closed | 記錄平台態度 | 視需要補 Pattern |
| resolved | status = resolved | 同步 resolved | moved to resolved | 記錄修補與驗證 | 補 remediation note |
| wont_fix | status = wont_fix | 同步 wont_fix | moved to closed | 記錄政策原因 | 補 stop condition |

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
