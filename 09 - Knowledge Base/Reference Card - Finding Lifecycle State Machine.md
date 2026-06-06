---
fileClass: ReferenceCard
type: reference-card
title: Finding Lifecycle State Machine
last_updated: 2026-06-04
tags: [reference-card, lifecycle, finding, submission, workflow, bb-referencecard]
source: internal
added: 2026-06-04
---

# Reference Card — Finding Lifecycle State Machine

> 補 `Reference Card - Workflow State Machine and Gates` 的缺口:那一頁只記 gate 名稱,不記每個 state 合法的輸入/輸出轉換,造成「這筆現在能送了嗎」反覆詢問。本頁鎖 state 機器。

## 合法狀態

```
CANDIDATE → OPEN → SUBMISSION_READY → FORM_READY → SUBMITTED → CLOSED / WITHDRAWN
```

## 每個狀態的合法轉換

| 現態 | 允許動作 | 下一態 | 禁止動作 |
|------|---------|--------|---------|
| **CANDIDATE** | surface-map gate 通過 | OPEN | 直接建 FORM |
| **OPEN** | 完成 5 gates(safety / chain / evidence / dedup / submission)| SUBMISSION_READY | 跳過任一 gate |
| **SUBMISSION_READY** | 建 `Submission.md` | FORM_READY | 邊寫邊送 |
| **FORM_READY** | `bb-submission-readiness` 通過 | SUBMITTED | 未通過直接送 |
| **SUBMITTED** | 等 triage reply | CLOSED 或 WITHDRAWN | 修改已送內容 |
| **CLOSED** | 寫 Lesson / KB 回填 | (terminal) | 重開送件 |
| **WITHDRAWN** | 記錄 withdrawn reason | (terminal) | 當作從未存在 |

## 狀態判斷快捷鍵(從檔案存在性反推)

| 檔案狀態 | 推斷 |
|---|---|
| 有 `Finding.md` 但沒 `Submission.md` | OPEN |
| 有 `Submission.md` 但沒 `FORM - *.md` | SUBMISSION_READY |
| FORM 存在且 `status: ready_to_submit` | FORM_READY |
| FORM 存在且 `status: submitted` | SUBMITTED |
| FORM `triage_status: triaged_resolved` / `closed` | CLOSED |
| FORM `triage_status: withdrawn` | WITHDRAWN |

## 反例:常見錯誤轉換

- ❌ CANDIDATE → FORM_READY(跳過 OPEN/SUBMISSION_READY,等於略過 5 gates)
- ❌ OPEN → SUBMITTED(沒建 FORM,等於直接送原始 Finding)
- ❌ SUBMITTED → FORM_READY(送出後又改內容)
- ❌ CLOSED → SUBMITTED(已結案重送)

## Related

- [[Reference Card - Workflow State Machine and Gates]] — gate 順序與內容
- [[Checklist - <Platform> FORM Pre-Submit Field Audit]] — FORM_READY → SUBMITTED 之前的最後 gate
- [[Checklist - Submission State Integrity]] — Submission 狀態跳脫偵測
