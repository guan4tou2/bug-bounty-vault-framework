---
fileClass: Attempt
target: "[[]]"
vuln_class: ""
title: ""
attempt_date: <% tp.date.now("YYYY-MM-DD") %>
attempt_time: <% tp.date.now("HH:mm") %>
hours_spent: 0
result: "exploitable | not_exploitable | inconclusive | blocked | parked"
result_reason: "prerequisite_unmet | waf_blocked | no_session | not_in_scope | duplicate_likely | other"
prerequisite: ""
killed_at: ""
should_retry_when: ""
related_recon: []
related_pattern: []
upgraded_to_finding: ""
tags: []
---

# Attempt — {{TARGET}} — {{TITLE}}

> **Discovery note**：Attempt 與 Finding 同為 discovery-note，章節用 canonical 英文 H2（AGENTS.md §3b）。
> Discovery Log 五欄：時間 / 來源 IP / 目標 IP / `[audit:SESSION8@HH:MM:SS]` / 動作。

## Summary

> 想做什麼？1-2 行結論（成立 / 不成立 / 被擋 / 缺前提）

---

## Discovery Log

> 嘗試的時間軸（同 Finding 五欄格式）

- `YYYY-MM-DD HH:MM` `[來源 IP → 目標 IP]` `[audit:SESSION8@HH:MM:SS]` 做了什麼、看到什麼
- `YYYY-MM-DD HH:MM` `[來源 IP → 目標 IP]` `[audit:SESSION8@HH:MM:SS]` 進一步觀察 / 試 bypass / 結論

---

## Reasoning

- 初始 hypothesis：
- 為什麼覺得會 work：
- 為什麼最後沒成立：

---

## Why Stopped

> 寫具體 gate / prerequisite，避免下次重蹈覆轍。

- **直接原因：**（e.g., 端點 require Bearer，無 cookie session）
- **前提條件未滿足：**（e.g., 需要 victim 已登入特定子網域，但子網域不允許 takeover）
- **平台規則：**（e.g., 大廠對 CORS theoretical 已知必 N/A — see [[Lessons Learned]]）
- **時間成本超過預期回報：**（hours_spent / 預估 bounty）

---

## Partial Evidence

> 即使沒成立、仍值得保留的觀察（指紋 / WAF 行為 / 間接證據 / 後續可串）

```bash
# 關鍵指令片段
```

- 端點 X 回應 Y 狀態碼
- WAF 行為：擋 `<script>` 但不擋 `<svg/onload=>`
- 有/沒有 rate limit
- 截圖：[[../poc/...]]

---

## Lessons Learned

- **新 Pattern 候選？** 是 / 否 — 連結 [[Pattern - ...]]
- **更新 Lessons Learned？** 是 / 否
- **跨 target 適用？**

---

## Re-attempt Conditions

> 什麼情況下重啟這個方向？（"除非..."）

- 除非 `<前提條件>` 改變
- 除非有新的 source map / 新的 endpoint
- 除非平台政策改變

---

## Related

- Target：[[]]
- Recon：[[]]
- 相關 Pattern：[[]]
- 升級成 Finding？[[]]（若有）
