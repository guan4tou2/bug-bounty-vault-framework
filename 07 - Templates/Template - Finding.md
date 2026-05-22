---
fileClass: Finding
finding_id: ""
target: "[[]]"
host: ""
platform: ""  # 留空；FORM 階段才決定平台（見 AGENTS.md §3e.1）
vuln_class: ""
cwe: ""
cvss: ""
severity: "P1 | P2 | P3 | P4 | P5"
risk: "critical | high | medium | low | info"
verification_level: "A | B | C | D"
verified_evidence: "live | source_code | static | theoretical"
status: "discovered | verified | ready | submitted | duplicate | na | accepted | fixed | on_hold | killed"
discovered_date: <% tp.date.now("YYYY-MM-DD") %>
discovered_time: <% tp.date.now("HH:mm") %>
last_verified: <% tp.date.now("YYYY-MM-DD") %>
hours_spent: 0
chain: false
related_recon: []
related_attempts: []
related_pattern: []
related_submission: ""
dedupe_checked_at: <% tp.date.now("YYYY-MM-DD HH:mm") %>
dedupe_query: ""
dedupe_hits: []
tags: []
---

# Finding — {{TARGET}} — {{TITLE}}

> **Discovery note only**：Finding 記錄的是「怎麼找到、怎麼驗、當時怎麼想」。
> 正式對外報告請寫在 `Submissions/Submission -*.md` 與 `FORM -*.md`。
>
> **章節規範**（詳見 AGENTS.md §3b）：
> - **Must-have**：Summary / Discovery Log / Reasoning / Evidence / Impact / Follow-up
> - **Nice-to-have**：Related / Vulnerable Code / Remediation / CVSS / Verification Status — 有內容才放
> - H2 標題一律用**英文**；內文中英自由
> - 不要的章節整段刪掉，不要留空殼

## Summary

一段話：what + current state + why it matters。只放 discovery-note 需要的關鍵資訊。

| 欄位 | 值 |
|------|-----|
| Target | `[[]]` |
| Host | |
| Finding ID | |
| Status | |
| Severity | |
| Verification | |
| Discovered | {{date}} {{time}} |

---

## Discovery Log

> **強制五欄**：時間（本地）/ 來源 IP（本機 or VPS）/ 目標 IP（dig 解析）/ audit ref（`[audit:SESSION8@UTC_HH:MM:SS]`，對應 §6f Bash audit log）/ 動作 + 結果。詳見 AGENTS.md §3b + §6f。
>
> audit ref 取得：`head -1 logs/claude_audit_$(date -u +%Y%m%d).log`（看 session 前 8 碼）

- `YYYY-MM-DD HH:MM` `[來源 IP → 目標 IP]` `[audit:XXXXXXXX@HH:MM:SS]` 做了什麼、看到什麼、為什麼往下一步走
- `YYYY-MM-DD HH:MM` `[來源 IP → 目標 IP]` `[audit:XXXXXXXX@HH:MM:SS]` 哪個假設成立 / 哪個假設被排除

<!-- 範例：
- `2026-05-16 14:32` `[114.45.x.x → 203.69.x.x]` `[audit:d2addc4f@06:32:18]` curl GET /api/users/1 帶自己 cookie，回 200 + 自己資料
- `2026-05-16 14:48` `[114.45.x.x → 203.69.x.x]` `[audit:d2addc4f@06:48:05]` 改 user_id=2，回 200 + 別人 PII → IDOR 確認

未來 takeover 想看「當時這條怎麼下指令的」：
  grep "session:d2addc4f.*06:48:05" logs/claude_audit_20260516.log
-->

---

## Reasoning

- 初始假設：
- 中途轉向原因：
- 還沒驗完但值得下次接手的想法：

---

## Evidence

> **強制：可直接複製執行的完整 curl / payload**（不只貼回應）。指令含 headers / cookies / payload。

```bash
# 關鍵 curl / payload / query / grep（完整可重現）
curl -i 'https://target/api/endpoint' \
  -H 'Cookie: session=...' \
  -H 'Content-Type: application/json' \
  -d '{"...":"..."}' | jq
```

- 回應片段 / 截圖路徑：
- PoC 檔案位置：

---

## Impact

**Verified（已 PoC 證明）：**
-

**Potential（需額外條件，低信心；不確定就刪掉這段）：**
- _前提：_

---

## Follow-up

- 對應 Submission：
- 狀態（submitted / withdrawn / superseded / needs-revalidation）：
- 下一步：

---

## Related

- Target：[[]]
- Pattern：[[]]
- Submission / FORM：[[]]
- Recon：[[]]
- Attempt：[[]]
- Attack Chain：[[]]

---

<!-- ====== 以下為 nice-to-have；沒內容就整段刪掉 ====== -->

## Vulnerable Code

> 只貼問題段落，附檔案路徑與行號。

```
// file: path/to/file, line 120-145
```

## Remediation

-

## CVSS

`AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_` → 分數 N.N

## Verification Status

- [ ] HTTP response 確認
- [ ] 原始碼確認
- [ ] Live PoC 執行（非破壞性）
- [ ] 截圖 / 影片

---

## Dedupe Gate

```bash
bash automation/vault_precheck.sh <target> "<keyword>" "<host_or_endpoint>"
```

- 命中摘要：
- 為什麼不是重複（若有命中）：

## Tasks

- [ ] #task @<target> 寫成正式 FORM
- [ ] #task @<target> 補截圖
