---
fileClass: Playbook
type: playbook
title: Trigger Chain Dry-Run
last_updated: 2026-06-04
tags: [playbook, methodology, dry-run, surface-mapping, skill-matrix, bb-playbook]
source: internal
added: 2026-06-04
---

# Playbook — Trigger Chain Dry-Run(挖洞前的「乾跑」)

> **問題:** 真的開挖之前,我怎麼確認 (a) 沒漏 disclosed 已知漏洞、(b) 16+ 個 yaklang skill 哪幾個對這個 target 真有用、(c) 攻擊面有哪些角度從沒測過?
> 
> **答案:** dry-run。讀完所有已知資訊 → 對 22 yaklang × 16 bb-* skill 跟攻擊面做矩陣 → 列出排序好的可行動清單。**先跑紙上,再跑機器**,省半小時 + 防誤報。

## 何時跑

- 任何新 target 第一次 session 開頭(`bash automation/init_target.sh <t>` 之後)
- 既有 target 接手 / 重啟 session
- 競賽中段,新 yaklang skill 或新 KB 條目進來,要重評攻擊面
- **跑 `bb-web-vuln-scan` / `bb-surface-mapping` 之前的 zero-cost 預檢**

## 流程(5 步,30 分鐘內)

### Step 1 — Disclosed Pre-Read Gate(強制)

讀完:
- `01 - Targets/<t>/Target - <t>.md`(frontmatter + findings 表)
- `$WORKSHOP_ROOT/<t>/RECON_DB.md`(if exists)
- `$WORKSHOP_ROOT/<t>/FINDINGS_QUICK_REF.md`(if exists)
- `$MEMORY_DIR/project_<t>_*.md`(if exists)
- 平台 disclosed PDF / writeup(競賽 / <Platform> disclosed)

**輸出證據檔**(audit-gate enforcement):
```bash
# WORKSHOP_ROOT/<t>/disclosed_pre_read.md
---
type: pre-read-evidence
target: <t>
read_at: 2026-06-04T09:00:00Z
sources:
  - target_page: ...
  - recon_db: ...
  - memory: ...
  - external_disclosed: <PDF URL or note>
known_findings_count: <N>
---

## Already-Reported Summary
- <ID> | <hostname> | <vuln class> | <root cause>
- ...

## Withdrawn / Out-of-Scope
- ...

## Cross-Team / Other Researchers
- ...
```

沒此檔 = bb-surface-mapping 拒絕往下(見 [[Checklist - Disclosed Findings Pre-Read Gate]] §evidence gate)。

### Step 2 — Surface 盤點(reuse 既有 Surface Map)

讀 RECON_DB `## 🗺 Attack Surface Map`,沒有就先跑 `bb-surface-mapping`。產出:

| 系統 / 元件 | 已知 yield | 已知 dead | server fingerprint |
|---|---|---|---|
| host1 | 3 findings | — | nginx + PHPSESSID |
| host2 | — | SPA catch-all | nginx (Apache backend?) |
| ... |

### Step 3 — Skill × Surface 矩陣

對每個 surface 元件 × 每個 yaklang skill,問:**「這 skill 對這 surface 提供 NEW 攻擊角度嗎?」**

四格:
- ✅ 完全沒測過 + 適用此 stack → 高 ROI
- 🟡 部分測過 / 不確定 stack 是否適用 → 先 fingerprint
- ❓ 不確定 → 跑廣度 skill(`recon-and-methodology` Java middleware fingerprint)再回判
- ❌ 已測過 / 不適用 stack → skip

範例(節錄,HTT 5/22 yaklang):

| Surface | 401-403 | type-juggling | host-header | business-logic | recon-and-methodology |
|---|---|---|---|---|---|
| Laravel/PHP host | ❌(LL-148)| ✅ 沒測過 | ✅ password reset 沒測 | ✅ form 流程沒測 | 🟡 不是 Java |
| ASP.NET host | ❌(LL-148)| ❌(PHP only)| 🟡 | ✅ | 🟡 |
| 鎖死系統(全 404)| ❌(LL-148)| ❌ | ❌ | ❌ | ✅ 看 server stack |

### Step 4 — 排序行動清單(top 5)

把 ✅ 格按「預期命中率 × 嚴重度」排序,前 5 條:
1. <最有把握 + 影響最大>
2. ...
5. <備援>

每條附:
- 對應 skill / 對應 surface 元件
- 預期信號(回 200 + 含 admin 字樣 / 200 + 響應差異大 / Set-Cookie token)
- 不該繼續的 stop 條件(回 SPA size 一致 / 全 4xx / 已是 dup)

### Step 5 — 紀錄到 memory(競賽特例)/ RECON_DB(一般)

- 競賽 → memory file `project_<t>_recon.md` 加「Session N 計畫」段(kb-purity 保護)
- 一般 → workshop `RECON_DB.md` 加 `## 🎯 Dry-Run Plan` 段
- 抽象化 lesson(看到新模式)→ KB `Lessons/LL-NNN-*.md`(過 kb-purity)

## 反例(別這樣做)

- **跳過 Step 1 直接 Step 3** — 結果報出來才發現 dup,浪費時間 + 影響 program validity ratio
- **22 skill 都跑** — fan-out 撞 quota(LL-147),正確做法是矩陣選 top 5,逐個深測
- **Step 3 結果只列「適用」不列「不適用 + 原因」** — 半年後重看忘記為什麼跳過某 skill,又重新評估一次
- **Step 4 排序按「我熟悉哪個」而非「命中率 × 嚴重度」** — 確認偏誤,挖到的都是同類型

## 範本:現場跑出來的 dry-run

[[Lessons Learned]] 教訓 #148(401-403 鎖死系統)就是 2026-06-04 一次 dry-run 的副產物 — Step 3 矩陣把 401-403 標 ✅,Step 4 排第一,實跑 0 hit,抽象成 KB lesson。**每次 dry-run 都有副產物可累積。**

## Related

- [[Checklist - Disclosed Findings Pre-Read Gate]] — Step 1 的 evidence gate 定義
- [[Checklist - Attack Surface Coverage]] — Step 2 的 surface 維度
- [[Reference Card - Promotion Ladder]] — 副產物(新 pattern / lesson)該升到哪一層
- [[Lessons Learned]] MOC — 副產物範例庫
- [[LL-120-spa-catch-all-偵測法-批量掃描前必須排除|LL-120]] — Step 4 stop 條件
- [[LL-148-401-403-bypass-matrix-鎖死系統命中率近-0-先-fingerprint-再決定|LL-148]] — Step 3 fingerprint-before-matrix 規則
- `bb-surface-mapping` skill — 沒 RECON_DB 時的 fallback
- `bb-web-vuln-scan` skill — dry-run 後真挖的入口
