---
id: LL-215
type: lesson
target: 通用（harness / 知識管理）
date: 2026-06-24
tags: [harness, knowledge-management, kb-roi, provenance, telemetry, entropy-gc, methodology]
---

# LL-215：系統一直 capture 卻從不量測 retrieval — 用效果回路把「採用率未驗證」變可量測

## 核心教訓

**知識管理的預設失敗模式是「只有 capture、沒有 retrieval 量測」**：session→KB→template→gate 全是單向產出，但「這些 KB/template 有沒有真的幫到挖洞」從來沒被量測。結果是 artifact 無限增長（96 Pattern / 27 Playbook / 209 LL），cognitive load 上升，卻沒有證據基礎能 prune —— 每次只能誠實說「採用率未驗證」，因為**結構上量不到**。

DAG template 0/124、Hermes ≈0 findings —— 都是**事後**才發現「建了沒用」。修正方向不是「再建一個 capture」，而是**閉合反向回路**。

## 三個反向量測（forward measurement > retro-mining）

| 缺口 | 工具 | 量什麼 |
|------|------|--------|
| KB 有沒有產出 finding | `kb_roi.sh` + Finding frontmatter `helped_by:` | 每筆 confirmed finding 記錄哪些 KB 促成它 → credited（保留/強化）vs uncredited（prune 證據） |
| 對的 KB 有沒有浮到眼前 | `surface_kb.sh <target>` | 偵測 target 技術指紋 → 自動浮相關 Pattern/Playbook（從「要記得查」變「自動端到面前」） |
| 哪些 template 是 shelf-ware | `check_shelfware.sh` | 數每個 template 的實例數（marker 比對）；0 實例 = shelf-ware（DAG template 曾 0/124 就是這種） |

## 為什麼 forward 量測 >> 事後挖

- 事後挖 124 個 session 才發現 DAG 沒人用：貴（rate-limit、safety classifier 擋 offensive transcript mining）、慢、且只能發現一次。
- `check_shelfware.sh` 一跑就標出 0 實例 template；`kb_roi.sh` 累積後直接給 entropy-GC 的證據。**便宜、可重複、即時。**

## 適用 / 注意

- `helped_by` 是因果 credit（什麼幫我找到），跟 `related_pattern`（關聯）不同 —— 確認 finding 時順手填一行。
- uncredited ≠ 無用：新增的、防禦性的、checklist 本就不直接產 finding；**機械偵測 + LLM 判斷**，別自動刪。
- 接線：`vault_maintenance.sh §8g/§8h`、`session_brief.sh §8`（surface_kb nudge）、`session_end_checklist.sh §15⑦`（helped_by 提醒）。

## 關聯

- 對應 [[LL-198-DAG只在多系統target用-否則friction過高ROI為負]]（DAG 採用率問題 → 現在可量測）
- 對應「mechanical detects, LLM judges」原則：三工具都只浮現候選，不替 LLM 決策。
