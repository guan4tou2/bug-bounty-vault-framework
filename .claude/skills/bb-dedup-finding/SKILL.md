---
name: bb-dedup-finding
description: Use when opening a new Finding or FORM, checking duplicate likelihood, deciding whether to merge reports, handling same endpoint/different user evidence, or user says 這不是挖過了嗎/同一漏洞/該不該合併.
---

# Bug Bounty — 重複 Finding 判定（§3f 規則 + 6 步驟）

> **2026-05-16 從 AGENTS.md §3f promote 到 skill**：每次「開新 Finding/FORM 前必過」+「用戶質疑是不是重複」的高頻 trigger，獨立 skill 保證強制觸發。

## 判定核心（單一問題）

**「同一個 commit 能不能把所有 PoC 一起修好？」**
- ✅ 能 → 同一漏洞，**合併 1 份**（多端點列表 + 代表性 PoC + 公司列附錄）
- ❌ 不能 → 不同漏洞，分開送

## §3f.1 決策三問（依序）

| Q | 問題 | Yes | No |
|---|------|-----|-----|
| Q1 | 同一個 backend code path？（同一段 missing auth check / 同一個 IDOR 欄位） | → Q2 | 不重複，分開送 |
| Q2 | 同一個 fix 能否一起修好？ | **合併 1 份** | 分開送（例：同 host 但 SSRF + IDOR 不同根因）|
| Q3 | 換了什麼？ |  |  |
|    | └ 換子端點 / 換 HTTP method | **合併** | — |
|    | └ 換查詢字串撈不同公司 / 不同 user_id | **合併**（屬枚舉證據）| — |
|    | └ 換 host（PROD ↔ SIT ↔ DEV，同 backend）| **可合可分**（HITCON 容許分送，保守做法合併）| — |
|    | └ 換 backend / 不同認證系統 / 不同 fix | — | **分開** |

## §3f.2 三種典型情境

| 情境 | 範例 | 處置 |
|------|------|------|
| **同 missing auth，不同子端點** | `/acp/v1/{zhaocai,robot,hideyoshi}` 都不驗 `planner_id` | 合併 1 份；端點列表格；PoC 選 1 讀 + 1 寫 |
| **同 backend code，不同 host** | PROD `api.ai` + SIT `apihub.sit` 同套 `/memory/v1/*` | 合併 1 份（`## Affected Hosts` 區塊列出）；或分送但互引 |
| **不同根因，剛好同 host** | 同 service 同時有 IDOR + SSRF | **分開送**（fix 不同）|

## §3f.3 「不同公司／不同 user_id」幾乎一定不算新 finding

- 換查詢字串撈不同 victim = 同一漏洞的**枚舉證據**，不是新漏洞
- 寫法：把所有確認過的公司／用戶整理成附錄表（強化嚴重性，不拆 N 份）
- 例外：若不同 victim 對應**不同 backend / 不同權限模型** → 才另計

## §3f.4 合併報告寫法（範本）

```markdown
## 受影響端點（同一 root cause）
| Endpoint | 動作 | 已驗證 |
|----------|------|-------|
| /acp/v1/zhaocai    | 讀 CRM         | ✅ |
| /acp/v1/dispatcher | 讀 CRM         | ✅ |
| /acp/v1/robot      | 寫 DailyReport | ✅ |
| /acp/v1/hideyoshi  | 寫+讀          | ✅ |

## PoC（代表性 2 個）
1. **讀**：zhaocai 撈出亞德客 customerCode
2. **寫**：robot 以 planner_id=99999 寫入 TRIGGERED

## 已枚舉客戶（附錄，強化嚴重性）
鴻海/廣達/緯創/仁寶/英業達/台積電/友達/群創/亞德客/日揚...
```

## §3f.5 撤回／合併處理流程（強制）

當判定 N 份報告應合併為 1 份：

1. **挑主 ID**：優先順序 = 已送出 > ready_to_submit > needs_revalidation > draft；同階段挑 severity 最高的
2. **重寫主 ID 報告**：合併端點清單 + PoC + 公司附錄，severity 取最高（讀+寫合併通常升 P1）；frontmatter 加 `components: [<被合併的 IDs>]` + `merged_date`
3. **被合併的報告**：
   - 檔名加 `(superseded by #N)` 後綴
   - frontmatter `status: withdrawn`（用 withdrawn 而非 superseded — 與「主動撤件」語義一致，bbops 過濾邏輯統一）
   - frontmatter 加 `superseded_by: <主 ID>` + `superseded_date` + `superseded_reason`
   - 保留檔案不刪，方便後續查證
4. **同步 RECON_DB / FINDINGS_QUICK_REF**：跑 `bash automation/generate_findings_index.sh <target>`
5. **commit 訊息**：`refactor(<target>): 合併 #A/#B/#C → #N (root cause: <一句話>)`

> **status 用 `withdrawn` 不用 `superseded` 的理由**：bbops Action Queue / FINDINGS_QUICK_REF 已有 withdrawn 處理邏輯（過濾不顯示）；新增 superseded 會增加 schema 複雜度。`superseded_by` 欄位本身已記錄合併關係，不需另開 status 值。

## §3f.6 開新 Finding 前的預檢（強制）

任何 agent 開新 Finding／FORM 前必須執行：

```bash
# 1. 先讀 FINDINGS_QUICK_REF — 看根因是否已被覆蓋
cat workshop/<target>/FINDINGS_QUICK_REF.md | grep -i "<關鍵字>"

# 2. 跑 vault_precheck — 端點 / host 比對
bash automation/vault_precheck.sh <target> "<endpoint或host>" "<service>"

# 3. 用 §3f.1 三問自我審查
```

任一命中 → 停止開新 Finding，改走「合併」或「Attempt」流程。

## 用戶質疑「這不是挖過了嗎」處理 SOP

紅旗：用戶說「這不是挖過了嗎」/「這挖過了」→ **立刻停**，**不能繼續挖**，做以下：

1. 讀 `workshop/<target>/FINDINGS_QUICK_REF.md`（含父 target QUICK_REF，若是 sub-target）
2. 列出**所有**覆蓋此區域的 Finding ID
3. 分類：
   - **True duplicate**（同 endpoint + 同 technique + 同 finding）→ STOP，問用戶要挖什麼新地方
   - **新資訊在已知 endpoint**（新 cred / 新 path / 新行為，未在 RECON_DB）→ 不是 dup，**明確說**「[ID] 覆蓋此端點，但 [X] 是新的」，補 RECON_DB 再繼續
   - **攻擊鏈**（已知 A + 新 B = 新 impact）→ 不是 dup，**明確說**「我用 [Finding ID] + 這個新發現組成鏈，目標是 [Z]」，先說 chain goal 再繼續

**禁用 pattern**：「I'm using it for a different purpose」WITHOUT 命名 specific 新資訊或 chain → 是 rationalization 紅旗 = duplicate → STOP

詳見 memory `feedback_no_goal_shifting_on_duplicate` + `feedback_dedup_root_cause`。

## Cross-reference

- AGENTS.md §3f（已 promote 到本 skill）
- memory `feedback_dedup_root_cause`
- memory `feedback_no_goal_shifting_on_duplicate`
- automation/vault_precheck.sh
- workshop/`<target>`/FINDINGS_QUICK_REF.md
