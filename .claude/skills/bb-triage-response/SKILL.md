---
name: bb-triage-response
description: Use when user pastes triage replies or says Accepted, Duplicate, N/A, Informative, Triaged, Resolved, bounty result, severity decision, vendor reply, or triage result.
---

# Bug Bounty — Triage 回覆處理（§9 + §10b 規則）

> **2026-05-16 從 AGENTS.md §9 + §10b promote 到 skill**：高頻陷阱 — 用戶貼 triage 回覆時容易只討論不更新；獨立 skill 強制觸發 5 處同步。

## 觸發紅旗

用戶說以下任一句 = 必須觸發本 skill：
- 「triage 回覆 / 結果」
- 「N/A」/「Duplicate」/「Triaged」/「Accepted」/「Informative」/「Resolved」
- 「廠商回覆 / bounty / VRT 判定」
- 貼一段 disclosure channel / vendor comment

**禁止：只討論 triage 結果而不同步更新檔案**。

## 5 處強制同步（順序：memory → Submission → Kanban → KB → commit）

### 1. `memory/project_<target>.md`

更新欄位：
- 狀態（active / parked / closed）
- Triager 說了什麼（一句話摘要）
- Severity 修正（若 severity 被降級）
- Reward / reputation 說明（若有）
- 結案 emoji 修正：📤 → ✅ Accepted / ❌ N/A / ❌ Dup / ⚠️ Informative

### 2. `memory/MEMORY.md`

更新該 target 的 summary line：
- 狀態符號改：📤 → ✅/❌
- 加結果摘要（如 `❌ #3703965 Duplicate (cloudAccessConfig→原報 Informative)`）

### 3. `Bug Bounty Vault/01 - Targets/<t>/Submissions/Submission - <t> - <ID>.md`

frontmatter 更新：

```yaml
status: accepted | duplicate | na | informative | resolved | fixed
triage_status: <平台回覆原句一句話>
triage_date: YYYY-MM-DD
triager: <triager name 或 anonymous>
bounty: <金額或 N/A>
```

body 加 `## Triage Result` 區塊：

```markdown
## Triage Result

- **Date**: YYYY-MM-DD
- **Status**: <Accepted/Duplicate/N/A/Informative/Resolved>
- **Triager**: <name>
- **Response**: 
  > <貼平台原始回覆，至少 2-3 句保留 context>
- **Bounty**: $XXX / N/A
- **Severity note**: <若有 severity 調整>
- **Lessons**: <若有值得記的教訓>
```

### 4. Kanban（**兩個檔案都要改**）

- `Bug Bounty Vault/00 - Dashboard/Master Kanban.md` — 跨 target master view
- `Bug Bounty Vault/01 - Targets/<t>/Kanban - <t>.md` — per-target

**移卡規則：**

| triage 結果 | 從 column | 移到 column |
|---|---|---|
| Accepted / Resolved | 📤 Submitted — Waiting | ✅ Triaged / Closed |
| Duplicate | 📤 Submitted — Waiting | ✅ Triaged / Closed（標 dup）|
| N/A / Informative | 📤 Submitted — Waiting | ✅ Triaged / Closed（標 N/A）|
| Pending more info | 📤 Submitted — Waiting | ⏸️ On Hold（等廠商）|

### 5. Vault `09 - KB/Lessons Learned.md`（若有教訓）

只有以下情況需要加 LL：

- 平台政策驚訝（N/A 原因出乎意料）
- Severity 修正改變對 severity 的認知
- Triager 給的 framework 解釋（例：「OCC API anonymous behavior = 預期功能」）
- 累犯類錯誤（同一 pattern 再次 N/A）

新增 LL 格式：

```markdown
### LL #NN — <短標題>（YYYY-MM-DD <target>）

**情境**：<一句話>
**Triager 回覆**：<原句>
**教訓**：<未來怎麼避免 / 怎麼框架化>
**Cross-ref**：[[Submission - <t> - <ID>]] / [[Pattern - ...]]
```

### 6. commit → graphify hook 自動 fast rebuild

```bash
git add memory/ "Bug Bounty Vault/"
git commit -m "[triage] <target> <ID>: <Accepted|Duplicate|N/A> — <one-line>"
```

graphify post-commit hook 自動 rebuild，不需手動跑 `graphify update`。

## Vault 還需要更新的（若相關）

- `Bug Bounty Vault/01 - Targets/<t>/Target - <t>.md`（hub 的 Submission Status 區塊）
- `Bug Bounty Vault/01 - Targets/<t>/Findings/Finding - <t> - <ID>.md`（frontmatter status 與 last_verified 同步）
- `Bug Bounty Vault/09 - KB/Pattern - <相關 pattern>.md`（若 triager 修正 VRT）
- `Bug Bounty Vault/00 - Dashboard/Dashboard.md`（last_updated + Quick Stats）

## 禁止 pattern（高頻陷阱）

| 錯誤 | 為何不可 |
|---|---|
| 只討論 triage 結果不改檔 | 下次 session 看不到，狀態漂移 |
| 只改 memory 不改 Kanban | bbops Action Queue / Dashboard 看到的還是「Submitted Waiting」 |
| 只改一個 Kanban（漏 Master 或 per-target） | 兩個視圖不一致 |
| 沒 commit | graphify 不會 rebuild，跨 target query 看不到 |

## 完整 checklist（送件前 60 秒）

- [ ] memory/project_`<t>`.md status + 一句摘要
- [ ] memory/MEMORY.md summary line 狀態符號
- [ ] Vault Submission frontmatter + ## Triage Result
- [ ] Master Kanban 卡片移位
- [ ] per-target Kanban 卡片移位
- [ ] Vault Target hub Submission Status 區塊
- [ ] （若有教訓）Lessons Learned 加新條
- [ ] commit `[triage] <target> <ID>: <status>`

## Cross-reference

- AGENTS.md §9（已 promote 到本 skill）
- AGENTS.md §10b（Dashboard/Kanban 同步規範）
- memory `feedback_kanban_must_update_on_triage`
- Vault `00 - Dashboard/Master Kanban.md`
- Vault `09 - KB/Lessons Learned.md`
