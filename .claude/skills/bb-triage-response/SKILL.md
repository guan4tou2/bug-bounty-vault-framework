---
name: bb-triage-response
description: Use when user pastes triage replies or says Accepted, Duplicate, N/A, Informative, Triaged, Resolved, bounty result, severity decision, vendor reply, or triage result.
---

# Bug Bounty — Triage 回覆處理

> 高頻陷阱：用戶貼 triage 回覆時容易只討論不更新檔案。本 skill 強制觸發多處同步，避免狀態漂移。

## 觸發紅旗

用戶說以下任一句 = 必須觸發本 skill：
- 「triage 回覆 / 結果」
- 「N/A」/「Duplicate」/「Triaged」/「Accepted」/「Informative」/「Resolved」
- 「廠商回覆 / bounty / VRT 判定」
- 貼一段 disclosure channel / vendor comment

**禁止：只討論 triage 結果而不同步更新檔案**。

## 強制同步順序（Submission → Kanban → Target hub → Dashboard → KB → commit）

所有路徑相對於 vault root（repo 根目錄）。

### 1. `01 - Targets/<target>/Submissions/Submission - <target> - <ID>.md`

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

### 2. Kanban

- `01 - Targets/<target>/Kanban - <target>.md` — per-target board
- 若你維護跨 target 總覽（例如 `00 - Dashboard/` 下的 Kanban / Dataview 看板），同步移卡

**移卡規則：**

| triage 結果 | 從 column | 移到 column |
|---|---|---|
| Accepted / Resolved | 📤 Submitted — Waiting | ✅ Triaged / Closed |
| Duplicate | 📤 Submitted — Waiting | ✅ Triaged / Closed（標 dup）|
| N/A / Informative | 📤 Submitted — Waiting | ✅ Triaged / Closed（標 N/A）|
| Pending more info | 📤 Submitted — Waiting | ⏸️ On Hold（等廠商）|

### 3. `01 - Targets/<target>/Target - <target>.md`

更新 hub 的 Submission Status 區塊（frontmatter 與表格）。

### 4. `00 - Dashboard/Dashboard.md`

更新 `last_updated` 與 Quick Stats（若 Dashboard 由 Dataview 自動聚合則可略）。

### 5. `09 - Knowledge Base/Lessons Learned.md`（若有教訓）

只有以下情況需要加 LL：

- 平台政策驚訝（N/A 原因出乎意料）
- Severity 修正改變對 severity 的認知
- Triager 給的 framework 解釋
- 累犯類錯誤（同一 pattern 再次 N/A）

新增 LL 格式：

```markdown
### LL #NN — <短標題>（YYYY-MM-DD <target>）

**情境**：<一句話>
**Triager 回覆**：<原句>
**教訓**：<未來怎麼避免 / 怎麼框架化>
**Cross-ref**：[[Submission - <target> - <ID>]] / [[Pattern - ...]]
```

### 6. commit

```bash
git add "01 - Targets/<target>/" "09 - Knowledge Base/" "00 - Dashboard/"
git commit -m "[triage] <target> <ID>: <Accepted|Duplicate|N/A> — <one-line>"
```

> 若你的私有實作有 post-commit index / graph rebuild hook，commit 會自動觸發；否則手動重建索引。

## 還需要更新的（若相關）

- `01 - Targets/<target>/Findings/Finding - <target> - <ID>.md`（frontmatter status 與 last_verified 同步）
- `09 - Knowledge Base/Pattern - <相關 pattern>.md`（若 triager 修正 VRT 分類）

## 禁止 pattern（高頻陷阱）

| 錯誤 | 為何不可 |
|---|---|
| 只討論 triage 結果不改檔 | 下次 session 看不到，狀態漂移 |
| 只改一處不改 Kanban | 看板顯示的還是「Submitted Waiting」 |
| 跨 target 與 per-target 看板不一致 | 兩個視圖矛盾 |
| 沒 commit | 索引 / 跨 target query 看不到更新 |

## 完整 checklist（送件後 60 秒）

- [ ] Submission frontmatter + `## Triage Result`
- [ ] per-target Kanban 卡片移位
- [ ] 跨 target 看板（若有）卡片移位
- [ ] Target hub Submission Status 區塊
- [ ] Dashboard last_updated（若非自動聚合）
- [ ] （若有教訓）Lessons Learned 加新條
- [ ] commit `[triage] <target> <ID>: <status>`

## Cross-reference

- `AGENTS.md §9`（Triage 回覆處理）
- `bb-submission-readiness`（送件前 gate）
- `bb-knowledge-capture`（教訓回流 KB）
- `09 - Knowledge Base/Lessons Learned.md`
