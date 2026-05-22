---
name: bb-context-handoff
description: Use when session context is low, work needs checkpointing, takeover is needed, user says 快滿了/整理進度/handoff/checkpoint/context low/takeover/接手, or a long bug bounty session reaches a natural handoff point.
---

# Bug Bounty — Context Window 管理 + 接手協議（§0f 規則）

> **2026-05-16 從 AGENTS.md §0f promote 到 skill**：handoff 是高風險操作（搞錯會丟失 work-in-progress），獨立 skill 強制 trigger 完整流程。

## 何時觸發 handoff

**LLM 沒辦法自己感知剩多少 token**。觸發時機：

| Trigger | 場景 |
|---|---|
| 用戶顯式 | 「快滿了 / 整理進度 / handoff / checkpoint / 接手」 |
| LLM 自覺 | 寫完一份報告、跑完大型 PoC、確認 / 否定一個 hypothesis — 天然斷點 |
| 結構性 | 同 session 跑了 ≥ 30 turn 或 ≥ 1.5hr 後檢查是否該 handoff |
| 系統 | Claude Code 顯示 context warning 時 |

## Handoff 流程（current session，context 快滿時）

### Step 1：heartbeat lock

```bash
bash automation/heartbeat.sh <target>
```

確保 lock 還活著（30 min sweep 不會把你清掉）。

### Step 2：**不釋放 lock**

讓接手 session 用 `--takeover`，否則別人會搶到。

### Step 3：寫 In-Progress block 到 HANDOFF.md

Edit `workshop/<target>/HANDOFF.md`，加入：

```markdown
<!-- BEGIN_INPROGRESS — 由 handoff 流程寫入；新 dump 會 overwrite 此區 -->
## In-Progress（session <短 id> → next session takeover）

> Handoff 時間：<ISO timestamp>
> Reason：<context-low / explicit-handoff / milestone>
> Model：<claude-sonnet-4-6 / claude-opus-4-7>
> Scope：<lock scope>

### 已完成（不要重做）
- [x] ...

### 進行中（接手第一步）
- [ ] **next**: <精準到可複製執行的指令 / URL>

### 已驗證 hypothesis
- ...

### 已否定 hypothesis
- ...

### Pending decisions（接手 session 確認）
- ...

### File locations
- workshop/`<target>`/recon/...
- Vault `01 - Targets/<t>/Findings/Finding - <t> - <ID>.md`

### DO NOT do（避免重複）
- ...
<!-- END_INPROGRESS -->
```

### Step 4：commit + 結束

```bash
git add workshop/<target>/HANDOFF.md
git commit -m "[handoff] <target>: context-low @ <milestone>"
```

## 接手流程（new session）

### Step 1：讀環境

```bash
bash automation/check_active_sessions.sh
cat workshop/<target>/HANDOFF.md
```

### Step 2：看 `## In-Progress` 段

**如果存在 In-Progress**：

```bash
bash automation/claim.sh <scope> --takeover --owner=<new model>
# claim.sh 會檢查 HANDOFF.md 含 BEGIN_INPROGRESS，否則拒絕；
# 通過後把前 session lock 移到 _expired/<scope>.takeover-from-<sid>
```

**如果不存在**：用 `claim.sh <scope>` 一般 claim（前 session 自然完成；非接手場景）。

### Step 3：第一個訊息給用戶

```
接手 from session `<前 id>`，立即下一步是 `<In-Progress 第一條>`
```

### Step 4：工作中隨時 update

工作中可隨時 update `## In-Progress` 段（perl marker 替換或 LLM Edit），不會被 regen_handoff_active.sh 動到（marker 隔離）。

### Step 5：完成所有 In-Progress 後

整段刪除（保留 marker 但內容空），跑 vault-sync 寫 `## Last Completed Session`。

## `--takeover` vs `--force`

| 選項 | 用途 | HANDOFF.md 要求 |
|---|---|---|
| `--takeover` | 合作交接（前 session context 滿、留下交接訊息） | 必須有 BEGIN_INPROGRESS 段 |
| `--force` | 強搶（前 session 死掉、過期未自動清、沒留交接） | 不檢查；有資料丟失風險 |

## 異常結束的手動操作

| 情境 | 動作 |
|---|---|
| Session 結束但忘了跑 session_end_checklist.sh | `bash automation/release.sh <scope>` 手動釋放 |
| Lock 過期 30min+ 仍在 active_sessions/（sweep 沒生效）| `bash automation/release.sh --all` 全清 + 通報維護 |
| 想看最近 history | `git log --oneline --grep "<target>:" -20`（HANDOFF.md 不存 Recent Activity，避免被 git add -A 夾帶） |
| Vault Dashboard 沒同步 | `VERBOSE=1 bash automation/regen_dashboard_active.sh` |

## 查詢命令備忘

```bash
# 看誰在做什麼
bash automation/check_active_sessions.sh

# 看 <target> 最近活動（替代 Recent Activity）
git log --oneline --grep "<target>:" -20

# 看單一 lock 詳情
jq . automation/active_sessions/<scope>.lock
```

## Cross-reference

- AGENTS.md §0f（已 promote 到本 skill）
- automation/heartbeat.sh
- automation/claim.sh（`--takeover` / `--force`）
- automation/release.sh
- automation/check_active_sessions.sh
- automation/regen_handoff_active.sh / regen_dashboard_active.sh
- automation/templates/HANDOFF_template.md（含 audit log 檔名）
- skill bb-triage-response（若 handoff 同時要處理 triage 回覆）
