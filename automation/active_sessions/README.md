# Active Sessions Lock Registry

**目的**：多 session 並行挖洞時的協調機制。lock-file 是 machine source of truth；HANDOFF.md 的 `## Active Sessions` 區段是 mirror（人類可讀）。

## Schema

每個 lock 是 `<safe_scope>.lock` 檔，內含 JSON：

```json
{
  "session_id": "uuid",
  "owner": "claude-opus-4-7",
  "scope": "example-target/sub-service/idor",
  "target": "example-target",
  "claimed_at": "2026-05-07T09:11:00Z",
  "last_heartbeat": "2026-05-07T09:25:00Z",
  "expected_release": "2026-05-07T11:00:00Z",
  "host": "example-host"
}
```

`<safe_scope>` = scope 把 `/` 換成 `--`，e.g. `example-target--sub-service--idor.lock`。

## Scope 階層與衝突規則

scope 用 `/` 分層,分 **target scope** 與 **shared-resource scope**(底線開頭):

### Target scopes
| Scope 範例 | 意思 |
|---|---|
| `example-target` | 整 target lock |
| `example-target/sub-service` | sub-service lock |
| `example-target/sub-service/idor` | sub-service + vuln-class lock |

### Shared-resource scopes（2026-06-04 新增 — 多 session 平行寫共享檔的保護）

當多個 Claude session / pipeline / agent 平行跑時,寫共享高頻檔(Pattern Index、Lessons Learned、Tool Arsenal、Skills…)會 race。下列 scope 把這類寫入分區互斥:

| Scope 範例 | 鎖定範圍 | 典型使用者 |
|---|---|---|
| `_meta` | 架構/文件補丁,無 target | 改 AGENTS.md / STRUCTURE.md / repo 規範 |
| `_kb` | 任何 `09 - Knowledge Base/` 寫入 | 大規模 KB 改造(SOTA refresh、批次升級) |
| `_kb/<area>` | 特定 KB 區域 | 例 `_kb/Pattern-Index`、`_kb/Lessons-Learned`、`_kb/Tool-Arsenal` |
| `_pipeline` | session-learning pipeline 跑 | 自動 proposal 提取 / promote 到 KB |
| `_staging` | `_staging/proposed/` 審核流 | 手動 review proposals 升 KB |
| `_automation` | `automation/` script 改 | 改 claim.sh / audit_workspace.sh 等核心腳本 |
| `_skill` | `.claude/skills/` 系列改 | 新增/改 skill(自動 sync .codex/.gemini)|
| `_agent` | `.claude/agents/` 改 | 新增/改 agent 提示 |
| `_dashboard` | `00 - Dashboard/`(Kanban Board 等)| 跨 target 寫入熱點;triage、進度同步 |

範例:
- 開 web-vuln-scan 設計時 claim `_skill`,期間 pipeline claim `_pipeline` 不撞(兄弟)
- 但若 pipeline 想 claim `_kb`(批量升 KB),而你正改 `_kb/Pattern-Index` → 撞(parent/child,衝突規則 #3)
- target 工作(`example-target`)與共享資源(`_kb`)互不撞(完全不同分支)

衝突邏輯由 `_lock_lib.sh::conflicts_with()` 統一處理,新 scope 自動沿用 prefix-based parent/child 規則。

**衝突判定（claim 時）**：

1. **完全相同** → 撞
2. **新 scope 是現有 scope 的 prefix**（claim parent，子已 lock）→ 撞
3. **現有 scope 是新 scope 的 prefix**（claim child，父已 lock）→ 撞
4. **完全不同分支**（兄弟、不同 target）→ 不撞

範例：`example-target/sub-service` 已 locked
- claim `example-target` → 撞（#2）
- claim `example-target/sub-service/idor` → 撞（#3）
- claim `example-target/example-msg-app` → 不撞（#4）
- claim `example-target` → 不撞（#4）

## 過期機制

- `last_heartbeat` 超過 30 分鐘 → 視為 dead session
- post-commit hook 觸發 heartbeat 更新（commit message 含 target name 即匹配）
- 過期 lock 由 `claim.sh` / `check_active_sessions.sh` 自動清掃到 `_expired/`，不阻塞新 claim

## 目錄

- `*.lock` — 活躍 lock（被 .gitignored；本機 only）
- `_expired/` — 過期/release 後的 archive，debug 用
- `_completed/` — release 時自動產生的 handoff capsule (scope/commits/files/last_task)
- `_inbox/<scope-or-session>/msg-*.md` — broadcast.sh 投遞的訊息;讀過會 rename `*.read`
- `SESSION_LOG.jsonl` — 跨 session 事件 bus(claim/release/status/broadcast/commit);append-only
- `.gitkeep` — 保留目錄結構

## 跨 session 溝通(2026-06-04 Full layer)

lock 告訴別人「我占哪個 scope」;`status` + `broadcast` + `SESSION_LOG` 告訴別人「我做到哪、有事要轉達」。

> **使用層級提示**(2026-06-04 review 後)
> - 🟢 **日常**:lock + `status.sh` + `session_brief.sh` + `SESSION_LOG` + handoff capsule(release 時自動產)— 90% 場景夠用
> - 🟡 **進階**:`broadcast.sh` + `_inbox/` — **experimental**,等真要跨人/跨 session 即時轉達訊息才用;3 小時實測使用 1 次(smoke test)
> - 仍然保留因為:opus-4.6 並行 / session-learning pipeline 並行 = 跨 session 場景會發生

```bash
# 心跳 + 公告當前正在做什麼(更新 lock.current_task + SESSION_LOG)
bash automation/status.sh "fixing Pattern Index drift"

# 看自己目前狀態
bash automation/status.sh --read

# 投訊息到別 session 的信箱(scope 或 session_id 都行)
bash automation/broadcast.sh --to=_kb "我在動 Lessons/，先別動"
bash automation/broadcast.sh --to=all "lint hook 壞了,等修好再 commit"

# 看自己的信箱
bash automation/broadcast.sh --inbox
bash automation/broadcast.sh --ack <msg-path>   # 標已讀

# 全景 snapshot(自己/別人/信箱/最近事件/handoff)
bash automation/session_brief.sh
bash automation/session_brief.sh --window=2h
```

release 時自動產出 `_completed/<ts>_<scope>_<sid>.md` handoff capsule,記錄 claim 期間的 commits + files_changed + last_task,讓下一個 session 接手不用問。

## 用法

```bash
# Session 開始
bash automation/check_active_sessions.sh           # 列出所有 active
bash automation/claim.sh example-target/sub-service/idor     # claim scope

# Session 中
# (post-commit hook 自動更新 heartbeat)

# Session 結束
bash automation/session_end_checklist.sh example-target  # 自動 release
# 或手動：
bash automation/release.sh example-target/sub-service/idor
```

## Vault 跨 repo 相容

scope 的 `target` 部分（第一段）跨 parent + Vault 共用。例：claim `example-target/sub-service` 同時鎖：
- parent repo `workshop/example-target/`
- Vault repo `01 - Targets/ExampleTarget/`

兩個 repo 都會在 commit 時觸發 heartbeat。
