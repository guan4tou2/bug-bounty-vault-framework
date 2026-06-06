# Automation Conventions

> 2026-06-04:明確化 `automation/` vs `_automation/` 的角色,以及跨 session 溝通層保留範圍。

## 兩個自動化目錄的分工

| 目錄 | 用途 | 命名範例 | 由誰呼叫 |
|---|---|---|---|
| **`automation/`** | **Workflow runners** — session lifecycle、locks、audit、init、release、broadcast。一般是 `.sh`,需要 user 在 session 中直接執行 | `claim.sh` / `release.sh` / `init_target.sh` / `audit_workspace.sh` / `session_start_brief.sh` / `session_end_checklist.sh` / `status.sh` / `broadcast.sh` / `session_brief.sh` | user 手動 / agent 命令 |
| **`_automation/`** | **KB-write helpers + lint / sync** — 短小 Python,大多 idempotent,常由 `pre-commit` hook 觸發或 `staging_status` 類 review 用 | `sync_pattern_index.py` / `staging_status.py` / `check_tool_arsenal.py` / `split_lessons.py` / `split_writeups.py` / `lint_frontmatter.py` / `platform_form.py`(2026-06-04 合併後)| pre-commit hook / 維護腳本 |

**判別三題:**

1. 這腳本是 session 內 user 會直接打的指令嗎?→ `automation/`
2. 這腳本是 lint / sync / KB-write 工具,接 hook 或定期跑?→ `_automation/`
3. 是 .sh 還是 .py?偏好(但不強制):`.sh` 在 `automation/`,`.py` 在 `_automation/`

**例外註記:**`automation/` 也有 .py(`lint_platform_form_types.py` — 歷史遷移中);長期目標:全部 <Platform> lint 都進 `_automation/`(2026-06-04 已合併到 `_automation/platform_form.py`)。

---

## 跨 session 溝通層保留範圍(2026-06-04 review)

3 小時實測使用統計:

| Subsystem | event 數 | 評估 | 處置 |
|---|---|---|---|
| `claim.sh` / `release.sh` lock | 4 + 5 | ✅ 高 | 必留 |
| `status.sh` 心跳 + lock.current_task | 4 | ✅ 中 | 必留 — 寫進 lock JSON,便宜 |
| `SESSION_LOG.jsonl` append | 23 total | ✅ 中 | 必留 — 自動補,append-only |
| `session_brief.sh` snapshot | (查詢時用) | ✅ 中 | 必留 — read-only,無 write 成本 |
| `release.sh` handoff capsule | 5 | ✅ 中 | 必留 — 下個 session 接手有用 |
| **`broadcast.sh` + `_inbox/`** | **1(smoke test)** | 🟡 低 | **保留但標 experimental** — 未來真有跨人/跨 session 同步需求(opus-4.6 並行 + pipeline 同時動)才會被觸發 |

**結論:** 通訊層**不砍**(會出現多 session/多 agent 場景,基礎建設要在),但用 README 標明 broadcast/inbox 是 experimental,避免誤以為是日常工作流。

---

## 加新自動化的決策樹

```
要加新腳本嗎?
│
├─ session 內 user 直接打的(claim/release/audit)
│  └─ automation/<name>.sh
│
├─ lint / sync / KB 維護(idempotent,hook 觸發)
│  └─ _automation/<name>.py
│
├─ 同領域已有 3+ 個腳本(如 <Platform>)
│  └─ 合併到單檔 + subcommand,別新增第 N+1 個
│
└─ 跨 session 溝通?
   ├─ status / handoff → 用現有 status.sh / session_brief.sh
   └─ 新功能 → 看是不是真有需求,否則先記 issue 等實際命中
```

---

## Related

- `automation/active_sessions/README.md` — lock / comm layer 設計
- `_automation/staging_status.py` — staging triage helper
- `_automation/check_tool_arsenal.py` / `sync_pattern_index.py` — KB drift check
- CLAUDE.md §「🚨 Session 開頭」— scope 文件入口
