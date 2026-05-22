---
fileClass: Recon
target: "[[]]"
session_date: <% tp.date.now("YYYY-MM-DD") %>
session_time_start: <% tp.date.now("HH:mm") %>
session_time_end: ""
hours_spent: 0
scope_focus: ""
tools_used: []
artefacts: []
findings_produced: []
attempts_produced: []
kb_capture_done: false
kb_capture_verified_at: ""
status: "wip | complete | interrupted"
tags: []
---

# Recon — {{TARGET}} — {{FOCUS}} — {{date}}

> **Discovery note**：與 Finding/Attempt 同為 discovery-note，章節用 canonical 英文 H2（AGENTS.md §3b 擴充）。

## Purpose

這次想找什麼？範圍、假設、成功條件。

## Scope

- 子網域 / 端點 / 功能
- 帳號狀態（無 / 自己 / 雙帳號）
- 限制（不能跑 nuclei 全集、避開 prod 寫入）

## Tools & Config

| 工具 | 為何選 | 配置 |
|------|--------|------|
| | | |

---

## Activity Log

> 每個活動條目應含 audit ref（`[audit:SESSION8@UTC_HH:MM:SS]`）方便對應 §6f Bash audit log。
> 取得 session ref：`head -1 logs/claude_audit_$(date -u +%Y%m%d).log`

### `<HH:mm>` <活動>  `[來源 IP → 目標 IP]`  `[audit:SESSION8@HH:MM:SS]`

**endpoint / host：**

**account / role：**

**指令：**
```bash
```

**結果摘要：**

**判讀 / 下一步：**

### `<HH:mm>` ...

---

## Knowledge Capture Gate（本輪學到的東西）

> 沒有資料請寫 `N/A`，不能留空。session 結束前要跑：
> `bash automation/recon_kb_capture_gate.sh --verify <target> [recon_note_path]`

### 本輪學到的東西（Learned Items，必填）

- 新訊號/新模式（這輪第一次確認）:
- 失敗路徑與停止條件（避免下輪重複踩坑）:
- false positive 過濾規則 / triage 判讀:
- 可複用 command / matcher / payload:
```bash
```

### 思考決策鏈（Hypothesis Log，必填）

- hypothesis:
- test:
- result:
- next decision:

### 範例證據（若適用）

#### 成功案例（Successful Cases）

- endpoint / host:
- account / role:
- exploit primitive:
- command:
```bash
```
- 為什麼成功:

#### WAF / 防護繞過（Bypass Techniques）

- defense observed:
- blocked payload:
- bypass payload / encoding / protocol trick:
- command:
```bash
```
- evidence:

### 回填到 Vault

- Pattern / Playbook / Lessons / Round Log 更新路徑（至少一處）：
- 這次新增了什麼可重用知識（1-2 行）：
- 相關 Finding / Attempt（含 related_recon / related_pattern）：

### bbflow 經驗回寫判斷（必填）

- 是否有可重複偵測經驗（yes/no）：
- Decision：
  - 回寫 bbflow：<hunter / Nuclei template / Osmedeus profile / wiki / CHANGELOG 路徑>
  - 或不回寫原因：<target-specific / 尚未穩定 / false positive / 一次性證據 / 其他>
- wiki sanitization gate：<done / n/a>（若回寫 wiki，已移除 target 名稱、host/IP、token/cookie、raw log、screenshot、PoC 證據）

### 完成勾選（verify 會檢查必填項）

- [ ] 本輪 Learned Items 已填（至少 2 條；無則寫 N/A + 原因）
- [ ] 思考決策鏈已填（假設→測試→結果→下一步）
- [ ] 已回填至少 1 個 Vault 知識節點（Pattern / Playbook / Lessons / Round Log）
- [ ] bbflow 回寫判斷已填（回寫 hunter/template/profile/wiki/CHANGELOG 或不回寫原因）
- [ ] （選填）成功案例已補齊
- [ ] （選填）若有 WAF / 防護繞過，已補齊

---

## Findings Produced

- [[Finding - <target> - ...]]（連結到正式 Finding 頁）

## Attempts Produced

- [[Attempt - <target> - ...]]

## Open Leads（待續方向，尚未成 Finding/Attempt）

- 端點 X 待測 Y 角度
- 看到 cookie Z，需查 spec

---

## Raw Artifact Links

- 工具輸出：[[../../../../workshop/<target>/...]]
- 截圖：[[../../poc/...]]

---

## Related

- Target：[[]]
- 上一次 Recon：[[]]
- 引用 Pattern：[[]]
