---
fileClass: ReferenceCard
type: reference-card
title: MCP Servers Catalog
last_updated: 2026-07-08
tags: [reference-card, mcp, tooling, external, installation, bb-referencecard]
source: vault-distilled
added: 2026-07-08
related:
  - Reference Card - External Skills Catalog
---

# Reference Card — MCP Servers Catalog

> **目的:** 列出這套 workflow 推薦掛載的 MCP server，讓新 clone / 接手者知道**哪些 server 不是本 repo 自帶，需要自己接進 `.mcp.json`**（本 repo 只放 pointer，不 ship 任何 server 設定 / runtime token）。
>
> **安全提醒:** 掛載一個 MCP server = 在自己的 agent session 載入別人寫的工具，屬「工具可被 prompt-injection 觸發、導致 system-prompt / 資料外洩」同類風險。只接你信任來源的 server；**runtime token / bearer 憑證絕不 commit 進版控**（用 env var 或 placeholder，執行期才填）。與第三方 skill 的處置一致，見 [[Reference Card - External Skills Catalog]]。

---

## 安裝方式

MCP server 有兩種掛法（擇一）：

```bash
# 方式 A：CLI（寫進 user 或 project scope）
claude mcp add <name> --scope project -- <command> <args...>

# 方式 B：直接編輯 project 的 .mcp.json（stdio server 範例）
# {
#   "mcpServers": {
#     "<name>": { "command": "<cmd>", "args": ["<args>"] }
#   }
# }
```

需要 token 的 server（SSE / HTTP transport）在 `.mcp.json` 用 `headers.Authorization` 帶 `Bearer <TOKEN>`——**該 token 於本機/執行期生成，不入庫**。

---

## Browser / dynamic recon

| Server | 一句話 | 來源 |
|---|---|---|
| **chrome-devtools** | 透過 DevTools Protocol 驅動真實 Chrome：navigate / 檢視 DOM・console・network / 效能 trace，適合動態 web 偵察與驗證 client-side 行為 | https://github.com/ChromeDevTools/chrome-devtools-mcp |

**chrome-devtools 安裝**

```bash
claude mcp add chrome-devtools --scope project -- npx -y chrome-devtools-mcp@latest
```

或 `.mcp.json`：

```json
{
  "mcpServers": {
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest"]
    }
  }
}
```

- **需求:** Node LTS 以上、Chrome 穩定版以上。
- **常用 flag:** `--headless`（無 UI）、`--isolated`（暫時 profile，用完清）、`--slim`（只 3 個基本工具）、`--browser-url`（接既有 Chrome instance）。

---

## 擴充本表

新增一條 server 時照同格式：**名稱 + 一句話用途 + 來源連結 + 安裝指令**。踩到下列任一就**不要**收進本 catalog（留在私有工作實例即可）：需要商業授權才跑的工具設定、含機構/target 專屬 URL、任何 runtime secret / token。
