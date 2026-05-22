# {{TARGET}} — Recon Database

> **Session 開頭必讀**（搭配 FINDINGS_QUICK_REF.md）。這份記錄所有原始 recon 數據：憑證、路徑、帳號、infra。
> 每次找到新東西就追加，commit 儲存。
> 最後更新：{{DATE}}

---

## 狀態速覽

| 項目 | 內容 |
|------|------|
| Platform | |
| Program URL | |
| 最後 recon 日期 | |
| 目前狀態 | active / parked / closed |
| 已知 findings | 見 FINDINGS_QUICK_REF.md |
| 重點攻擊面 | — |

---

## ⏳ Deferred Actions（已部署，等觸發）

> **新 session 必讀。** 已執行但尚未觸發的動作。「找到端點」≠「已部署動作」——凡是部署了 payload、寫入了檔案、觸發了需等待的鏈條，必須在此紀錄狀態，並在 memory 更新。

_目前無 deferred action。_

<!--
範例欄位（有 deferred action 時填入）：

| 動作描述 | 目標主機 | 部署時間 | 觸發條件 | 已觸發 | 回呼 / 回傳 |
|---------|---------|---------|---------|-------|------------|
| /app/main.py payload write（#84） | api.example.com PROD | Session N | pod 自然重啟 | ❌ | VPS :80/rce_proof |

SSRF 能力邊界（常見誤解）：
- 「服務可達（oracle confirmed）」≠「可讀取回應」≠「可利用」
- 若是 blind SSRF：只能確認連通性，無法讀任何回應內容
-->

---

## 🔑 Credentials & Keys

> ⚠️ 內部使用，不得出現在送給平台的表單或 ZIP。

| Type | User / Key | Value | Host / Service | 來源 | 狀態 |
|------|-----------|-------|---------------|------|------|
| — | — | — | — | — | — |

---

## 🔍 Known Artifacts（已確認存在，勿重複挖）

> **每次確認一個 finding，立刻把所有具體識別子（姓名、IP、token、email、分機、版本等）追加到這裡。**
> vault_precheck.sh 會搜這個 section — 這是你最重要的去重防線。
> 格式：`| #NNN | <類型> | <值 1>、<值 2>... | <備註> |`

| Report | 類型 | 具體識別子 | 備註 |
|--------|------|-----------|------|
| — | — | — | — |

---

## 🛤 Discovered Paths & Endpoints

> Confidence: **TENTATIVE**（間接跡象）→ **FIRM**（直接觀測）→ **CONFIRMED**（多源驗證）

| URL / Path | Method | Auth? | 回應 | Confidence | 備註 | 狀態 |
|-----------|--------|-------|------|-----------|------|------|
| — | — | — | — | — | — | — |

---

## 🖥 Internal Infrastructure

| Host / IP | Port | 角色 | 來源 |
|-----------|------|------|------|
| — | — | — | — |

---

## 👤 Accounts & Usernames

| 帳號 | 平台 / 系統 | 備註 | 來源 |
|------|-----------|------|------|
| — | — | — | — |

---

## 📦 Technology Stack

| Service / Framework | Version | 位置 | 備註 |
|--------------------|---------|------|------|
| — | — | — | — |

---

## 🎯 Attack Surface（已測 / 未測）

| 端點 / 功能 | 狀態 | 優先度 | 下一步 | Attack Path Hint |
|-----------|------|--------|--------|-----------------|
| — | 未測 | — | — | — |

---

## 🛡️ Pre-flight Checks（§0g — 動手前版本+CVE 預檢）

> **何時填**：拿到具體 target 版本或 cloud target 後、動手分析前，依 AGENTS.md §0g 跑預檢並把結果記在此處。
> **多版本目標**：一個版本（或一個機型）一個 entry；同 vendor 多機型 firmware 分別記錄。
> **SaaS / Cloud**：用 §0g.9 子表 B 模板；有版本號 target 用子表 A。

_尚無記錄。第一次跑 §0g 時依 AGENTS.md §0g.9 模板新增 entry。_

---

## 📋 Operation Log

> **送出請求之前先填一行（執行前記錄）。** `結果` 欄預填 `pending`，執行後立即更新。
> 需記錄：任何 POST/PUT/PATCH/DELETE、手動 curl GET（測試端點）、exploit/payload 測試。
> 不需記錄：自動化掃描工具逐條輸出、VPS 後台腳本（poller/C2/exploit.sh）、純瀏覽器 UI 操作。
>
> 取得來源 IP：`curl -s https://ifconfig.me`（本機）或 `ssh <vps-user>@<vps-ip> "curl -s ifconfig.me"`（VPS）

| 時間（本地） | 時間（UTC） | 來源 IP | 方法 | 目標 URL | 意圖說明 | 結果 |
|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — |

---

## 📝 Session Log（滾動追加）

### {{DATE}} — 初始化

- RECON_DB 建立
