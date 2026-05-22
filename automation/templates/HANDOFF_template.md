# {{TARGET}} — Session Handoff

> 由 vault-sync agent 在 session 結束時自動更新。
> pre-recon agent 在 session 開始時自動讀取。
> 只記錄 **FINDINGS_QUICK_REF 和 RECON_DB 不包含的資訊**。

---

## 最後 Session

- **日期：** {{DATE}}
- **持續時間：** —
- **狀態：** active / blocked / parked
- **Audit log（§6f）：** `$LOGS_ROOT/claude_audit_<UTC_YYYYMMDD>.log`
  - Session ID 前 8 碼（接手 grep raw 指令用）：`<由 vault-sync 填入；head -1 取得>`
  - 跨多日的 session：在 Discovery Log 標多個日期檔的 audit ref

---

## 上次在做什麼

> 一句話：正在測試的假設或方向

（填入：例如 "測試 /api/v2/send 是否接受 md5 raw password 直接送 SMS"）

---

## 立即下一步

> 具體到可以直接複製執行的程度

```bash
# 填入下一個 curl / 命令 / URL
```

---

## 阻塞原因

> 如果有阻塞，說明在等什麼

- （無）

---

## 進行中的線索（尚未建 Vault Finding）

> 已找到、值得追蹤、但還沒確認或尚未建 Vault Finding 的東西

| 線索 | 位置 / 端點 | 狀態 | 優先度 |
|------|------------|------|--------|
| — | — | 待驗證 | — |

---

## 本 Session 新學到的東西

> 不是 finding，是理解（架構、行為、繞過方式）

- —

---

## 注意事項 / 上下文

> 任何下次 session 不看 git log 就會忘記的重要背景

- —
