---
type: lesson
id: "148"
title: "401/403 bypass matrix 對「鎖死系統」命中率近 0 — 先做 server fingerprint 再決定要不要跑"
tags:
  - bb-lesson
  - 403-bypass
  - recon
  - spa-catchall
  - fingerprint
  - prioritization
last_updated: 2026-06-04
---

# 教訓 #148. 401/403 bypass matrix 對「鎖死系統」命中率近 0 — 先做 server fingerprint 再決定要不要跑

## TL;DR
對「baseline 全 404、首頁很小」的鎖死系統一口氣跑 401/403 bypass matrix(25 變形)→ 看似命中 7 個 200 → 全是 SPA catch-all 假陽性 + 兩個 500 是 Apache+PHP 規範化 bug,**0 個真實 bypass**。先 fingerprint(Server header / cookie / tech stack)後決定是否跑 matrix,可省下半小時 + 避免錯把 500 文字當「資訊洩漏」報。

## 觀察
1. **SPA catch-all 全命中假陽**:`/X/..` 的 URL 規範化 = `/`,server 都回首頁,size 100% 等於 root。
2. **Apache + PHP 規範化 bug**:`/X/.` / `/X/..` 在 mod_rewrite 路由到 PHP handler,handler 對結尾 `.` 處理失敗 → 回 generic 500(`Content-Length: 39 ERROR Status: 500`)。容易誤判為「endpoint 真實存在 → Spring Boot Actuator」,實際上系統根本沒有 Java middleware。
3. **500 沒帶 stack trace = 不可報**:`Content-Length: 39` 的純文字 500 沒洩漏路徑/版本/敏感資料,三題檢驗 Q1 = 攻擊者拿到「500 字串」= 沒影響 = N/A。
4. **真實命中需要**:baseline 不是 404(eg 403 才是真有保護的)+ server 不是 Apache+PHP 大鍋(Spring Boot / .NET / Nginx 各家規範化行為不同)。

## 規則(先 fingerprint,再決定要不要跑)

```bash
# Step A: server fingerprint(每個系統 10 秒)
curl -sk -I "https://target/" | grep -iE "Server:|X-Powered-By:|Set-Cookie:"
# 觀察:
#   Server: Apache + PHPSESSID cookie  → Apache+PHP 大鍋,/X/. 容易 500 = 假信號
#   Server: nginx + JSESSIONID         → 真 Java backend,bypass matrix 可能有戲
#   Server: Microsoft-IIS              → ASP.NET,bypass matrix 高 ROI
#   Server: Cloudflare                 → 後端被遮,bypass matrix 對 CDN 反應
#   無 Server header / Server: gunicorn → Python,可能 SPA catch-all 機率高

# Step B: SPA catch-all 預檢(每個 baseline 不是 4xx 的系統 5 秒)
root_size=$(curl -sk "https://target/" | wc -c)
random_size=$(curl -sk "https://target/abcdef_random_404_check" | wc -c)
# root_size == random_size → SPA catch-all,bypass matrix 對「/admin」必假陽,跳過
# root_size != random_size → 真實 routing,可跑 matrix
```

## 應跑 matrix 的條件(同時滿足)
1. baseline = 4xx **且不是 404**(403/401 才是真有保護)
2. 非 SPA catch-all(`/abc_random` 跟 `/` size 不等)
3. server 非 Apache+PHP 大鍋(或測試前先 grep 過 `/X/.` 不會 500 假陽)

## 不該跑 matrix 的場合
- baseline 全 404 + Apache+PHP → 改去測**真實已知的 endpoint**(eg 登入頁 / API 路徑 / form),用 `type-juggling` / `business-logic-vulnerabilities` / `http-host-header-attacks` 等 skill
- SPA catch-all 確認 → 改去 grep JS bundle 撈真實 endpoint

## 500 response 該不該報的判準

| 500 內容 | 報? | 為什麼 |
|---|---|---|
| 含 stack trace + 路徑 + 版本 | ✅ Information Disclosure | 真資訊洩漏(同 NF-010 ASP.NET 模式)|
| 只有「ERROR Status: 500」純文字 | ❌ 不報 | 拿到 500 字串 = 沒影響 = N/A |
| 含 SQL 錯誤訊息 | ✅ SQLi 候選 | error-based oracle |
| 含 path traversal / 部分檔名 | ✅ Info Disclosure | 路徑洩漏 |

## Related
- [[LL-120-spa-catch-all-偵測法-批量掃描前必須排除|教訓 #120]] — SPA catch-all 必先偵測
- [[Lessons Learned]] MOC §資訊洩漏 — 500 / 4xx 大 body 判讀
- [[Reference Card - Vulnerability Type Classification]] — 升降級規則
- yaklang skill `401-403-bypass-techniques` 對「真實 4xx baseline」才高 ROI
- yaklang skill `recon-and-methodology` Java middleware fingerprint — 先確認 Spring Boot 才測 Actuator
