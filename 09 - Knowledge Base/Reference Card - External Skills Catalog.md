---
fileClass: ReferenceCard
type: reference-card
title: External Skills Catalog
last_updated: 2026-06-06
tags: [reference-card, skills, external, yaklang, installation, bb-referencecard]
source: vault-distilled
added: 2026-06-06
---

# Reference Card — External Skills Catalog

> **目的:** 列出 vault 推薦安裝的第三方 skill 套件,讓新 clone / 接手者知道**哪些 skill 不是 vault 自帶,需要自己跑 `npx skills add`**。
> 
> **安全提醒:** 安裝任何第三方 skill = 在自己 Claude session 載入別人寫的 SKILL.md,跟 [[LL-144-mcp-skill-執行可被-prompt-injection-觸發-system-prompt-外洩|教訓 #144]] 同類風險。skills.sh 有第三方 audit(Gen / Socket / Snyk),不過 Snyk 對攻擊 payload 教學常誤判 Critical,**Gen audit 是最可靠指標**。

---

## 安裝方式

```bash
# 進入 vault 根目錄
cd /path/to/vault

# 單 skill 安裝
npx skills add https://github.com/yaklang/hack-skills --skill <skill-name>

# 安裝路徑:.agents/skills/<name>/ + symlink → .claude/skills/<name>/
# 多 agent 通吃(Claude Code / Codex / Cursor / Antigravity / Cline / OpenCode / Warp / 14 個)
```

每次安裝會問你:agent(全選 OK)、scope(Project)、method(Symlink)、最終 confirm。

---

## yaklang/hack-skills(22 個推薦)

來源:https://github.com/yaklang/hack-skills(894 stars,103 skills total)。
我們挑選了 **22 個對 bug bounty 工作流真正有用** 的(全 22 個今天 2026-06-06 都在 vault 跑過,內容驗證 OK)。

### Round 1:高 ROI + 完全沒重疊(8)

| Skill | 一句話 | Audit |
|---|---|---|
| `business-logic-vulnerabilities` | 商業邏輯漏洞(價格 / 流程 / 負數 / coupon stack)711 行 | 全 pass ✅ |
| `401-403-bypass-techniques` | 401/403 bypass matrix(path / method / header / 協議) | gen:pass / socket:1 alert |
| `dependency-confusion` | 私倉/公倉 namespace squat 供應鏈攻擊 | gen+socket:pass |
| `waf-bypass-techniques` | WAF 識別 + Ghost Bits + 產品矩陣 | gen+socket:pass |
| `graphql-and-hidden-parameters` | GraphQL introspection / batching / hidden field | gen:pass |
| `authbypass-authentication-flaws` | Password reset / MFA bypass / token predictability | gen:pass |
| `csp-bypass-advanced` | CSP base-uri / object-src / nonce 重用 | gen:pass |
| `http-host-header-attacks` | Host header injection / password reset poisoning | gen:pass |

### Round 2:JS / PHP target 用得到(7)

| Skill | 一句話 |
|---|---|
| `prototype-pollution` | JS PP + gadget chain |
| `prototype-pollution-advanced` | PP → RCE + KNOWN_GADGETS.md 配套 |
| `type-juggling` | PHP 弱比較 / magic hash(`0e1234` / array / null) |
| `http-parameter-pollution` | HPP 跨 CDN/WAF/app 解析不一致 |
| `crlf-injection` | CRLF + response splitting + Unicode bypass |
| `nosql-injection` | MongoDB / Redis operator injection(`$ne`, `$gt`) |
| `upload-insecure-files` | IIS/Nginx/Apache/Tomcat 解析 CVE matrix |

### Round 3:移動 / Auth 高風險(3)

| Skill | 一句話 | Audit 注意 |
|---|---|---|
| `jwt-oauth-token-attacks` | JWT alg:none / kid/jku / PKCE bypass | Snyk fail(內容含 payload 範例,誤判) |
| `mobile-ssl-pinning-bypass` | Frida / objection / Xposed pinning bypass | — |
| `android-pentesting-tricks` | Android WebView / Frida hook / intent / Play Integrity | Socket+Snyk fail(誤判) |

### Round 4:廣度框架(比 vault 既有深 + 廣)(4)

| Skill | 一句話 | 配套 |
|---|---|---|
| `xss-cross-site-scripting` | 573 行 XSS 完整框架(8 context matrix / Blind XSS / CSP bypass) | + ADVANCED_XSS_TRICKS.md, SCENARIOS.md |
| `ssrf-server-side-request-forgery` | 434 行 SSRF(cloud metadata / IP bypass / gopher / URL parser confusion) | + SCENARIOS.md, URL_PARSER_TRICKS.md |
| `idor-broken-object-authorization` | 487 行 IDOR/BOLA/BFLA + ORM filter injection(Django/Prisma) | — |
| `recon-and-methodology` | 447 行 Zseano / GitHub recon / Java middleware fingerprint | — |

---

## 一鍵全裝(複製貼到 terminal)

```bash
cd /path/to/vault

# Round 1
npx skills add https://github.com/yaklang/hack-skills --skill business-logic-vulnerabilities
npx skills add https://github.com/yaklang/hack-skills --skill 401-403-bypass-techniques
npx skills add https://github.com/yaklang/hack-skills --skill dependency-confusion
npx skills add https://github.com/yaklang/hack-skills --skill waf-bypass-techniques
npx skills add https://github.com/yaklang/hack-skills --skill graphql-and-hidden-parameters
npx skills add https://github.com/yaklang/hack-skills --skill authbypass-authentication-flaws
npx skills add https://github.com/yaklang/hack-skills --skill csp-bypass-advanced
npx skills add https://github.com/yaklang/hack-skills --skill http-host-header-attacks

# Round 2
npx skills add https://github.com/yaklang/hack-skills --skill prototype-pollution
npx skills add https://github.com/yaklang/hack-skills --skill prototype-pollution-advanced
npx skills add https://github.com/yaklang/hack-skills --skill type-juggling
npx skills add https://github.com/yaklang/hack-skills --skill http-parameter-pollution
npx skills add https://github.com/yaklang/hack-skills --skill crlf-injection
npx skills add https://github.com/yaklang/hack-skills --skill nosql-injection
npx skills add https://github.com/yaklang/hack-skills --skill upload-insecure-files

# Round 3
npx skills add https://github.com/yaklang/hack-skills --skill jwt-oauth-token-attacks
npx skills add https://github.com/yaklang/hack-skills --skill mobile-ssl-pinning-bypass
npx skills add https://github.com/yaklang/hack-skills --skill android-pentesting-tricks

# Round 4
npx skills add https://github.com/yaklang/hack-skills --skill xss-cross-site-scripting
npx skills add https://github.com/yaklang/hack-skills --skill ssrf-server-side-request-forgery
npx skills add https://github.com/yaklang/hack-skills --skill idor-broken-object-authorization
npx skills add https://github.com/yaklang/hack-skills --skill recon-and-methodology
```

Install 自動拉 sibling docs(SCENARIOS / METHODOLOGY / CHECKLIST / KNOWN_GADGETS / WAF_PRODUCT_MATRIX / ADVANCED_XSS_TRICKS / URL_PARSER_TRICKS),11 個檔同 skill 一起進。

---

## 安裝驗證

```bash
# 確認 22 個都在
ls .agents/skills/ | grep -v "^bb-" | wc -l    # 應該 ≥ 22
ls .claude/skills/ | grep -v "^bb-\|README" | wc -l  # symlinks 同數

# 跑 audit(我們的)
bash automation/audit_workspace.sh
# lint(包含 KB-Pattern frontmatter)
bash automation/lint_workspace_skills.sh
```

---

## ❌ 我們審過但**不安裝**的(供參考避免裝錯)

### `aradotso/security-skills` 整包不裝(66 skills)

紅旗信號:
- 廠商名 stuffing(`avast-*` × 6、`bitdefender-*` × 6、`malware-*` × 14)
- 近似重複(`malware-detection-awareness` / `malware-detection-and-removal` / `malware-detection-warning` 三件套)
- install 數叢聚 300-400 區間(刷量特徵)
- **頂級 skill audit 不過**:`anthropic-cybersecurity-skills`(478 installs)Gen=**FAIL** + Socket=**WARN**
- 多數是 **defensive / SOC / awareness** 內容,不是 bug bounty 用

### `yaklang/yaklang/pentest-task-design` 不裝

只有 1 個 skill,1 install,無內容。

### `yaklang/hack-skills` 剩 80 個不裝(僅選 22)

**跟 vault 既有重疊嚴重**:
- `hack` / `recon-for-sec` / `api-sec` / `api-recon-and-docs` — vault 有完整 recon stack
- `sqli-sql-injection` — vault 有 Pattern - Blind SQL Injection + LL-146
- `cors-cross-origin-misconfiguration` — vault 有 3 個 CORS pattern
- `race-condition` — vault 有 Pattern - Race Condition Single-Packet
- `web-cache-deception` — vault 有 Pattern - Web Cache Deception

**out-of-scope**(bug bounty 通常不接受):
- `linux-privilege-escalation` / `windows-*` / `active-directory-*` / `ntlm-relay-*` — 內部 pentest
- `kernel-exploitation` / `browser-exploitation-v8` / `heap-exploitation` / `stack-overflow-and-rop` — CTF 不付錢
- `smart-contract-vulnerabilities` / `defi-attack-patterns` — web3 不同 program

**audit 全 fail** 自動 skip:
- `ssti-server-side-template-injection` / `cmdi-command-injection` / `xxe-xml-external-entity` / `dangling-markup-injection`

---

## 從這份文件衍生的 KB 連結

- [[Reference Card - Promotion Ladder]] §1 T4 — 外部 skill 在 ladder 哪一層
- [[LL-144-mcp-skill-執行可被-prompt-injection-觸發-system-prompt-外洩|教訓 #144]] — 第三方 skill 安全風險
- [[Playbook - Reusable Workflows]] §0 — 用 yaklang skill 跑 workflow 的注意事項
- CLAUDE.md 「🔌 External Skills」表 — 22 個 yaklang skill 的 trigger 詞

## 升級維護

新版 yaklang/hack-skills 出新 skill 時:
1. 跑 `npx skills add https://github.com/yaklang/hack-skills --skill <new-name>`
2. 確認 audit pass(至少 Gen)
3. 評估是否補本檔的 22 → 23(本 vault 維護者決定)
4. 更新本檔的 Round 表 + 一鍵全裝段
