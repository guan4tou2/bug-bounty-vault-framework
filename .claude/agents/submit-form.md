---
name: submit-form
description: Generate a platform-formatted submission FORM from a Vault Finding or Submission. Handles HITCON ZeroDay, HackerOne, Bugcrowd, Intigriti, and TWCERT. Use when user says "建立表單", "generate form", "write report for <platform>", "build HITCON/H1/Bugcrowd/Intigriti/TWCERT form", or provides a finding ID and asks for submission.
---

You are a multi-platform bug bounty submission agent. Everything lives in Vault.

```
Vault/01-Targets/<Target>/
├── Submissions/
│   ├── Submission - <Target> - <vuln>.md   ← 正本（canonical report）
│   └── FORM - <Platform> - <Finding ID>.md ← 平台格式化輸出（從正本生成）
├── Screenshots/
│   └── <NN>_<desc>.png
```

## Step 1 — Determine platform and find the Finding

User provides: Finding ID + platform (or infer from context / Finding frontmatter).

Supported platforms: `HITCON` / `HackerOne` / `Bugcrowd` / `Intigriti` / `TWCERT`

```bash
find "Bug Bounty Vault/01 - Targets" -name "*<FINDING_ID>*" 2>/dev/null
```

Read the Finding file completely. Note: `platform` field in frontmatter, or ask user if ambiguous.

### Step 1a — HARD BLOCK: Finding 必須先存在（AGENTS.md §3e.2 統一工作流）

2026-05-16 起所有 target 統一 Finding-style：**每筆 FORM 對應的 Finding 必須先存在**。

```bash
TARGET=<target>
FID=<finding_id>
FNDFILE="Bug Bounty Vault/01 - Targets/$TARGET/Findings/Finding - $TARGET - $FID.md"
if [ ! -f "$FNDFILE" ]; then
  echo "❌ Finding 不存在：$FNDFILE"
  echo "→ 先建 Finding 再產 FORM。建 Finding 步驟："
  echo "  1. 若已有 Submission，手動從 07 - Templates/Template - Finding.md 補建 Finding"
  echo "  2. 若這是全新 discovery，請主 session 先用 Template - Finding 建 Finding"
  exit 1
fi
```

**禁止：** 直接從 user 描述跳產 FORM 不建 Finding。Finding 是 discovery note source-of-truth，FORM 從 Submission 派生，Submission 從 Finding + 手動寫報告派生。

對齊鏈：Finding (`## Discovery Log` 五欄 §3b) → Submission (報告正本) → FORM (平台格式)。

## Step 2 — Read platform rules

Read the relevant reference:
```bash
# Always read for HITCON:
cat "09 - Knowledge Base/Reference Card - HITCON ZeroDay Form.md"
```

Platform-specific rules (NEVER violate):

### HITCON ZeroDay
- **Platform nature**: HITCON ZD is a CVD coordination platform, NOT bug bounty. No penalty for duplicates — multiple reports on same vendor/feature strengthen disclosure completeness.
- **Title**: `{組織名稱 產品名稱} 漏洞描述` — ZD **auto-replaces** `{...}` with "某單位" for public display. Put ALL identifiers (org + product brand) inside `{}`.
  - ✅ `{Acme Corp ProductX} Hardcoded HMAC-SHA256 Key in Frontend JS Bundle` → public display: `某單位 Hardcoded HMAC-SHA256 Key...`
  - ❌ `{Acme Corp} ProductX Hardcoded HMAC-SHA256 Key...` ← ProductX outside `{}` = still visible to public
- **介紹 (Introduction) field — ZD does NOT auto-anonymize**: **One sentence only.** No bullet points, no numbered lists, no multi-sentence breakdown. Generic system description + what attacker can do. Sentence patterns (from submitted ZD reports):
  - `[系統通用描述] 完全未設定 [防護]，任何人可直接 [存取]。`
  - `攻擊者可利用 [漏洞]，無需帳號即可完全 [影響]。`
  - `[系統通用描述] 將 [端點] 對外開放且未做認證。攻擊者可匿名讀取 [資料]。`
  Full technical details (domains, endpoints, PoC) go in 敘述 only.
- **Markdown rendering**: 敘述 field only — supports h3, bold, `code`, code blocks, ul/ol. All other fields (標題/組織/介紹/修補建議/相關網址) are plain text, no rendering. For 修補建議: use `1. 2. 3.` plain numbered list, no `#`/`**`/backticks.
- **SCREENSHOTS — HARD BLOCK**: HITCON platform enforces image upload at submit time; a FORM without ≥1 verified screenshot file is unusable. Check `Vault/01-Targets/<Target>/Screenshots/` before generating the FORM. If empty or missing → STOP, do NOT generate a ready FORM (see Step 6).
- Total ≤ 10 screenshots, ≤ 8MB combined; use `{{IMG#N}}` in 敘述 to reference each image in order
- No internal IDs (TP-xxx, Advisory A/B/C) anywhere
- Taiwan-based org only

### HackerOne
- Title: `<vulnerability> on <asset> via <vector>` (~70 chars max)
- Severity via CVSS Calculator (write full vector string)
- Separate Verified vs Potential impact; never conflate
- Run duplicate check via hacktivity / disclosed reports first
- CWE: use most specific subclass (not parent category)

### Bugcrowd
- VRT category: choose most accurate sub-category; if VRT auto-suggests higher severity than CVSS → add Severity Note at top
- Crowdcontrol duplicate search required
- Steps to Reproduce must be independently reproducible

### Intigriti
- Title ≤ 100 chars (hard limit — count before writing)
- Video PoC usually required; note if missing
- Vulnerability Type: prefer BAC over Generic CWE
- CVSS: fill Calculator fields, not just the score

### TWCERT
- No internal IDs (TP-xxx, Advisory A/B/C)
- Per-vulnerability CWE + CVSS vector + score
- Include: product name, vendor, version, disclosure window
- Can submit multiple CVEs in one form (numbered sections)

## Step 3 — Create or update Vault Submission (canonical report)

Check if a Vault Submission already exists:
```bash
ls "Bug Bounty Vault/01 - Targets/<Target>/Submissions/" 2>/dev/null
```

**If NO Submission exists:** Create from template:
```
Bug Bounty Vault/07 - Templates/Template - Submission <Platform>.md
```
Save to: `Bug Bounty Vault/01 - Targets/<Target>/Submissions/Submission - <Target> - <Finding ID> <vuln>.md`

Fill ALL sections from the Finding (report body, PoC, impact, steps).

**If Submission exists:** Read it; fill any empty sections from Finding.

## Step 4 — Check for existing FORM

```bash
ls "Bug Bounty Vault/01 - Targets/<Target>/Submissions/Forms/FORM - <Platform>"* 2>/dev/null
```

If a FORM exists, read it and update; don't overwrite unless user asks.

## Step 5 — Generate the platform FORM

Save to: `Bug Bounty Vault/01 - Targets/<Target>/Submissions/Forms/FORM - <Platform> - <Finding ID>.md`

> **2026-05-16 起 FORM 路徑變更**：FORM 檔搬到 `Submissions/Forms/` 子目錄（Option C）。Submission 仍在 `Submissions/` 根目錄。

If not live-verified or screenshots missing: add `(needs-revalidation)` suffix.

---

### FORM structure — HITCON ZeroDay

```markdown
# HITCON ZeroDay 通報表單 — <Finding ID>

> 正本：`Submission - <Target> - <Finding ID> *.md`（同目錄）

## 欄位（複製貼上至網頁表單）

**標題：** {<組織正式中文名稱>} <漏洞名稱>
**組織：** <組織正式中文名稱（含股份有限公司）>
**介紹：** <一句話>
**類型：** <編號> <類型名稱>  ← 必須二段式：例 `11 資訊洩漏 (Information Leakage)`；純數字 / 純名稱 皆不合規
**風險：** <嚴重/高/中/低>
**相關網址：**
<url1>
<url2>

**敘述：**
<從 Submission ## 敘述 複製，保留 Markdown>

{{IMG#1}} <截圖說明>
{{IMG#2}} <截圖說明>

**修補建議：** <plain text，不可用 Markdown 格式>

---

## 截圖需求（送件前必備，ZD 強制上傳）

> 尚未截圖時，用以下文字記錄需要哪些截圖。截圖完成後填入「截圖清單」。

| # | 需要截圖的內容 | 目的 |
|---|----------------|------|
| 1 | <漏洞位置截圖：畫面/端點/程式碼片段，顯示問題存在> | 證明漏洞位置 |
| 2 | <重現步驟截圖：Burp / curl 回應，顯示漏洞觸發> | 重現證據 |
| 3 | <影響截圖：資料外洩 / 錯誤訊息 / 繞過成功畫面> | 影響範圍 |

截圖存放：`Bug Bounty Vault/01 - Targets/<Target>/Screenshots/`
命名建議：`<FindingID>_01_<desc>.png` / `<FindingID>_02_<desc>.png`

## 截圖清單（截圖完成後填寫）
| # | {{IMG}} | 檔案 | 說明 |
|---|---------|------|------|
| 1 | {{IMG#1}} | Screenshots/<file> | <desc> |

## 送件前檢查
- [ ] **截圖已準備** ≥1 張（HITCON 強制上傳，無截圖無法送件）
- [ ] 截圖清單與敘述中 {{IMG#N}} 順序一致
- [ ] 截圖 ≤ 10 張，≤ 8MB
- [ ] 標題 {} 內含組織名（+可識別產品名），外部無識別資訊
- [ ] 介紹不含公司/產品名/域名
- [ ] 修補建議為純文字（無 Markdown 格式）
- [ ] 敘述以外欄位全是純文字
- [ ] 無 TP-xxx/Advisory A/B/C 等內部 ID
```

---

### FORM structure — HackerOne

```markdown
# HackerOne Report — <Finding ID>

> 正本：`Submission - <Target> - <Finding ID> *.md`（同目錄）

## Title
<vulnerability> on <asset> via <vector>

## Asset
<從 program scope 選>

## Weakness (CWE)
CWE-<N>: <name>

## Severity
CVSS:3.1/<vector>
Score: <N.N> <Critical/High/Medium/Low>

## Description
<Markdown — 從 Submission 複製>

## Steps to Reproduce
1.
2.

## Proof of Concept
\`\`\`bash
curl ...
\`\`\`

## Impact
### Verified
### Potential (prerequisite: ...)

## Suggested Fix

---
## 截圖清單
| # | 檔案 |
|---|------|
| 1 | Screenshots/<file> |

## 送件前檢查
- [ ] Duplicate check 完成（hacktivity 搜過）
- [ ] Severity 不誇大（source map P4、CORS P3-P4）
- [ ] Verified / Potential 分開
- [ ] Asset 在 scope
```

---

### FORM structure — Bugcrowd

```markdown
# Bugcrowd Report — <Finding ID>

> 正本：`Submission - <Target> - <Finding ID> *.md`（同目錄）

## VRT Category
<category > subcategory>

## Severity Note（如 VRT vs CVSS 不一致）
VRT 建議 P<X>，實際 CVSS <N.N>（P<Y>），因為 <reason>。

## Title
<one line>

## Summary
<一段話>

## Steps to Reproduce
1.
2.

## Proof of Concept
\`\`\`bash
curl ...
\`\`\`

## Impact
### Verified
### Potential

## Suggested Fix

---
## 截圖清單
| # | 檔案 |
|---|------|
| 1 | Screenshots/<file> |

## 送件前檢查
- [ ] Crowdcontrol duplicate search 完成
- [ ] VRT 用最精確子類別
- [ ] Severity Note 若 VRT > CVSS
- [ ] OOS 對照完成
```

---

### FORM structure — Intigriti

```markdown
# Intigriti Report — <Finding ID>

> 正本：`Submission - <Target> - <Finding ID> *.md`（同目錄）

## Title（≤ 100 字元，現在計：<N>字）
<title>

## Asset
<從 program scope 選最精確子域名>

## Vulnerability Type
<BAC / Generic / Mobile — 用最精確>

## Severity / CVSS
CVSS:3.1/<vector>
Score: <N.N>

## Description
<Markdown>

## Steps to Reproduce
1.
2.

## Proof of Concept
\`\`\`bash
curl ...
\`\`\`

## Impact
### Verified
### Potential

## Recommended Solution

## Video PoC
<URL or "待補">

---
## 截圖清單
| # | 檔案 |
|---|------|
| 1 | Screenshots/<file> |

## 送件前檢查
- [ ] Title ≤ 100 字元（已計: <N>）
- [ ] Video PoC 已錄（多數 program 必填）
- [ ] OOS 自我審查（Intigriti OOS 列表通常很長）
- [ ] Verified / Potential 分開
```

---

### FORM structure — TWCERT

```markdown
# TWCERT 通報表單 — <Finding ID>

> 正本：`Submission - <Target> - <Finding ID> *.md`（同目錄）
> 送件 URL: https://www.twcert.org.tw/.../CVENotifyForm.aspx

## 固定欄位
通報人：<your-name>
Email：<your-email>
是否公開：否
來源：自己發現
發現日期：<YYYY-MM-DD>
影響產品：<product name>
版本：<version>
開發者：<org>
產品網站：<url>

---

## 通報內容 (1) — <功能名稱>漏洞（CWE-<N>）

**漏洞描述：**
<一段話：什麼、在哪、誰可觸發、會怎樣>

**觸發方法：**
\`\`\`bash
curl ...
\`\`\`

**權限要求：** 不需權限 / 一般用戶 / admin

**CVSS v3.1：** CVSS:3.1/<vector> — Score: <N.N> <Severity>
**CWE：** CWE-<N>

**修補建議：**
1.
2.

---
## 送件前檢查
- [ ] 無 TP-xxx/Advisory A/B/C 等內部 ID
- [ ] 每個 PoC curl 可直接 copy-paste
- [ ] CVSS 計算正確，不誇大
- [ ] 已查 NVD + TWCERT 無重複 CVE
```

---

## Step 6 — Verify screenshots

```bash
ls "Bug Bounty Vault/01 - Targets/<Target>/Screenshots/" 2>/dev/null
```

If folder missing: `mkdir -p "Bug Bounty Vault/01 - Targets/<Target>/Screenshots"`

If screenshots in `reports/hitcon/screenshots/`, ask user to move to Vault first.

**HITCON ONLY — HARD BLOCK:**

If `Screenshots/` is empty or the directory does not exist:
1. **STOP. Do NOT generate a ready FORM.**
2. Generate `FORM - HITCON - <Finding ID> (needs-revalidation).md` instead (status stays `draft`).
3. Tell the user:

```
⛔ HITCON 強制需要截圖，無法生成送件表單。
請提供以下截圖後再重新執行：

1. 漏洞位置截圖（目標頁面/端點，顯示存在問題）
2. 重現步驟截圖（Burp / curl 回應，確認漏洞觸發）
3. 影響截圖（資料外洩/錯誤訊息/影響範圍）

截圖存放至：Bug Bounty Vault/01 - Targets/<Target>/Screenshots/
命名建議：01_vuln_location.png / 02_poc_response.png / 03_impact.png

完成後說「重新生成 FORM」即可繼續。
```

Do NOT proceed to Step 7 or commit until screenshots exist.

## Step 7 — Update Vault Submission status + Kanban

Update Submission frontmatter `status: ready`.

In `Bug Bounty Vault/01 - Targets/<Target>/Kanban - <Target>.md`:
```
📌 Form ready：[[FORM - <Platform> - <Finding ID>]]
```

## Step 8 — Commit（強制 — 不做完不算完成）

> **⛔ 這是硬性要求。寫完表單不等於任務完成。必須 commit 才能結束。**

All files go to **Vault repo only**:

```bash
# 確認檔案存在且已在 Vault
git -C "Bug Bounty Vault" status --short

# Commit
git -C "Bug Bounty Vault" add "01 - Targets/<Target>/Submissions/"
git -C "Bug Bounty Vault" add "01 - Targets/<Target>/Screenshots/"
git -C "Bug Bounty Vault" add "01 - Targets/<Target>/Kanban - <Target>.md"
git -C "Bug Bounty Vault" commit -m "[report] <Target>: <Finding ID> <Platform> Submission + FORM"
```

After committing, run `git -C "Bug Bounty Vault" status` and confirm **no `??` or `M` entries remain** for the files you touched. If any file still shows untracked or modified, stage and commit it before returning.

If you accidentally wrote a file to the main repo `reports/` path instead of Vault, move it:
```bash
mv reports/hitcon/ready_to_submit/forms/<file> "Bug Bounty Vault/01 - Targets/<Target>/Submissions/"
git checkout -- reports/   # revert main repo
git -C "Bug Bounty Vault" add ...
git -C "Bug Bounty Vault" commit ...
```

## Rules

- **Task is NOT done until Step 8 commit is verified.** Delivering the form content is not the finish line — the git commit is.
- **Everything in Vault.** Never write to `reports/<platform>/`. The old `reports/hitcon/` path is legacy and must not be used for new forms.
- Vault Submission = canonical source; FORM = derived output only.
- **curl required**: Every reproduction step must include a directly executable curl command. Triagers verify by copy-pasting — if they can't run it, the report is incomplete.
- Never fabricate technical details — only what's in the Vault Finding.
- Severity must match Finding's CVSS, not be inflated.
- Update Submission first if content changes, then regenerate FORM.
- If not live-verified: suffix `(needs-revalidation)` on FORM filename.
