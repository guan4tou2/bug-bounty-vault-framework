---
name: bb-hitcon-form
description: Use when creating or editing HITCON ZeroDay forms, FORM - HITCON - <ID>.md, ZD submissions, HITCON field formatting, HITCON vulnerability type values, or HITCON screenshot requirements.
---

# Bug Bounty — HITCON ZeroDay Form Guide

> HITCON ZeroDay has a unique format (code-block wrapping, type mapping table, {org} title convention, vulnerability type codes). This skill ensures correct form generation.

## 1. Platform Characteristics

HITCON ZeroDay = **CVD (Coordinated Vulnerability Disclosure)**, not a bug bounty competition.

| Item | Rule |
|---|---|
| Severity | **Any severity can be submitted independently** (no need to accumulate to P1) |
| Duplicate | No penalty (unlike H1) — your report is evaluated independently |
| Anonymous | Optional; title uses `{Organization Name}` convention |
| Screenshots | **HARD BLOCK** — platform requires image upload at submission, FORM without screenshots is unusable |

## 2. Form Fields (in submission order)

| Field | Required | Format |
|---|---|---|
| Title | ✅ | `{Organization Name} One-line vulnerability description` (wrapped in ` ``` `) |
| Organization | ✅ | Legal entity name (wrapped in ` ``` `) |
| Introduction | ✅ | **One line** describing the vulnerability (wrapped in ` ``` `, **no multi-line**) |
| Type | ✅ | From mapping table: `<Chinese (English)>` (**no number prefix**, wrapped in ` ``` `) |
| Risk | ✅ | `嚴重 / 高 / 中 / 低` (wrapped in ` ``` `; section heading uses `## 風險` not `## 風險等級`) |
| Related URLs | ✅ | Full URL, one per line (wrapped in ` ``` `) |
| Description | ✅ | Markdown — this field **renders** Markdown (others are plain text) |
| Remediation | ✅ | One or more paragraphs (wrapped in ` ``` `) |
| Screenshots | ✅ | At least 1, from `01 - Targets/<target>/Screenshots/` |
| Attacker Position | Optional | `本地 / 鄰近網路 / 網路` (Local / Adjacent Network / Network) |

## 3. Code Block Wrapping (mandatory for plain-text fields)

**Plain-text fields** (Title / Organization / Introduction / Type / Risk / Related URLs / Remediation) must be wrapped in ` ``` `.

✅ Correct:
````markdown
## 標題

```
{Acme Corporation} SQL Injection in User API Authentication Endpoint
```

## 介紹

```
User authentication API accepts unsanitized SQL in the username parameter, allowing full database access.
```
````

❌ Wrong (plain text without code blocks — HITCON platform will parse as Markdown):
```markdown
## 標題
{Acme Corporation} SQL Injection in Authentication
```

## 4. Type Field Format

Format: **`<Chinese Name (English Name)>`** — no number prefix.

✅ Correct:
```
存取控制缺陷 (Broken Access Control)
資訊洩漏 (Information Leakage)
注入攻擊 (Injection Attack)
```

❌ Wrong:
```
A01 存取控制缺陷                  ← Added OWASP number
Broken Access Control            ← English only, missing Chinese
0036 - 資訊洩漏                   ← Added HITCON value ID
```

## 5. Attack Chain Submission Order (multi-vulnerability)

If a case has multiple chained vulnerabilities:

1. **Submit sub-vulnerabilities first**, get individual ZD IDs (`ZD-2026-NNNNN`)
2. **Submit chain report after**, referencing sub-vulnerability ZD IDs in the description
3. Chain report type: select "攻擊鏈" (Attack Chain)

## 6. Frontmatter Schema (FORM .md file)

```yaml
---
fileClass: Form
type: submission
platform: HITCON
target: <target-name>           # or "[[Target - <target>]]" (Vault wikilink)
finding_id: "<FindingID>"       # Required — matches Vault Finding filename
title: "<full title>"
status: ready | submitted | accepted | na | dup
severity: P1 | P2 | P3 | P4 | P5
host: <primary affected host>
vuln_type: <type name (no number prefix)>
case_id: "ZD-2026-NNNNN"        # Fill after submission
submitted_date: "YYYY-MM-DD"    # Fill after submission
verified_date: "YYYY-MM-DD"
created: YYYY-MM-DD
needs_screenshots: true | false
artifacts:
  - "<keyword 1>"
  - "<identifier 2>"
---
```

> Note: Use `case_id` field (not the deprecated `zd_number`).

## 7. No Internal IDs in Reports

Platform submissions must **not** contain:
- ❌ Internal tracking IDs (e.g., `XX-001`, `XX-002`)
- ❌ Advisory labels (e.g., Advisory A/B/C)
- ❌ Any internal reference numbers

Use platform case_id (`ZD-2026-NNNNN`) for platform communication; use `finding_id` (`<Target>-NNN`) internally only.

## 8. Pre-Submission 60-Second Checklist

```bash
# 1. Live re-verification (update last_verified)
curl -s <target-url> -H 'Cookie: ...'   # Expected vs actual response

# 2. At least 1 screenshot
ls "01 - Targets/<target>/Screenshots/" | grep "<FindingID>"

# 3. Run HITCON FORM lint (if available)
python3 automation/lint_hitcon_form_types.py

# 4. Verify frontmatter completeness
grep -E "^(finding_id|severity|host|vuln_type|verified_date):" \
  "01 - Targets/<target>/Submissions/Forms/FORM - HITCON - <ID>.md"

# 5. Verify no internal IDs in report body
grep -E "XX-[0-9]+" \
  "01 - Targets/<target>/Submissions/Forms/FORM - HITCON - <ID>.md"
# Expected: 0 matches
```

## 9. CVE Citation

If the FORM references CVE numbers, trigger **bb-cve-citation** skill first.

Default: don't write a "similar CVE" section. If the platform's "Related CVE" field is required:
```
N/A — No verified similar public vulnerability. This is a first public disclosure.
```

## Cross-reference

- AGENTS.md §3e (Finding → Submission → FORM pipeline)
- AGENTS.md §5 (Anti-exaggeration in reports)
- skill bb-cve-citation (for CVE references)
- skill bb-dedup-finding (must pass before submission)
