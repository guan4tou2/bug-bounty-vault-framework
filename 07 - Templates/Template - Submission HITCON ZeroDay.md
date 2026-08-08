---
type: submission
fileClass: Submission
target: "[[Target - {{name}}]]"
platform: hitcon-zeroday
program: HITCON ZeroDay
finding_id: "{{id}}"
title: "{{title}}"
severity: P3
status: ready
risk: medium
host: "{{host}}"
vuln_type: "{{vuln_type}}"
findings:
  - "[[Finding - {{name}} - {{vuln}}]]"
artifacts:
  - "{{identifier_1}}"
reported_date: "{{date}}"
submitted_at: ""
case_id: ""
disclosure_window_days: 90
public_disclosure_date: ""
hitcon_type: 11
tags:
  - hitcon-zeroday
  - cvd
parent: "[[Target - {{name}}]]"
---

# Submission: HITCON ZeroDay — {{name}} {{vuln}}

> **This file = canonical source of truth for the formal report.**
> `FORM - HITCON - <Finding ID>.md` (same directory) is the platform-formatted version generated from this, for copy-paste submission.
> Submission URL: https://zeroday.hitcon.org/vulnerability/submit

---

## Submission Strategy

> HITCON ZeroDay = CVD (Coordinated Vulnerability Disclosure), primarily serving Taiwan-based vendors.
> Conditions for parallel submission with TWCERT / why HITCON over TWCERT.

---

## Submission Info

| Item | Value |
|---|---|
| Platform | HITCON ZeroDay |
| Target | {{name}} |
| Org | {{org}} |
| Risk | 🟡 Medium / 🟠 High / 🔴 Critical |
| Status | 🟡 Ready / 🟢 Submitted |
| Platform-formatted version | `[[FORM - HITCON - {{vuln}}]]` (in Submissions/ directory) |
| Screenshot location | `01 - Targets/{{name}}/Screenshots/` |

---

## Report Fields (fill in for submission)

> **Formatting rules (enforced in FORM file):**
> - Title / Organization / Introduction / Type / Risk / Related URLs / Remediation → wrap in ` ``` ` code blocks (plain text, no Markdown)
> - Introduction → one sentence, ending with period
> - Description → keep Markdown formatting, do **not** wrap in code block
> - `{}` contains only the organization name; no hostnames / internal IDs outside

## Title

```
{<Official Organization Name>} <Vulnerability Name>
```

## Organization

```
<Official organization legal name>
```

## Introduction

```
<What system has what vulnerability, causing what direct impact.>
```

## Type

```
<Official type name>
```

> **Format enforcement**: Write only the official type name, no number prefix (e.g., `Information Leakage`).
> Number reference table below. Bare numbers (`11`), old format (`11 Information Leakage`), or short names without English parenthetical all need normalization before submission.

## Risk

```
Critical / High / Medium / Low
```

## Related URLs

```
<affected URL 1>
<affected URL 2>
```

---

## Description (Markdown — formal report body)

### Vulnerability Overview

<One paragraph summarizing all findings>

---

### Vulnerability 1: <Name> (CWE-XXX)

**Steps to Reproduce:**

1.
2.
3.

```bash
# Full curl command, reviewer can copy-paste directly
```

**Server Response:**

```
<response excerpt>
```

**Impact:**
-

---

### Attack Chain (if multiple vulnerabilities chain together)

```
Step A → Step B → Step C → Result
```

---

### Evidence

> Screenshots stored at: `01 - Targets/{{name}}/Screenshots/`
> In Obsidian use `![[filename.png]]` to embed; in FORM use `{{IMG#N}}` references.

{{IMG#1}} <screenshot description>

---

## Remediation

```
1. Immediate:
2. Short-term:
```

---

## HITCON Vulnerability Type Reference

| Type | Number |
|---|---|
| SQL Injection | 1 |
| Command Injection | 2 |
| Reflected XSS | 4 |
| Stored XSS | 5 |
| DOM-based XSS | 6 |
| CSRF | 8 |
| LFI | 9 |
| Arbitrary File Upload | 10 |
| **Information Leakage** | **11** |
| Logic Vulnerability | 12 |
| Privilege Escalation | 13 |
| Code Execution | 15 |
| **Known Vulnerable Component** | **18** |
| Other (Web) | 19 |
| **RCE** | **47** |
| Weak Password | 48 |
| Arbitrary File Download | 49 |
| **IDOR** | **50** |
| Access Control Flaw | 51 |
| **SSRF** | **52** |

---

## Progress Tracker

| Phase | Date | Status |
|---|---|---|
| 1. Discovery | | ⏸ |
| 2. Verification | | ⏸ |
| 3. Vault Finding created | | ⏸ |
| 4. Report body (this file) completed | | ⏸ |
| 5. Platform-formatted version generated | | ⏸ |
| 6. Pre-submit checklist | | ⏸ |
| 7. **Submit** | TBD | 🟡 |
| 8. Triage response | TBD | ⏸ |

---

## Pre-submission Checklist

- [ ] Title `{}` contains only organization name, no hostname / internal IDs outside
- [ ] Introduction, type, risk, related URLs, remediation = plain text (no Markdown)
- [ ] Description field = Markdown (can use ## / ** / ` etc.)
- [ ] Every PoC curl is directly copy-paste executable
- [ ] Screenshots <= 10, total size <= 8MB, referenced with `{{IMG#N}}`
- [ ] No internal IDs (e.g., TP-xxx / Advisory A/B/C)
- [ ] Vendor is a Taiwan-based organization
- [ ] No unverified attack chains claimed as proven

---

## Triage Notes

> Triage responses, status change records

-

---

## Related

- Target: [[Target - {{name}}]]
- Finding: [[Finding - {{name}} - {{vuln}}]]
- Pattern: [[Pattern - ...]]
- Form: [[FORM - HITCON - {{vuln}}]]
