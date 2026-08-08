---
type: submission
fileClass: Submission
target: "[[Target - {{name}}]]"
platform: twcert
program: "TWCERT/CC (Taiwan Computer Emergency Response Team / Coordination Center)"
severity: P3
status: ready
risk: medium
findings:
  - "[[Finding - {{name}} - {{vuln}}]]"
reported_date: "{{date}}"
submitted_at: ""
case_id: ""
cve_requested: 1
disclosure_window_days: 90
public_disclosure_date: ""
tags:
  - twcert
  - cve-eligible
parent: "[[Target - {{name}}]]"
---

# Submission: TWCERT — {{name}} {{vuln}}

> **Canonical source: this file. `FORM - TWCERT - {{vuln}}.md` (same directory) is the platform-formatted output.**
> Submission URL: https://www.twcert.org.tw/tw/CustomSite/Application/CVENotify/CVENotifyForm.aspx

## Submission Strategy

> One paragraph: why TWCERT, whether parallel with HITCON, vendor notification strategy.

## Submission Info

| Item | Value |
|---|---|
| Platform | TWCERT/CC |
| Target | {{name}} |
| Org | {{org}} |
| Risk | 🟡 Medium / 🟠 High / 🔴 Critical |
| Status | 🟡 Ready / 🟢 Submitted / ✔ Accepted |

## TWCERT Form Fields (fill when submitting)

| Field | Content |
|---|---|
| Reporter Name | {{reporter_name}} |
| Email | {{email}} |
| Public disclosure | ❌ No |
| Vulnerability source | Self-discovered |
| Discovery date | YYYY-MM-DD |
| Affected product name | {{product}} |
| Affected product version | {{version}} |
| Product developer | {{org}} |
| Product website | {{url}} |

## Report Content

> [!warning] No internal IDs
> TWCERT form **must not** contain internal IDs (e.g., TP-xxx / Advisory A/B/C).
> Use "(1) / (2) / (3)" or "<feature name> vulnerability" instead.

### Report Content (1) — <Feature Name> Vulnerability

**Vulnerability Type:** CWE-XX

**Vulnerability Description:**
(One paragraph: what, where, who can trigger it, what happens)

**Verified Conditions (live):**
1. ...
2. ...

**Specific Conditions to Trigger:**
(Prerequisites / environment / scope)

**Trigger Method:**
```bash
curl ...
```

**Required Privileges:** No authentication / authenticated user / admin

**Confidentiality / Integrity / Availability:** Low/High/None
**CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
**CVSS Score:** N.N <Severity>
**CWE types:** CWE-XX

**Potential Escalation (unverified):**
(Be honest — do not present speculation as confirmed)

**Additional Notes:**
(Supplementary context)

## Affected Scope

| Affected System | URL | Status |
|---|---|---|
| ... | ... | 🔴 |

## Remediation Recommendations

1. ...
2. ...

## Progress Tracker

| Phase | Date | Status | Notes |
|---|---|---|---|
| 1. Discovery | | ⏸ | |
| 2. Verification | | ⏸ | |
| 3. Draft writeup | | ⏸ | workshop path |
| 4. Severity correction | | ⏸ | CVSS / CWE calibration |
| 5. Pre-submit checklist | | ⏸ | see below |
| 6. **Submit** | TBD | 🟡 | TWCERT case ID TBD |
| 7. Triage response | TBD | ⏸ | typically 7-14 days |
| 8. CVE assigned | TBD | ⏸ | per MITRE service/product rule |
| 9. Public disclosure | YYYY-MM-DD | ⏸ | 90-day window |

## Pre-submission Checklist

- [ ] No internal IDs (TP-xxx / Advisory A/B/C)
- [ ] Every PoC curl is directly copy-paste executable
- [ ] CVSS calculated + no exaggeration (align with severity calibration)
- [ ] CWE mapping is correct (avoid auto-high-severity subcategories)
- [ ] No unverified attack chains claimed
- [ ] Screenshots / evidence / logs prepared (redact account names)
- [ ] Checked prior CVEs to confirm no duplicates (NVD + TWCERT existing)
- [ ] Pre-submit OOS confirmation that vulnerability type is not excluded

## Related

- Target: [[Target - {{name}}]]
- Finding: [[Finding - {{name}} - {{vuln}}]]
- Pattern: [[Pattern - ...]]
- Form: [[FORM - TWCERT - {{vuln}}]]
