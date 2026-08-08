---
type: submission
fileClass: Submission
target: "[[Target - {{name}}]]"
platform: bugcrowd
program: "{{program}}"
program_url: "https://bugcrowd.com/engagements/{{program}}"
severity: P3
status: ready
risk: medium
findings:
  - "[[Finding - {{name}} - {{vuln}}]]"
reported_date: "{{date}}"
submitted_at: ""
submission_id: ""
bounty: ""
vrt_category: ""
duplicate_check_done: false
tags:
  - bugcrowd
parent: "[[Target - {{name}}]]"
---

# Submission: Bugcrowd — {{name}} {{vuln}}

> **Canonical source: this file. `FORM - Bugcrowd - {{vuln}}.md` (same directory) is the platform-formatted output.**
> Submission URL: `https://bugcrowd.com/engagements/{{program}}`

## Submission Strategy

> Why Bugcrowd over other platforms; VRT category selection; potential OOS risk axes.

## Submission Info

| Item | Value |
|---|---|
| Platform | Bugcrowd |
| Program | {{program}} |
| Risk | 🟡 P3 / 🟠 P2 / 🔴 P1 |
| Status | 🟡 Ready / 🟢 Submitted |

## Bugcrowd VRT Category (Important)

Select the most precise subcategory:
- Do not select categories that auto-suggest P1 when the actual severity is P3-P4 (e.g., "Disclosure of Secrets > Publicly Accessible Asset" → P1 auto-suggest → but source map / public client ID is actually P4-P5)
- Get the parent category right: Broken Access Control / Server-Side Misconfig / Server-Side Injection / Sensitive Data Exposure / Cross-Site Scripting

## VRT Severity Alignment

| Vulnerability Type | Reasonable VRT | Common Over-rating |
|---|---|---|
| Unrestricted API key (Maps/Firebase) | P4 Info | ❌ Do not claim P2 |
| Source map with client ID | P3-P4 | ❌ Do not claim P1 |
| CORS misconfig requiring subdomain control | P3-P4 | ❌ Do not claim P2 |
| Spring Boot Actuator /health | P3-P4 | ❌ Do not claim P2 |
| OAuth state prediction (static) | P3 / P2 if PoC'd | ❌ Do not claim P1 |
| IDOR read other user's data | P2-P3 | — |
| IDOR modify/delete other user's data | P1-P2 | — |
| RCE | P1 | — |

> [!info] Severity Note
> If VRT auto-suggests severity > your actual CVSS, you **must** add a severity note at the beginning of the Title or first paragraph of Description: "Note: While VRT category suggests P2, actual CVSS is P4 because <reason>".

## Report Structure (Bugcrowd Preferred Format)

```markdown
## Severity Note (if needed)
VRT auto-suggests P2, actual CVSS is P4 because <reason>.

## Summary
One paragraph: vulnerability / scope / impact.

## Steps to Reproduce
1. ...
2. ...

## Proof of Concept
\`\`\`bash
curl ...
\`\`\`

[Screenshots]
[Video PoC]

## Impact

### Verified
- ...

### Potential (state prerequisites)
- ...

## Suggested Fix
- ...
```

## Progress Tracker

| Phase | Date | Status |
|---|---|---|
| 1. Discovery | | ⏸ |
| 2. Verification | | ⏸ |
| 3. Crowdcontrol search (duplicate) | | ⏸ |
| 4. VRT selection | | ⏸ |
| 5. Draft + severity note | | ⏸ |
| 6. **Submit** | TBD | 🟡 |
| 7. Triage | TBD | ⏸ |
| 8. Bounty | TBD | ⏸ |

## Pre-submission Checklist

- [ ] **Duplicate check**: searched Bugcrowd Crowdcontrol
- [ ] Scope confirmed (including OOS cross-reference)
- [ ] VRT uses most precise subcategory (avoid P1-auto categories)
- [ ] CVSS calculated + Severity Note added (if VRT vs CVSS mismatch)
- [ ] Every PoC curl is copy-paste executable
- [ ] Verified / Potential impact separated
- [ ] Screenshots redact sensitive information
- [ ] No unverified attack chains claimed

## Out-of-Scope Self-Check (Typical Bugcrowd OOS)

- [ ] Not submitting source map alone (with public client ID / Maps key)
- [ ] Not submitting self-XSS / clickjacking without impact
- [ ] Not submitting SPF / DMARC / DKIM issues
- [ ] Not submitting best practices violations
- [ ] Not submitting missing security headers / cookie flags
- [ ] Not submitting user enum / OTP rate limit

## Related

- Target: [[Target - {{name}}]]
- Finding: [[Finding - {{name}} - {{vuln}}]]
- Pattern: [[Pattern - ...]]
- Pattern: [[Pattern - Triage Calibration]] (VRT calibration)
- Form: [[FORM - Bugcrowd - {{vuln}}]]
