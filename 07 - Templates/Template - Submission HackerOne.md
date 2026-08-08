---
type: submission
fileClass: Submission
target: "[[Target - {{name}}]]"
platform: hackerone
program: "{{program}}"
program_handle: "{{handle}}"
program_type: bbp
severity: P3
status: ready
risk: medium
findings:
  - "[[Finding - {{name}} - {{vuln}}]]"
reported_date: "{{date}}"
submitted_at: ""
report_id: ""
bounty: ""
duplicate_check_done: false
tags:
  - hackerone
  - bbp
parent: "[[Target - {{name}}]]"
---

# Submission: HackerOne — {{name}} {{vuln}}

> **Canonical source: this file. `FORM - HackerOne - {{vuln}}.md` (same directory) is the platform-formatted output.**
> Submission URL: `https://hackerone.com/{{handle}}`

## Submission Strategy

> Why this submission; scope confirmation; whether to contact program triager first.

## Submission Info

| Item | Value |
|---|---|
| Platform | HackerOne |
| Program | {{program}} |
| Handle | {{handle}} |
| Type | BBP (bounty) / VDP |
| Target | {{name}} |
| Risk | 🟡 P3 / 🟠 P2 / 🔴 P1 |
| Status | 🟡 Ready / 🟢 Submitted / ✔ Resolved |

## HackerOne Form Fields

| Field | Content |
|---|---|
| **Title** | `<vulnerability> on <asset> via <vector>` (max ~70 characters) |
| **Asset** | Select from program scope dropdown |
| **Weakness** | CWE mapping (most precise subcategory) |
| **Severity** | CVSS Calculator or None/Low/Medium/High/Critical |
| **Description** | Markdown |
| **Steps to Reproduce** | Numbered list |
| **PoC** | curl / video / screenshots |
| **Impact** | Verified vs Potential separated |

## Description (Markdown)

```markdown
## Summary
(One paragraph: what vulnerability, scope of impact, why it matters)

## Steps to Reproduce
1. ...
2. ...
3. ...

## Proof of Concept
\`\`\`bash
curl ...
\`\`\`

[Screenshot 1: ...]
[Screenshot 2: ...]
[Video PoC URL]

## Impact

### Verified
- (directly proven by PoC)

### Potential (must state prerequisites)
- (conditional escalation, honestly state prerequisites)

## Suggested Fix
- ...
```

## Severity / CVSS

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
Score: N.N <Severity>
```

> [!warning] Anti-exaggeration rules
> - Every impact claim must correspond to a PoC step
> - Do not write "could potentially" without evidence
> - Source map exposure = P3-P4, do not claim P1
> - CORS misconfig (no prerequisite control) = P3-P4, do not claim P2
> - Spring Boot Actuator /health = P3-P4

## Progress Tracker

| Phase | Date | Status |
|---|---|---|
| 1. Discovery | | ⏸ |
| 2. Verification | | ⏸ |
| 3. Duplicate check (hacktivity search) | | ⏸ |
| 4. Draft writeup | | ⏸ |
| 5. Pre-submit checklist | | ⏸ |
| 6. **Submit** | TBD | 🟡 |
| 7. Triage response | TBD | ⏸ |
| 8. Bounty | TBD | ⏸ |
| 9. Resolved / Disclosed | TBD | ⏸ |

## Pre-submission Checklist

- [ ] **Duplicate check**: searched hacktivity / disclosed reports (high-profile targets have frequent collisions)
- [ ] Asset is in scope (check program scope page)
- [ ] Severity aligned with reality (no exaggeration; reference severity calibration table)
- [ ] CWE uses most precise subcategory (avoid auto-P1 categories)
- [ ] Every PoC curl is copy-paste executable
- [ ] Verified vs Potential separated
- [ ] Screenshots redact sensitive information (employee names / tokens redacted)
- [ ] No unverified attack chains claimed

## Out-of-Scope Self-Check

Cross-reference against program's OOS list (typical OOS types):

- [ ] Not submitting source map / API key alone (unrestricted public use)
- [ ] Not submitting user enum alone
- [ ] Not submitting OTP / login rate limit alone
- [ ] Not submitting CORS on non-sensitive endpoint alone
- [ ] Not submitting Self-XSS / Clickjacking without impact
- [ ] Not submitting missing security headers / cookie flags

## Related

- Target: [[Target - {{name}}]]
- Finding: [[Finding - {{name}} - {{vuln}}]]
- Pattern: [[Pattern - ...]]
- Form: [[FORM - HackerOne - {{vuln}}]]
