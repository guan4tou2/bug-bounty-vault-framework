---
type: submission
fileClass: Submission
target: "[[Target - {{name}}]]"
platform: intigriti
program: "{{program}}"
program_url: "https://app.intigriti.com/programs/{{program}}"
severity: P3
status: ready
risk: medium
findings:
  - "[[Finding - {{name}} - {{vuln}}]]"
reported_date: "{{date}}"
submitted_at: ""
submission_id: ""
bounty: ""
vulnerability_type: ""
duplicate_check_done: false
tags:
  - intigriti
parent: "[[Target - {{name}}]]"
---

# Submission: Intigriti — {{name}} {{vuln}}

> **Canonical source: this file. `FORM - Intigriti - {{vuln}}.md` (same directory) is the platform-formatted output.**
> Submission URL: `https://app.intigriti.com/researcher/submissions/new`

## Submission Strategy

> Why Intigriti; Ranged Bounty calculation (Severity x Tier); OOS risk.

## Submission Info

| Item | Value |
|---|---|
| Platform | Intigriti |
| Program | {{program}} |
| Bounty Model | Severity x Tier (Ranged) |
| Risk | 🟡 / 🟠 / 🔴 |
| Status | 🟡 Ready / 🟢 Submitted |

## Intigriti Form Field Specifications

| Field | Spec | Notes |
|---|---|---|
| **Title** | **<= 100 characters (hard limit)** | Truncated if exceeded |
| **Asset** | Select from program scope dropdown | Choose most specific subdomain |
| **Vulnerability Type** | CWE search (Generic / Mobile / Broken Access Control groups) | Use BAC over Generic |
| **Severity** | CVSS Calculator or None/Low/Medium/High/Critical/Exceptional | |
| **Endpoint** | Primary vulnerability URL (optional) | |
| **Description** | Markdown, no length limit | |
| **Steps to Reproduce** | Separate field | curl must be copy-paste executable |
| **Impact** | Separate field | Verified / Potential separated |
| **Recommended Solution** | optional | |
| **IP Address** | optional | Testing IP |
| **Video PoC** | **Required by most programs** | YouTube unlisted or mp4 |
| **Attachments** | Screenshots | |

### CVSS Calculator Suggested Values (typical info leak P4)

| Component | Selection |
|---|---|
| AV | Network |
| AC | Low |
| PR | None |
| UI | None |
| S | Unchanged |
| C | Low |
| I | None |
| A | None |
| Score | **5.3 Medium** (C=Low) / 4.3 (conservative) |

### System Detection Warnings

After selecting Vulnerability Type, the system auto-detects OOS:

- "Potential Out-of-scope submission" warning = auto-detection, **not** human judgment, can proceed with submission
- After submission, triager reviews manually

## Report Structure

```markdown
## Summary
One paragraph.

## Steps to Reproduce
1. ...
2. ...

## Proof of Concept
\`\`\`bash
curl ...
\`\`\`

[Video PoC: YouTube unlisted URL]
[Screenshots: 1, 2, 3]

## Impact

### Verified
- ...

### Potential (state prerequisites)
- ...

## Recommended Solution
- ...
```

## Progress Tracker

| Phase | Date | Status |
|---|---|---|
| 1. Discovery | | ⏸ |
| 2. Verification | | ⏸ |
| 3. Title character count (<= 100) | | ⏸ |
| 4. Vulnerability Type selection | | ⏸ |
| 5. CVSS calculation | | ⏸ |
| 6. Video PoC recorded | | ⏸ |
| 7. **Submit** | TBD | 🟡 |
| 8. Triage | TBD | ⏸ |

## Pre-submission Checklist

- [ ] **Title <= 100 characters**
- [ ] Asset selected as most specific (do not select wildcard parent)
- [ ] Vulnerability Type uses BAC over Generic (if applicable)
- [ ] CVSS aligned with suggested values
- [ ] **Video PoC recorded** (required by most programs)
- [ ] Description / Steps / Impact are three separate sections
- [ ] **OOS self-check** (program OOS lists are typically very long)
- [ ] Maps to one of the "reliable program axes":
  - Unauthenticated access to internal operational data (verified, not theoretical)
  - Staging / UAT exposed to public internet with direct data access
  - Source map with live unauth API + business data exposure
- [ ] Production vs staging comparison evidence included (if staging finding)

## Out-of-Scope Self-Check

> Review the detailed OOS list for each specific program

Typical Intigriti OOS:
- Not submitting SPF/DMARC/DKIM / Email spoofing
- Not submitting Username / email enumeration (alone)
- Not submitting Email bombing / OTP rate limit
- Not submitting Subdomain takeover without actual takeover
- Not submitting Banner grabbing / Version disclosure
- Not submitting Tokens leaked to third parties (source map alone)
- Not submitting Best practices violations
- Not submitting Theoretical security issues

## Related

- Target: [[Target - {{name}}]]
- Finding: [[Finding - {{name}} - {{vuln}}]]
- Pattern: [[Pattern - ...]]
- Pattern: [[Pattern - Triage Calibration]]
- Form: [[FORM - Intigriti - {{vuln}}]]
