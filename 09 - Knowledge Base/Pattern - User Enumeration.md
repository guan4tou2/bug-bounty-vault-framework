---
type: pattern
title: Pattern - User Enumeration
vuln_class: user-enumeration
tags: [bb-pattern]
status: active
last_updated: 2026-05-22
---

# Pattern: User Enumeration (Account Enumeration)

> Reported alone, user enumeration is P5 or N/A. It only escalates once chained into an account-takeover (ATO) path.

## Core Identification Methods

| Difference type | Example | Note |
|---------|------|------|
| Different HTTP status codes | 403 vs 423 | e.g. an SSO login endpoint: account doesn't exist → 403, account disabled → 423 |
| Different response body | "Invalid credential" vs "Account disabled" | Text difference is directly comparable |
| Timing difference | existing account responds ~50ms slower | Needs many samples to detect reliably |
| Cross-endpoint confirmation | endpoint A confirms the account exists, endpoint B performs an action | The strongest PoC structure |

## Real-World Case Studies

### Case A — Cross-Brand Email Enumeration (❌ Informative)

- **Endpoint**: `POST /identity/users/validate_email` on a shared identity backend used across several consumer-IoT sub-brands
- **Difference**: existing account → `"status":"unactivated"`; nonexistent account → `"status":"unregistered"`
- **Coverage**: multiple sub-brands sharing the same identity/passport backend
- **Outcome**: ❌ Informative — the program required demonstrated exploitation (credential stuffing / account access / data breach), and cross-brand impact was judged out of the program's scope
- **Lesson**: read the program policy before submitting user enumeration — if it explicitly requires an exploitation demonstration, attach an ATO-chain PoC or don't submit at all

### Case B — Email Enumeration + CORS + No Rate Limiting (P2 submitted)

- **Endpoint**: `POST /v1/api/users/validate`
- **Difference**: nonexistent → 404; existing → 200
- **Aggravating factor**: CORS reflected any-origin + no rate limiting = enumerable at scale
- **Outcome**: submitted as P2 (escalated by chaining CORS + no rate limit)
- **Lesson**: user enumeration alone = P5; chained with CORS + rate-limit gaps it can reach P2

### Case C — SSO HTTP Status Code Difference (FORM ready)

- **Endpoint**: `POST /api/sso/v1/login` on a company-wide SSO backend
- **Difference**: nonexistent account → HTTP 403 `"Invalid credential"`; disabled account → HTTP 423 `"Account disabled!"`
- **Rate limiting**: soft — recovers automatically within seconds, no CAPTCHA; a 1-2 second delay bypasses it, yielding roughly 1,000-2,000 checks/hour/IP
- **Timing side channel**: existing accounts have higher response latency (bcrypt comparison), usable alongside the status-code signal
- **Blast radius**: this SSO backend served the vendor's entire product line
- **CVSS**: 5.3 Medium (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)
- **Lesson**: a 403-vs-423 status split is a machine-readable enumeration oracle; even though 403 covers both "account doesn't exist" and "wrong password," the 423 branch still cleanly enumerates disabled accounts — and if a meaningful fraction of accounts are historically disabled, real-world exploitability is higher than it first appears

### Case D — Tenant Enumeration + Hashed Email Disclosure

- **Endpoint**: a cloud-service API
- **Impact**: a hashed email field is vulnerable to a rainbow-table attack
- **CVSS**: 5.3 Low
- **Outcome**: reported directly via the vendor's security contact email

## Escalation Path

```
User enumeration alone
    → P5 / N/A (for a large vendor)

User enumeration + no rate limiting
    → P4

User enumeration + no rate limiting + reflected any-origin CORS
    → P3 (reflective CORS lets an attacker enumerate without needing their own account)

User enumeration + no rate limiting + login-CSRF / credential-stuffing PoC
    → P2

User enumeration + no CAPTCHA + demonstrated programmatic bulk scanning
    → P2 (requires an automation PoC attached)
```

## Pre-Submission Checklist

- [ ] Does the program policy explicitly exclude user enumeration?
- [ ] Is it attached to a rate-limit / CORS / CAPTCHA gap?
- [ ] Does the PoC demonstrate bulk enumeration (10+ accounts)?
- [ ] How large is the affected user base (global product vs. a small platform)?

## Related

- [[Pattern - Triage Calibration]] — empirically confirmed that email enumeration alone = P5
- [[Resource - Platform Profiles]] — how different platforms treat user enumeration reports
