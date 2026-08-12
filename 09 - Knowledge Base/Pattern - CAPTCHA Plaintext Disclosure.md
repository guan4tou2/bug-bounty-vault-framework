---
type: pattern
title: Pattern - CAPTCHA Plaintext Disclosure
tags: [pattern, captcha, authentication-bypass, brute-force, bb-pattern]
status: active
vuln_class: authentication-bypass
last_updated: 2026-06-03
---

# Pattern: CAPTCHA Plaintext Disclosure

> The CAPTCHA answer is sent proactively to the client (plaintext or a weak hash), or the login endpoint doesn't actually validate the CAPTCHA at all — the CAPTCHA mechanism is entirely ineffective, enabling unlimited brute force.

---

## Distinction from "Pattern - CAPTCHA Coverage Inconsistency Across Subdomains"

[[Pattern - CAPTCHA Coverage Inconsistency Across Subdomains]] describes subdomains that **have no CAPTCHA at all** (a coverage gap). This pattern describes CAPTCHA that's **present but leaks its own answer or isn't actually validated** — nominally present, functionally worthless.

---

## Detection Signals

| Signal | Explanation |
|------|------|
| CAPTCHA endpoints (`/getcaptcha`, `/VerifyCodeImage.aspx`, etc.) return JSON | The response includes an extra field alongside the base64 image (`data_code`, `CheckCode`, `answer`, etc.) |
| The returned value corresponds exactly to the CAPTCHA image | Plaintext, or a reversible/brute-forceable hash |
| Login/signup endpoint returns "wrong credentials" rather than "wrong CAPTCHA" (even when no CAPTCHA param is sent) | The server doesn't validate CAPTCHA at all |
| App is built on ASP.NET WebForms / legacy PHP | `CheckCode` / `VerifyCode` fields are common in these stacks |
| Same endpoint exists across multiple environments (production/staging/UAT) | Usually all affected |

---

## Test / Grep Methodology

### Step 1: Identify the CAPTCHA endpoint

```bash
# Intercept the login flow with Burp Suite / ZAP, find the CAPTCHA image request
# Common path patterns:
/getcaptcha
/Common/VerifyCodeImage.aspx
/captcha.php
/api/captcha
/captcha/generate
```

### Step 2: GET the CAPTCHA endpoint directly, check the response structure

```bash
curl -s "https://target.com/getcaptcha" | jq .
# If the response includes data_code / CheckCode / answer / text → direct vulnerability
```

### Step 3: Brute-force a weak hash (MD5 scenario)

```python
import itertools, hashlib, string, requests

resp = requests.get('https://target.com/Common/VerifyCodeImage.aspx?ISDB=true&ISBase64=true')
check_code = resp.json()['CheckCode'].upper()

charset = string.digits + string.ascii_lowercase
for combo in itertools.product(charset, repeat=4):
    candidate = ''.join(combo)
    if hashlib.md5(candidate.encode()).hexdigest().upper() == check_code:
        print(f"CAPTCHA: {candidate.upper()}")
        break
# 4 alphanumeric chars = 36^4 = 1,679,616 combinations; MD5 brute force < 2 seconds
```

### Step 4: Confirm whether the login endpoint enforces CAPTCHA server-side

```bash
# Attempt login with no CAPTCHA parameter at all
curl -s -X POST "https://target.com/Account/AccountHandler.ashx" \
  -d 'action=login&userId=testuser&password=wrongpass'
# If the response is "wrong credentials" (not "wrong CAPTCHA") → server-side validation is missing
```

---

## Variants

| Variant | Case | Severity |
|------|------|--------|
| **Plaintext leak** (`data_code` = the answer) | A CAPTCHA endpoint returning the answer directly alongside the image | P1 |
| **MD5 leak** (`CheckCode = MD5(lowercase)`) | A legacy portal returning an MD5 of the answer | P1 (< 2s brute force) |
| **No server-side validation** (login endpoint skips CAPTCHA entirely) | A legacy account handler that ignores the CAPTCHA field | P1 (more severe — needs no CAPTCHA interaction at all) |
| **Same root cause across multiple environments** (production/staging/UAT all affected) | 5/5 endpoints affected in one case | P1 (impact multiplier) |
| **Other weak hashes** (SHA-1, CRC32) | Theoretically possible | P1 (depends on brute-force speed) |

---

## Severity Guide

| Level | Condition |
|------|------|
| **P1 (Critical)** | CAPTCHA answer leaks in plaintext or via a weak hash, and the protected endpoint is login/password-reset/OTP |
| **P1 (Critical)** | The login endpoint has no server-side CAPTCHA validation at all (the most direct bypass) |
| **P2 (High)** | Only affects a low-risk endpoint (e.g. search, comments) — no direct account takeover |
| **P3 (Medium)** | The CAPTCHA bypass requires an already-authenticated state to trigger |
| **Escalation path** | Chained with account enumeration ([[Pattern - Account Enumeration Oracle]]) → full brute-force account-takeover chain |

### CVSS Reference

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1 Critical**

---

## Case Studies

### Case A — CAPTCHA Plaintext Leak (live)

- Endpoint: `GET https://api.target.example/getcaptcha`
- Response: `{"data_base":"data:image/png;base64,...","data_code":"EAjyCGhm8t60T62Gy7Xg"}`
- `data_code` is the correct CAPTCHA answer — each GET returns a fresh image/answer pair
- All 5 deployed environments were affected (production/staging/UAT/alias domains)
- Chained with an account-enumeration finding and a permanent-deactivation DoS finding → full enterprise-account ATO chain

### Case B — Legacy Portal MD5 Leak + No Server-Side Validation (live)

- Endpoint 1: `/Common/VerifyCodeImage.aspx?ISDB=true&ISBase64=true` returns `CheckCode = MD5(lowercase CAPTCHA)`
- CAPTCHA "KDV7" → `MD5("kdv7") = 41F97A0C2831403F22D9D93EC5E7C4A0`, brute-forced in < 2 seconds
- Endpoint 2: `/Account/AccountHandler.ashx` login endpoint **doesn't validate CAPTCHA at all** (more severe)
- Chained with a separate SMS API credential leak → control over thousands of SMS credits

---

## Exploitation Chain Potential

```
CAPTCHA bypass
  └─→ Account enumeration ([[Pattern - Account Enumeration Oracle]])
        └─→ Unrestricted password brute force
              └─→ ATO → data theft / account abuse
```

---

## Cross-Reference

- [[Pattern - CAPTCHA Coverage Inconsistency Across Subdomains]] — a coverage gap (different issue)
- [[Pattern - Account Enumeration Oracle]] — a common chaining path

## Session-Mined Additions

- **Double-layer bypass**: (1) the API returns `MD5(answer)` rather than plaintext → crackable via rainbow table or brute force since the answer is usually a 4-6 digit number with a tiny keyspace; (2) the server doesn't validate the CAPTCHA value at all → simply omit it. When both layers coexist, severity is higher.
