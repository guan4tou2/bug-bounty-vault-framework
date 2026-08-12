---
type: pattern
title: "Plaintext Password in Persistent Cookie"
vuln_class: plaintext-password-persistent-cookie
cwe: [CWE-522, CWE-312, CWE-311]
tags: [cookie, plaintext, persistence, remember-me, credential-theft, bb-pattern]
status: active
last_updated: 2026-04-25
---

# Pattern — Plaintext Password in Persistent Cookie

> A "365-day expires" cookie is the strongest red flag. The moment you see it, dump the cookie jar and check whether a password-like field is stored in the clear.

## TL;DR

A web application's "remember me" feature stores the user's password directly in plaintext (or merely Base64-encoded) inside a long-lived cookie (expires: 365 days). Any attacker who can read the cookie — via XSS, local SQLite access, or a network man-in-the-middle — can recover the account password directly, with no hash cracking required.

**Key indicators:**
- Cookie name contains `password`, `pwd`, `login_pwd`, `auth_pwd`, `pass`
- `expires` set to 365 days or longer ("remember me forever")
- Missing `HttpOnly` flag (readable by JS)
- Missing `Secure` flag (transmittable over plaintext HTTP)

## Root-cause Ingredients

### jQuery Cookie (most common on the frontend)

```javascript
// Example source pattern seen across multiple tenant paths of a shared SaaS platform
$.cookie('login_password', plaintext_password, { expires: 365 });
$.cookie('login_id',       username,           { expires: 365 });

// Paths observed: per-tenant branded login paths under a shared multi-tenant app
```

### Native document.cookie

```javascript
// Equivalent native implementation
document.cookie = "user_pwd=" + pwd + "; max-age=31536000; path=/";
document.cookie = "login_password=" + encodeURIComponent(pwd) + "; expires=" +
  new Date(Date.now() + 365*24*60*60*1000).toUTCString();
```

### Typical missing-security-flag mistake

```javascript
// Dangerous: all three flags missing
$.cookie('password', user_pwd, { expires: 365 });

// Correct: only store an opaque session token, never the password
$.cookie('session_token', server_issued_opaque_token, {
  expires: 30,
  secure: true,
  // HttpOnly can only be set by the server via the Set-Cookie header; JS cannot add it
});
```

### Server-side PHP equivalent mistake

```php
// Dangerous
setcookie('login_pass', $_POST['password'], time()+31536000, '/');

// grep pattern: setcookie.*pass | Cookies\.set.*pwd | \$\.cookie.*password
```

## Detection Methodology

### 1. Post-login cookie dump (fastest)

```javascript
// Browser DevTools console, run after logging in
document.cookie.split(';').map(c => c.trim()).filter(c =>
  /pass|pwd|password|auth|login/i.test(c)
);
```

### 2. Browser DevTools — Application tab

1. DevTools → Application → Cookies → select the target domain
2. Field names containing `pwd`, `password`, `login_pwd`, `auth_pwd` → compare the value directly against the password you typed
3. **An `Expires` value of 365+ days is a strong red flag**

### 3. Source code grep

```bash
# JavaScript / jQuery
grep -rn "\$\.cookie.*pass\|Cookies\.set.*pwd\|document\.cookie.*pass" ./src/

# PHP
grep -rn "setcookie.*pass\|setcookie.*pwd\|setcookie.*password" ./

# Python / Flask
grep -rn "set_cookie.*pass\|response\.cookie.*pwd" ./

# Find 365-day expiry configuration
grep -rn "expires.*365\|max-age.*31536000" ./src/ | grep -i "pass\|pwd\|login"
```

### 4. Network traffic analysis (Burp Suite)

```
GET /login HTTP/1.1
Cookie: login_password=MyPlainP@ssw0rd; login_id=user@example.com

# Or the Set-Cookie header of a POST response
Set-Cookie: login_password=MyPlainP@ssw0rd; expires=Sat, 25 Apr 2027 00:00:00 GMT; Path=/
```

## Live Verification SOP

1. **Create a test account** (disposable, to avoid exposing your own real credentials)
2. **Log in with "remember me" checked** (or simply log in — if there's no toggle, it may be enabled by default)
3. **Dump the cookie jar:**

   ```javascript
   // DevTools console
   document.cookie
   // or check Application → Cookies directly
   ```

4. **Compare the cookie value against the login password:** if value === the password you typed → plaintext confirmed
5. **Confirm missing HttpOnly:** if `document.cookie` can read the cookie → HttpOnly is missing
6. **Confirm missing Secure:** capture an HTTP (non-HTTPS) request; if the Cookie header carries the password value → Secure is missing
7. **Verify across multiple tenants** (if you suspect this is systemic):

   ```bash
   # Compare cookie-setting behavior across different tenant paths
   curl -c cookies.txt -b cookies.txt -X POST "https://vendor-app.example.com/tenant-a/login" \
     -d "username=test&password=TestPass123&remember=1"
   grep -i "pass\|pwd" cookies.txt
   ```

## Variants

| Variant | Description | Exploitability | Example |
|---------|-------------|-----------------|---------|
| **A: Plaintext, stored directly** | `$.cookie('login_password', 'MyPass123', {expires:365})` | Immediate ATO | Case ACME-001 |
| **B: Base64-encoded** | `btoa(password)` → cookie value, looks like a hash | Decoded in a second | Case ACME-002 (Base64 variant) |
| **C: MD5/SHA1 hash** | Less common, but MD5 is crackable via rainbow tables | Requires crack time | Same pattern class |
| **D: Plaintext in localStorage** | `localStorage.setItem('pwd', password)` — equally readable via XSS | Immediate via XSS | Same case family (localStorage variant) |
| **E: Plaintext in sessionStorage** | Only valid for the current tab, but still readable via XSS | Immediate via XSS | Less common |

**Base64 decode verification:**

```javascript
// If a cookie value looks like Base64
atob("TXlQbGFpblBhc3N3b3Jk")  // → "MyPlainPassword"
```

## Real-World Examples

| Case | Affected scope | Storage method | Severity | Impact scope |
|------|-----------------|-----------------|----------|---------------|
| **ACME-001** — shared multi-tenant SaaS app | Multiple per-tenant branded login paths on a shared platform | `$.cookie('login_password', plaintext, {expires:365})` | High | Tier-1 customers, tens of thousands of users |
| **ACME-002** — related to the same vendor codebase | A healthcare-sector tenant | Base64 + localStorage | High | Sensitive accounts in a regulated sector |
| HackerOne #689086 | Shopify partner portal | Plaintext in cookie | Medium | Resolved |
| HackerOne #1074947 | A SaaS login flow | Base64 password cookie | Medium | Resolved |

**Why ACME-001 was rated more severely**: the affected platform was a shared multi-tenant B2B SaaS product whose tenants included a national-scale telecom operator, a nationwide retail chain, and a certification/testing body — the impact was a systemic cross-organization issue, not a single-application flaw.

## Defense

### Correct server-side implementation

```python
# Correct: only store a server-issued opaque session token
response.set_cookie(
    'session_id',
    value=generate_secure_token(),   # managed by the server-side session store
    max_age=30*24*3600,              # 30 days (not 365)
    httponly=True,                   # not readable by JS
    secure=True,                     # only sent over HTTPS
    samesite='Strict'                # CSRF protection
)
# Never store a password in a cookie or localStorage
```

### Remediation checklist

1. **Server-side session token**: after successful login, issue only an opaque token; the password never leaves the server
2. **HttpOnly flag**: must be set on all auth cookies to prevent XSS reads
3. **Secure flag**: enforce HTTPS-only transmission
4. **SameSite=Strict**: prevent cookies from being attached to CSRF requests
5. **OAuth refresh tokens**: modern architectures should use refresh tokens instead of password cookies
6. **Never store passwords client-side**: frontend JS must never write a password into any persistent store (cookie / localStorage / sessionStorage / IndexedDB)

## Filing & Severity

### CWE mapping

| CWE | Name | When applicable |
|-----|------|------------------|
| **CWE-522** | Insufficiently Protected Credentials | Primary classification — password not encrypted at rest |
| **CWE-312** | Cleartext Storage of Sensitive Information | Plaintext present in cookie/storage |
| **CWE-311** | Missing Encryption of Sensitive Data | If also transmitted over HTTP (no Secure flag) |
| **CWE-614** | Sensitive Cookie in HTTPS Session Without Secure Attribute | Supplementary — Secure flag missing |

### CVSS assessment

| Condition | Score | Notes |
|-----------|-------|-------|
| Base (requires XSS or local access) | **6.5 M** | AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N |
| If a confirmed XSS exists | **8.1 H** | Chained, upgrades to AV:N/AC:L/PR:N/UI:R |
| Systemic impact across multiple Tier-1 tenants | Raises overall report severity | Quantify the number of affected accounts |

### Honest impact framing

```markdown
## Impact

**Verified impact:**
- After login, the cookie directly exposes the plaintext password ($.cookie / document.cookie readable)
- Missing HttpOnly flag — readable by any XSS
- 365-day expiry — the password remains in the browser indefinitely after each login

**Conditional impact (requires additional conditions):**
- XSS → cookie theft → password recovery → ATO (requires an XSS entry point first)
- Local disk access → browser SQLite cookie database read → mass credential harvesting
  (requires local malware / phishing / AV bypass)
- If the target reuses the password on other services: credential stuffing → cross-service ATO
```

## Attack Chains

```
Chain 1 — Immediate theft via XSS
Same-origin XSS → document.cookie leaks the plaintext password → attacker logs in directly as the victim (ATO)

Chain 2 — Local browser SQLite read
Physical access / malware → read %APPDATA%\Chrome\User Data\Default\Cookies →
decrypt the cookie value directly via SQLite → mass credential harvesting (no network traffic required)

Chain 3 — Plaintext transmission over HTTP (if Secure flag missing)
Network MITM → intercept the HTTP request → Cookie: login_password=xxx visible in the clear → immediate ATO

Chain 4 — Cross-service attack
Password stolen from cookie → password-reuse scan (a majority of users reuse passwords) →
credential stuffing against email / banking / other services → large-scale ATO
```

## Related

- [[Pattern - Hardcoded Credentials]] — same plaintext exposure, but in source code rather than a cookie
- [[Pattern - Coturn Default TURN Credentials]] — another class of default-credential issue
- [[Lessons Learned]] — large vendors have a very high bar for info-disclosure-only reports; must be chained for impact
- [[Tool - Arsenal Index]] — Burp Suite cookie interceptor configuration
