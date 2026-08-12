---
type: pattern
title: "SaaS Marketplace OAuth — Insecure Defaults (redirect_uri prefix matching)"
tags: [pattern, oauth, oauth-redirect-uri-validation, marketplace, ato, bb-pattern]
status: active
vuln_class: oauth-redirect-uri-validation
last_updated: "2026-06-03"
---

# Pattern — SaaS Marketplace OAuth: Insecure Defaults (redirect_uri prefix matching)

> SaaS marketplaces (video-conferencing platforms, team-chat platforms, DevOps platforms, etc.) let third-party developers register OAuth apps — security-relevant toggles frequently default to **OFF**, meaning a large share of production apps end up running with weak validation. The attack surface here is the **platform default**, not an individual app's misconfiguration.

## Why This Is a Real Vulnerability, Not Noise

The OAuth 2.0 `redirect_uri` is the delivery destination for the authorization code. If validation uses **prefix matching** instead of exact matching, an attacker only needs to find one legitimate OAuth app that accepts an arbitrary suffix, then redirect the code to an attacker-controlled endpoint — leading to account takeover (ATO).

The core issue isn't a single app's misconfiguration — it's the **platform default**. As long as a security toggle like "Strict Mode" defaults to OFF, every new app created on the marketplace inherits the same weak attack surface.

**Stop-loss rule**: if fully verifying the exploit requires obtaining a third-party app's OAuth token, but you don't have both a developer account and a separate victim account, mark the finding `verification_level: B` (static / partial dynamic) — do not write up the end-to-end exploit as fully demonstrated.

---

## Case Study: General-Purpose OAuth App Platform (anonymized)

**Finding context**: a major SaaS collaboration platform's marketplace, which lets any developer register a general-purpose OAuth app.
**Severity**: P3 Medium (`verification_level: A`, verified evidence: live)

### Observed default settings (verified)

| Setting | Default | Secure value | Impact |
|---|---|---|---|
| Strict Mode for redirect URLs | **OFF** | ON | Prefix matching instead of exact matching |
| Subdomain check | **OFF** | ON | Any subdomain accepted |
| `state` parameter | **optional** | required | No CSRF protection |

**Verification method**: created a general-purpose OAuth app on the platform, confirmed the defaults via JS checkbox state inspection in the app-creation UI, and cross-checked against the platform's own developer documentation describing what Strict Mode is supposed to protect against.

### Verified bypass vectors

Registered `redirect_uri`: `https://example.com/callback`

| Vector | Test URI | Result |
|---|---|---|
| Baseline (exact match) | `https://example.com/callback` | PASS |
| **Path suffix** | `https://example.com/callback/evil` | **BYPASS** |
| **String prefix (no path separator)** | `https://example.com/callbackevil` | **BYPASS** |
| **Query injection** | `https://example.com/callback?next=evil.com` | **BYPASS** |
| **Subdomain (check OFF)** | `https://evil.example.com/callback` | **BYPASS** |
| Path traversal | `https://example.com/callback/../evil` | BLOCKED (normalized) |
| Host confusion | `https://example.com.evil.com/callback` | BLOCKED (root domain differs) |
| Different prefix | `https://example.com/evil` | BLOCKED |

All bypass results were tested directly against the platform's `/oauth/authorize` endpoint; an HTTP 302 to the authorization page indicates validation passed. The BLOCKED results are recorded too, showing the platform does have some boundary protection (path traversal is normalized).

---

## Summary

The SaaS marketplace OAuth **insecure defaults** pattern:

1. A developer creates an OAuth app on the marketplace and leaves the defaults untouched (never manually enables Strict Mode)
2. The platform validates `redirect_uri` using prefix matching
3. An attacker crafts a `redirect_uri` that satisfies the prefix (path addition / query injection / subdomain)
4. The victim clicks a crafted authorization URL and grants access; the code is redirected to the attacker's endpoint
5. The attacker exchanges the code for an access token → accesses the victim's data on the platform (meetings, recordings, contacts, files, etc., depending on the platform)

**Why this scales**: a platform-level insecure default affects every app developer on the marketplace at once; compared to finding "one app with a CSRF bug," testing the platform-level default has a much higher ROI, and the report comes with a directly actionable fix recommendation for the platform (change the default).

---

## Detection Signals

| Signal | Tool | Meaning |
|---|---|---|
| Marketplace docs mention a "Strict Mode" / "Subdomain Check" style toggle | Read dev docs | The security feature is optional, not enforced by default |
| Developer docs say something like "By default, all subdomain URLs..." | Read dev docs | Subdomains are allowed by default |
| The OAuth app creation UI has checkbox-style security options | Browser DevTools | Inspect default checked/unchecked state |
| `redirect_uri=registered_uri/extra_path` → authorization page loads normally | curl / browser | Confirms prefix matching |
| `redirect_uri=sub.registered_domain/path` → authorization page loads normally | curl / browser | Confirms subdomain check is disabled |
| Authorization URL with no `state` parameter still succeeds | curl | `state` is not enforced → possible OAuth CSRF |
| OAuth tokens can be obtained before any app-review process completes | docs / testing | Production-equivalent apps are testable pre-review |

---

## Test Methodology

### Step 0: Confirm the platform uses optional security settings

```bash
# Read the marketplace developer documentation, searching for:
# "Strict Mode", "exact match", "subdomain", "state parameter required"
# Goal: confirm whether these are opt-in toggles or enforced by default
```

### Step 1: Create a test OAuth app (leave defaults untouched)

```
1. Create a general-purpose OAuth app on the marketplace
2. Set redirect_uri = https://example.com/callback (or a domain you control)
3. Do not modify any security toggles (leave defaults as-is)
4. Record the client_id and the registered redirect_uri
```

### Step 2: Test redirect_uri bypasses

```bash
CLIENT_ID="your_client_id"
BASE_REDIRECT="https%3A%2F%2Fexample.com%2Fcallback"
AUTH_EP="https://<marketplace-domain>/oauth/authorize"

# Test 1: exact match (baseline — must pass)
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${BASE_REDIRECT}" | head -3

# Test 2: path suffix (prefix-matching bypass)
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${BASE_REDIRECT}%2Fevil" | head -3

# Test 3: string prefix (no path separator)
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=https%3A%2F%2Fexample.com%2Fcallbackevil" | head -3

# Test 4: query injection (open-redirect chain precondition)
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${BASE_REDIRECT}%3Fnext%3Dhttps%3A%2F%2Fevil.com" | head -3

# Test 5: subdomain (bypasses "Subdomain Check OFF")
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=https%3A%2F%2Fevil.example.com%2Fcallback" | head -3

# Interpretation:
# HTTP 302 to the authorization page (or 200 with the page loaded) = validation passed (bypass)
# HTTP 400 "redirect_uri does not match" = validation is enforced
```

### Step 3: Test whether `state` is enforced

```bash
# with state
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${BASE_REDIRECT}&state=csrf_token_123" | head -3

# without state
curl -si "${AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${BASE_REDIRECT}" | head -3

# if both return 302 → state is optional → possible OAuth CSRF
```

### Step 4: Assess exposure on existing production apps

```bash
# Search the marketplace's public app listing for apps with a large install base
# Check their callback domain for:
# 1. An open redirect (/redirect?url=, /next=, /return=)
# 2. A takeover-able subdomain (dangling CNAME)
# This is the bridging evidence for "insecure-default -> production app impact"

# Note: when testing production apps, stay GET-first — do not force an authorization
```

---

## Common Bypass Techniques

| Technique | Test sample | Precondition | Verified in case study |
|---|---|---|---|
| Path suffix | `registered/evil` | Strict Mode OFF | Yes |
| String prefix (no separator) | `registeredEvil` | Strict Mode OFF + no boundary check | Yes |
| Query injection | `registered?next=evil.com` | Strict Mode OFF | Yes |
| Subdomain | `evil.registered-domain.com/path` | Subdomain Check OFF | Yes |
| Path traversal | `registered/../../evil` | Strict Mode OFF + no normalization | Blocked (platform normalizes) |
| Host confusion | `registered-domain.evil.com/path` | Strict Mode OFF + root domain unchecked | Blocked (platform validates root domain) |
| Fragment trick | `registered#@evil.com` | Some parsers treat everything after # as an anchor | Untested |
| Port confusion | `registered-domain.com:8080/path` | Only host+path compared, port ignored | Untested |
| Open-redirect chain | `registered-domain.com/redirect?url=evil.com` | The registered app itself has an open redirect | Theoretical (requires the target app to have an open redirect) |

---

## Attack Chains

### Chain A: Query Injection + Open Redirect → Code Theft

```
Attacker:
  1. Finds a marketplace OAuth app registered with redirect_uri = https://app.example.com/callback
  2. Confirms https://app.example.com/callback?next=https://evil.com is accepted (Strict Mode OFF)
  3. Confirms app.example.com's /callback endpoint redirects when it receives a "next" parameter

Victim:
  4. Is lured into clicking a crafted authorization URL (phishing email, social post)
  5. Logs into the platform and authorizes the app
  6. Platform redirects to https://app.example.com/callback?next=https://evil.com&code=AUTH_CODE
  7. The app's open redirect forwards the victim (with the code still in the URL) to evil.com
  8. evil.com captures the code via the Referer header

Attacker:
  9. Exchanges the code for an access token → accesses the victim's data on the platform
```

**Precondition**: the registered app's domain must have an open redirect (requires additional verification — this is the second condition in a theoretical chain).

### Chain B: Subdomain Takeover + Code Theft

```
Attacker:
  1. Finds a marketplace app registered with redirect_uri = https://sub.example.com/callback
  2. Confirms sub.example.com is a dangling CNAME (subdomain takeover is feasible)
  3. Takes over sub.example.com, deploys a server to capture the code

Victim:
  4. Is lured into clicking a crafted authorization URL
  5. After authorizing, the platform redirects to https://sub.example.com/callback?code=AUTH_CODE
  6. The attacker's server logs the code

Attacker:
  7. Exchanges the code for an access token
```

**Precondition**: requires a successful subdomain takeover (a moderate-difficulty precondition).

### Chain C: OAuth CSRF (missing state)

```
Attacker:
  1. Starts an OAuth flow under their own account, obtains an authorization URL (without state)
  2. Lures the victim — while logged into the platform — into visiting that URL

Victim:
  3. Sees the authorization page directly (already logged in), clicks to authorize

Effect:
  The attacker's third-party app is granted access to the victim's account
  → the attacker can continuously read the victim's data on the platform (no further interaction needed)
```

**Note**: this chain does not require a redirect_uri bypass — `state` being optional is sufficient on its own.

---

## Severity Guide

| Condition | Severity | Notes |
|---|---|---|
| redirect_uri bypass → code lands directly on the attacker's server (end-to-end verified) | P1 Critical | Direct ATO, no secondary condition needed |
| Subdomain takeover chain (both takeover and redirect_uri bypass verified) | P1-P2 | Two verified conditions chained together |
| Query-injection bypass + open-redirect chain (both conditions verified) | P2 High | Full code-theft path demonstrated |
| Platform-level insecure default (Strict Mode OFF by default, bypass verified) | **P3 Medium** | The case study's actual severity; redirect_uri bypass is verified, but end-to-end code theft requires a production app with an open redirect or a takeover-able subdomain |
| `state` optional alone (no redirect_uri bypass) | P3-P4 | OAuth CSRF; requires social engineering + a victim click |
| redirect_uri prefix matching (URL-layer test passes, but only path addition demonstrated) | P3 Medium | Matches the case study above |
| Static analysis confirms the default is OFF, but no dynamic test performed | P4 Low / `verification_level: B` | Note the blocker explicitly |

**Anti-overclaim reminder**:

The case study's actual severity is P3 Medium, not P1 Critical, because:

1. **Verified (live evidence)**: Strict Mode defaults to OFF; redirect_uri prefix matching allows path addition / query injection / string-prefix / subdomain bypasses
2. **Theoretical (not end-to-end verified)**: that a specific production app's developer relies on these insecure defaults (most developers likely don't change them, but this is an inference); that the app's callback endpoint has an open redirect or a takeover-able subdomain

The report should read: "The platform defaults Strict Mode to OFF (verified); redirect_uri prefix matching allows path addition and query injection bypass (verified); full authorization-code theft requires a secondary condition such as an open redirect on the app's domain or a subdomain takeover (theoretical, not verified in this scope)." Do not write "an attacker can steal authorization codes from any OAuth app on the platform."

---

## Related Notes

- [[Pattern - Custom OIDC Redirect URI Validation]] — the redirect_uri bypass pattern for self-implemented OIDC servers; the distinction from this pattern is that this one is a **marketplace platform-level insecure default**, while the OIDC pattern is a **custom OIDC server implementation bug**
- Pre-submission checklist: the "three-question filter" before submitting a report

### Other SaaS marketplace OAuth platforms worth testing

| Platform type | OAuth app entry point (example) | Similar setting name |
|---|---|---|
| Video conferencing marketplace | developer app-creation console | Strict Mode / Subdomain Check |
| Team chat marketplace | app management console | Redirect URL exact matching |
| DevOps/wiki marketplace | developer console | Callback URL matching |
| Code hosting platform apps | app settings | Callback URL / Homepage URL |
| Identity platform (Azure AD-style) | app registration portal | Redirect URI type (Web/SPA/Public) |

**Testing tip**: prioritize platforms where a free account is enough to register an OAuth app; immediately after creating the app, check the default state of every security-toggle checkbox and compare it against what the documentation says developers are supposed to enable.

## Additional Notes

- **Impact of Strict Mode defaulting to OFF**: if a platform's Strict Mode defaults to OFF, every marketplace app inherits permissive redirect_uri validation at install time — one platform-level setting affects every app.
- **Verification step**: test the OAuth flow of any marketplace app by sending an invalid redirect_uri and checking whether it's accepted.
