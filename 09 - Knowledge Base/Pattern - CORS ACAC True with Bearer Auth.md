---
type: pattern
title: Pattern - CORS ACAC True with Bearer Auth
tags: [pattern, cors, allow-credentials, bearer-jwt, localstorage, misconfiguration, csrf-disambiguation, downgrade, bb-pattern]
status: active
last_updated: 2026-05-13
---

# Pattern — CORS ACAC True with Bearer Auth (misconfigured but not exploitable)

## Core Concept

[[Pattern - CORS Misconfiguration]] treats "ACAO reflects arbitrary origin + ACAC:true" as a critical CSRF risk. **But that conclusion only holds when auth is cookie-based.**

When the service instead uses **Bearer JWT (localStorage)** as its auth mechanism:
- `attacker.com` can indeed call the API cross-origin via the reflected CORS ACAO
- **but the browser's same-origin policy blocks attacker JS from reading the victim's localStorage**
- the attacker has no way to obtain the JWT → the cross-origin request carries no Authorization header → the backend returns 401
- → **ACAC:true is effectively decorative in this setup — there is no CSRF exploitability**

This distinction matters a lot:
- Reporting it as a critical CSRF gets auto-N/A'd by triage (no working PoC)
- Not reporting it at all wastes a real finding (the misconfiguration genuinely exists, and if auth ever reverts to cookies it instantly becomes exploitable)
- The correct approach: report it as a **misconfiguration (Low severity)**, note that the current auth mechanism is Bearer JWT, and ask the vendor to align their CORS policy with their auth mechanism.

## Decision Tree (run this whenever you see reflected ACAO + ACAC:true)

```
1. Confirm reflection:
   curl -sI "$URL" -H "Origin: https://evil.com" | grep -i "access-control"
   → only proceed if you see ACAO: https://evil.com + ACAC: true

2. Confirm the auth mechanism:
   ──────────────────────────────────────────
   ① Does Set-Cookie carry a session?  curl -sI -X POST "$LOGIN_URL" ...
   ② Does localStorage store a JWT?     check the frontend source map or DevTools
   ③ Is Authorization: Bearer present on subsequent API requests?
   ──────────────────────────────────────────

   ┌────────────────────┬──────────────┬──────────────────────┐
   │ Cookie + ACAC:true │ Bearer JWT   │ Both (mixed)         │
   ├────────────────────┼──────────────┼──────────────────────┤
   │ ✅ instant CSRF    │ ⚠️  misconfig│ ✅ CSRF (via the cookie path) │
   │ report as P2/P3     │ report as Low/Info │ same as cookie case  │
   └────────────────────┴──────────────┴──────────────────────┘

3. Additional checks (Bearer case can still carry risk):
   ├ SameSite setting → whether reverting to cookies would have extra mitigation
   ├ Are there sensitive endpoints still using cookie auth (mixed auth)?
   └ Is there an OPTIONS preflight while the actual request qualifies as a simple request?
```

## Real-World Example

### API with Bearer-only Auth

**Endpoint**: `https://api.example.com/api/login`

```bash
# Trigger ACAC:true
curl -si -X OPTIONS "$URL" -H "Origin: https://evil.example.com" \
  -H "Access-Control-Request-Method: POST"

# Response:
# access-control-allow-origin: https://evil.example.com
# access-control-allow-credentials: true
# access-control-allow-headers: *
# access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
```

**But**:
- The source map showed `localStorage.setItem('token', ...)` plus an Axios interceptor adding `Authorization: Bearer ${token}`
- `curl -sI "$URL"` returned no `Set-Cookie`
- All subsequent API calls used the Bearer header

→ **Downgraded to Low** (misconfig but not CSRF-exploitable).

### Contrast: A Sibling Subdomain with Cookie Auth

```bash
curl -sI "https://im.example.com/"
# Set-Cookie: sess=.example.com; Domain=.example.com  ← cookie-based mechanism
```

Even though `/api/users` appears to also use Bearer, the `sess` cookie is a domain-wide stickiness cookie that may influence load-balancer routing and thus auth state; **and SameSite wasn't explicitly set.**

→ This is a **mixed auth** case — CSRF exploitability must be evaluated case by case.

## Why the Distinction Matters (Submission Practice)

**From the triager's perspective**:
- Seeing "CORS ACAC:true + reflected ACAO" naturally suggests CSRF
- If the report claims "instant CSRF" but the attack chain can't actually be PoC'd → automatic N/A
- If the report says "misconfig (Low)" and explains the Bearer-auth mitigation → the triager sees you did your homework, which earns acknowledgment and occasionally a Low bounty

**Three things to include in the submission**:
1. Confirm ACAC:true genuinely reflects (curl evidence)
2. Explain the current auth mechanism (Bearer JWT, no cookie session)
3. Explain the risk (**reverting to cookies would instantly become CSRF**; this is currently a defense-in-depth failure)

## Severity Tiers

| Scenario | Severity |
|------|----------|
| ACAC:true + cookie auth + SameSite=None | **P2 High** (instant CSRF) |
| ACAC:true + cookie auth + SameSite=Lax/Strict | P3 Medium (partially mitigated) |
| ACAC:true + Bearer JWT (localStorage) only | **P5 Info / P4 Low** (misconfig only) |
| ACAC:true + mixed auth (partly cookie, partly Bearer) | **P3 Medium** (case-by-case) |
| ACAC:true but ACAO doesn't reflect (fixed trusted origin) | Not a vulnerability |

## Non-Vulnerable Cases

| Scenario | Why it doesn't count |
|------|------------|
| ACAO fixed to `*` + ACAC:true | Browsers reject this combination per spec (wildcard can't pair with credentials) — no risk |
| Pure public API (no auth boundary) | No credentials to protect |
| Service Worker / Web Worker (not cross-origin) | CORS doesn't apply |

## Related Patterns

- [[Pattern - CORS Misconfiguration]] — the parent pattern; this file covers its Bearer-auth sub-case
- [[Pattern - CORS Simple Request vs Preflight Bypass]] — a companion pattern for testing the simple-request path

## Lessons Learned

1. **Always verify the auth mechanism before reporting a CORS misconfig.** Otherwise the N/A rate is high.
2. **Check DevTools localStorage / Application → Cookies** — a one-minute check to confirm the auth flow and avoid a bad report.
3. **Reporting "misconfig but not currently exploitable" is a valid finding**, as long as you clearly explain why it isn't currently exploitable and what the future risk is if auth reverts to cookies. Triagers appreciate this kind of forward-looking analysis.
4. **Mixed auth (cookie + Bearer)** is the riskiest configuration: the dev team assumes "we use Bearer, so CSRF isn't a concern," but a legacy endpoint that still reads a cookie remains exploitable.

## Session-Mined Additions

- **Reverse rule (don't submit before confirming cookie auth)**: after confirming CORS ACAC:true, you must confirm whether the session uses a cookie (Set-Cookie header) or Bearer (Authorization header). If only Bearer is used → not exploitable, downgrade to Informative.
- **CF_Authorization SameSite=None inference**: services protected by Cloudflare Access use a `CF_Authorization` cookie that defaults to `SameSite=None` — once CORS ACAC:true is confirmed, exploitability follows without needing a full login test.
