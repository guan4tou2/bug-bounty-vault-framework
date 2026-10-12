---
type: pattern
title: Pattern - JWT Clock Tolerance Bypass
tags: [pattern, cwe-613, cwe-287, jwt, authentication, token-replay, static-analysis, bb-pattern]
status: active
vuln_class: authentication-bypass
severity_range: P4-P2 (Low standalone; Medium+ when the token drives app behaviour)
seen_in: []
last_updated: 2026-10-12
precedents: clockTolerance option semantics in the Node.js `jsonwebtoken` and `jose` libraries (tolerance is added to every time-claim comparison)
---

# Pattern - JWT Clock Tolerance Bypass

## TL;DR

The JWT verifier is configured with an enormous clock tolerance (`clockTolerance: Number.MAX_VALUE`, `Infinity`, `MAX_SAFE_INTEGER`, or "a few years"). Signature verification (RS256/ES256/HS256) still works, so the code *looks* fully validated — but `exp`, `nbf` and `iat` checks are effectively disabled. Any token that was ever legitimately issued can be replayed forever.

**Signature valid is not the same as token valid.** The signature stops forgery; the tolerance removes the time bound.

## Detection

```bash
# Generic static search over unpacked JS (web bundles, Electron asar, Node services)
grep -rn 'clockTolerance' .
grep -rnE 'MAX_VALUE|MAX_SAFE_INTEGER|Infinity' . | grep -iE 'clock|tolerance|jwt|verify'

# jose
grep -rn 'jwtVerify' . | grep -n 'clockTolerance'

# jsonwebtoken (also watch for a frozen/overridden clockTimestamp)
grep -rnE 'verify\(.*clockTolerance|clockTimestamp' .
```

Equivalents in other stacks: `leeway` / `clock_skew` / `acceptExpiresAt` / `setAllowedClockSkewSeconds` / `ClockSkew` set to an implausibly large value, or `verify_exp=False` / `ignoreExpiration: true`.

## Why it matters

The attack prerequisite is real — you need one legitimately issued token — so standalone this is often Low/Informational. It becomes Medium or higher when:

- The JWT payload controls application behaviour (server URL, feature flags, role, tenant).
- Tokens are distributed over an insecure channel (plain HTTP, config files, email, logs, shared links).
- Tokens outlive the user's entitlement (offboarded employee, revoked partner, rotated role) and there is no server-side revocation.

## Chain amplifiers

| If you also have | Escalation path |
|---|---|
| Payload controls a server/endpoint URL | Replay an expired token → client connects to an attacker-chosen server → credential capture |
| Token delivered over HTTP or a readable file | Capture once → valid forever → persistent redirection or access |
| Token loaded from a file path the client reads | Combine with path traversal / arbitrary file write → plant a token → trigger the behaviour switch |
| No revocation list / session binding | Former user's token remains a working credential |

## Affected libraries

- `jose` (Node.js): `jwtVerify(token, key, { clockTolerance: ... })`
- `jsonwebtoken` (Node.js): `verify(token, key, { clockTolerance: ... })`
- Equivalent leeway / skew parameters in other JWT libraries

## Counter-check (rule out a false positive)

1. Is the tolerance actually huge? A few seconds to ~5 minutes is a normal clock-skew allowance, not a finding.
2. Does the token carry an `exp` claim at all? A token with no `exp` never expires regardless — that is a different (design) issue.
3. Is there an independent server-side check (session table, revocation list, short-lived refresh binding) that rejects old tokens anyway? Test it, do not assume.
4. Does the payload change behaviour? Pure read-only identity with server-side authorisation lowers impact.
5. Live confirmation: replay a token whose `exp` is clearly in the past against an endpoint you are authorised to call, and record the full request/response.

## Filing & severity

- CWE-613 (Insufficient Session Expiration); CWE-287 where the replay grants access the user should no longer have.
- Report the demonstrated replay, not the theoretical maximum (AGENTS.md §5). If you only have the static config, say so and score from static evidence.

## Related

- [[Pattern - Hardcoded Credentials]]
- [[Pattern - Electron Preload Injection Chain]]
- [[Reference Card - Finding Discovery Verification Schema]]
