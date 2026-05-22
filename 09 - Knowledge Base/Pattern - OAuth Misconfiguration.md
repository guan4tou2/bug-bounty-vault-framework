---
fileClass: KB
type: pattern
tags: [pattern, oauth, redirect, auth]
added: 2026-01-01
---

# Pattern — OAuth Misconfiguration

## Summary

Weaknesses in OAuth 2.0 implementations that allow authorization code theft, token leakage, or CSRF attacks against the consent flow.

## Detection Signals

- `redirect_uri` accepts path additions, query parameters, or subdomain variations
- `state` parameter is optional or not validated
- Authorization codes are long-lived or reusable
- Token endpoint accepts `redirect_uri` different from authorization request
- Implicit flow used where authorization code flow is appropriate

## Test Vectors (redirect_uri)

Given registered redirect: `https://app.example.com/callback`

| Vector | Test URI | Expected |
|--------|----------|----------|
| Exact match (baseline) | `https://app.example.com/callback` | PASS |
| Path addition | `https://app.example.com/callback/evil` | Should FAIL |
| Query injection | `https://app.example.com/callback?next=https://evil.com` | Should FAIL |
| No path boundary | `https://app.example.com/callbackevil` | Should FAIL |
| Subdomain | `https://evil.app.example.com/callback` | Should FAIL |
| Path traversal | `https://app.example.com/callback/../evil` | Usually blocked (normalized) |
| Host confusion | `https://app.example.com.evil.com/callback` | Usually blocked |

## Attack Chains

1. **Query injection + open redirect:** `redirect_uri=https://app.com/callback?next=https://evil.com` → auth code leaks via Referer
2. **Subdomain takeover:** dangling CNAME on `sub.app.com` → receive auth codes directly
3. **OAuth CSRF (missing state):** force victim to authorize attacker's app → persistent API access

## Severity Guide

| Condition | Severity |
|-----------|----------|
| redirect_uri bypass + sensitive scopes | P2-P3 |
| Missing state (CSRF) | P3-P4 |
| Token leakage via Referer | P3 |
| Implicit flow where code flow possible | P4 |

## Related

- [[Pattern - CORS Misconfiguration]]
- [[Lessons Learned]]
