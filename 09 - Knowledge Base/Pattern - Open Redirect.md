---
fileClass: KB
type: pattern
tags: [pattern, open-redirect, redirect, oauth, phishing]
added: 2026-01-01
---

# Pattern — Open Redirect

## Summary

The application accepts a user-controlled URL in a redirect parameter and forwards the user to that URL without validating it against an allowlist. Standalone, the impact is limited to phishing. When chained with OAuth flows, the redirect target receives authorization codes or tokens, escalating severity significantly.

## Detection Signals

- Query parameters named `redirect`, `redirect_uri`, `return`, `return_to`, `next`, `url`, `goto`, `target`, `dest`, `destination`, `forward`, `continue`, `callback`
- HTTP 301/302 responses whose `Location` header reflects parameter input
- OAuth `redirect_uri` parameter with loose or absent validation
- JavaScript `window.location` or `document.location` set from URL parameters
- Meta-refresh tags sourcing a URL from user input

## Grep Signatures

```bash
# Common redirect parameter names in source
grep -rn 'redirect\|return_to\|next=\|goto=\|target=\|dest=\|forward=\|callback=' \
  --include='*.js' --include='*.py' --include='*.rb' --include='*.php'

# Unsafe JS redirects that read from URL params
grep -rn 'window\.location\s*=\|document\.location\s*=\|location\.href\s*=' \
  --include='*.js' --include='*.ts'

# redirect_uri in OAuth handler without strict match
grep -rn 'redirect_uri' --include='*.py' --include='*.rb' --include='*.js' --include='*.php' | \
  grep -v 'allowlist\|whitelist\|startswith\|===\|==\s*config'

# Meta-refresh from input
grep -rn 'meta.*refresh\|http-equiv.*refresh' --include='*.html' --include='*.php' --include='*.erb'
```

## Test Methodology

1. Enumerate all redirect-like parameters in login, logout, and OAuth flows using a spider and parameter discovery.
2. Inject an external URL (`https://example.com`) and observe whether the response `Location` header or JS redirect targets it.
3. Apply bypass techniques when direct injection is blocked (see table below).
4. For OAuth flows: inject an external `redirect_uri` and attempt to receive the authorization code or token.
5. Test CRLF injection in redirect parameters by appending `%0d%0a` sequences to inject response headers.
6. Test JavaScript-based redirects by modifying the page source or replaying API responses.
7. Document the full redirect chain; note any intermediate hops that retain token fragments.
8. Assess chaining potential: does the redirect parameter appear in an OAuth `redirect_uri`, SSO, or token-issuing flow?

## Common Bypass Techniques

| Defense | Bypass |
|---------|--------|
| Scheme check (must start with `https://`) | `//evil.com` — scheme-relative URL |
| Domain allowlist (exact match) | `https://example.com.evil.com` — subdomain confusion |
| Domain allowlist (suffix check) | `https://evil.com?host=example.com` or `https://evil.com#example.com` |
| Slash normalization | `https:evil.com` — missing slashes; `\/\/evil.com` |
| Path-only redirect check | `//evil.com/%2f..` — path traversal to escape |
| `@` symbol filter | `https://example.com@evil.com` — `@` makes `evil.com` the effective host |
| SSRF-adjacent | `http://169.254.169.254` — validate if redirect hits internal network |
| CRLF filter | Double-encode: `%250d%250a` |
| Fragment handling | `https://example.com#@evil.com` — fragment may be stripped by some validators |

## Severity Guide

| Scenario | Severity |
|----------|----------|
| Chained to OAuth flow — attacker receives authorization code or access token | P3 |
| Chained to password reset — redirect leaks reset token to attacker | P3 |
| Standalone open redirect enabling targeted phishing (branded domain) | P4 |
| Logout-only redirect with no token involved | P4-P5 |
| Self-redirect / redirect within same origin only | P5 |

> **Chain note:** A standalone open redirect on an OAuth `redirect_uri` parameter is typically P3 because the attacker can steal tokens. Always check for OAuth usage before assigning P4/P5.

## Related

- [[Pattern - OAuth Misconfiguration]]
- [[Pattern - SSRF]]
- [[Lessons Learned]]
- [[Playbook - Recon]]
