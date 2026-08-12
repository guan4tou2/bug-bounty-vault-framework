---
type: pattern
title: Pattern - reCAPTCHA Bypass + Account Oracle
category: auth
tags: [pattern, recaptcha, account-enumeration, password-reset, cwe-204, cwe-640, chain, bb-pattern]
status: active
last_updated: 2026-06-04
---

# Pattern — reCAPTCHA Bypass + Account Oracle (CWE-204 + CWE-640 Chain)

> Compound pattern: a reCAPTCHA token that is never actually validated server-side (CWE-204 observable response discrepancy) combined with a weak password-recovery flow (CWE-640), chaining into large-scale account enumeration + rate-limit bypass.

## Trigger Condition

When testing a password reset / forgot-password / login endpoint, and you suspect the reCAPTCHA token isn't actually being validated.

## Verification Steps

1. **reCAPTCHA not enforced**: send an **empty** reCAPTCHA token to the reset endpoint and compare the response against a request with a valid token.
   - Identical response → reCAPTCHA is cosmetic (client-side only)
2. **Account oracle**: submit a "known-existing account" vs. a "non-existent account" and observe differences in error message / status code / response timing.

Both conditions holding together = an unrestricted account-enumeration attack surface.

## Impact

- Large-scale account enumeration
- Rate-limit bypass (when reCAPTCHA is the only defense)
- Expanded authentication-bypass attack surface

## Reporting

- Compound CWE (CWE-204 + CWE-640)
- Severity should be bumped at least one level due to the reCAPTCHA bypass

## Exclusions (downgrade conditions)

- If a server-side rate limit remains effective and cannot be bypassed → downgrade to Low.

## Related Patterns

- [[Pattern - Account Enumeration Oracle]]
- [[Pattern - CAPTCHA Coverage Inconsistency Across Subdomains]]
