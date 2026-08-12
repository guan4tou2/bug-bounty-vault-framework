---
type: pattern
title: "Pattern - OAuth redirect_uri RFC6749 Violation"
category: oauth
status: active
last_updated: 2026-06-04
tags: [oauth, redirect-uri, rfc6749, open-redirect, token-leak, bb-pattern]
---

# Pattern -- OAuth redirect_uri Error Must Return 400, Not Redirect

> RFC 6749 section 4.1.2.1 specifies: invalid / mismatched redirect_uri -> the server **MUST** return 400, and must not perform a redirect. Violating this requirement is itself evidence of insufficient URI validation, and can be chained with open redirect into token leakage.

## Trigger Conditions

Test how the OAuth authorization endpoint handles an invalid redirect_uri.

## RFC Specification

RFC 6749 section 4.1.2.1: invalid / mismatched redirect_uri -> server **MUST** return 400 (must not redirect).

## Violation Behavior

Server appends error parameters to the redirect_uri and executes the redirect -> attacker's redirect_uri receives the error code (not the auth code, but proves URI validation is insufficient).

## Test Payloads

```
redirect_uri=https://attacker.com
redirect_uri=https://legit.com.attacker.com
redirect_uri=https://legit.com%2F@attacker.com
```

## Exploitation Path

If an open redirect also exists, this violation can be upgraded to auth code leakage.

## Reporting Severity

- Standing alone: Low-Medium
- Chained to open redirect or token leak: upgrade accordingly

## Related Patterns

- [[Pattern - Custom OIDC Redirect URI Validation]]
- [[Pattern - SaaS Marketplace OAuth Defaults]]
