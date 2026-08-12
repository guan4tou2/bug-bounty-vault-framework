---
type: pattern
title: "Pattern - OIDC Client ID Enumeration"
category: oidc
status: active
last_updated: 2026-06-04
tags: [oidc, client-id, enumeration, oracle, status-code-differential, bb-pattern]
---

# Pattern -- OIDC Provider Client ID Oracle via Status Code Differential

> A custom OIDC provider's authorize endpoint returns different status codes for valid vs invalid client_id, forming a client_id enumeration oracle. Only applicable to custom OIDC implementations (not standard IdPs like Google / Azure).

## Trigger Conditions

Testing a custom OIDC provider (not standard IdPs like Google / Azure).

## Attack Vector

POST `/oauth/authorize` or `/connect/authorize`, sending different client_id values.

## Oracle

| client_id | Response |
|-----------|----------|
| valid | HTTP 200 (redirect to login) |
| invalid | HTTP 400 (error body) |

## Applicability Conditions

- OIDC provider uses sequential / predictable client_id
- UUID4 random client_id -> **cannot enumerate** (exclude)

## Impact

Confirming partner / tenant client_id -> prerequisite for further OAuth flow testing.

## Notes

- This pattern applies to custom OIDC implementations
- Google / Azure have consistent error handling that does not leak information -> not applicable

## Related Patterns

- [[Pattern - Custom OIDC Redirect URI Validation]]
- [[Pattern - Account Enumeration Oracle]]
