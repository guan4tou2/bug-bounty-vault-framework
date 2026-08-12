---
type: pattern
title: Pattern - GraphQL CSRF Multiplex / Parameter Desync
tags: [pattern, cwe-352, graphql, csrf, multiplex, batch-query, gitlab, bb-pattern]
status: active
category: csrf
last_updated: 2026-06-04
---

# Pattern - GraphQL CSRF Multiplex / Parameter Desync

> If a GraphQL endpoint's CSRF token check only inspects the main query parameter, a multiplex/batch query format can bypass it.

## Trigger Condition

Testing the CSRF protection on a GraphQL endpoint.

## Case Study (GitLab)

GitLab's `/api/graphql` endpoint's CSRF token check only inspected the main query parameter — a multiplex query format (`?variables=...&query=...`) bypassed it.

## Test Steps

1. Send a normal mutation → confirm a CSRF token is required
2. Send the same request in multiplex/batch-array format → check whether the token is still enforced

## Other GraphQL CSRF Bypass Vectors

- `Content-Type: application/x-www-form-urlencoded` (doesn't trigger a CORS preflight)
- `GET` with the query as a URL parameter

## Reporting Requirement

You must demonstrate a **state-changing mutation actually executing**, not just that the token check can be bypassed — otherwise triagers will treat it as theoretical.

## Related

- [[Pattern - GraphQL Deep Techniques]]
- [[Pattern - CORS Misconfiguration]]
