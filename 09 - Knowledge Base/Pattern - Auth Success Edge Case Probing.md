---
type: pattern
title: Pattern - Auth Success Edge Case Probing
tags: [pattern, auth, proof-of-concept, non-destructive, otp, idor, bb-pattern]
status: active
category: methodology
last_updated: 2026-06-04
---

# Pattern — Proving Auth Success Without Destructive Side Effects

> When a test needs to confirm that a credential or authorization is valid, but the "success" path triggers a side effect like an SMS, email, or payment, use a **boundary/malformed value** to prove auth succeeded without actually triggering the side effect.

## Trigger Conditions

- Need to confirm a credential or session is valid.
- But a successful operation has a destructive side effect (sending an SMS, sending an email, charging a payment, writing to the DB).

## Technique

Substitute a boundary or malformed parameter value in place of a valid one:
- A malformed phone number
- An OTP that's too short
- A field value outside the expected range

## Interpreting the Response

| Response | Conclusion |
|------|------|
| `phone format invalid` / `OTP too short` (a validation error, not 401/403) | The server validates auth **before** validating the parameter → auth gate already passed |
| `invalid credentials` / 401 / 403 | Auth failed |

Look specifically for: **a validation error that occurs after auth succeeds.**

## Applicable Scenarios

- OTP brute-force proof-of-concept
- SMS-bomb PoC (proving reachability without actually flooding)
- Payment-flow IDOR

## Caution (Anti-Overclaiming)

- This technique **only proves auth succeeded** — it does not prove the full attack chain.
- The report must explicitly state: "having proven auth succeeds, this theoretically allows..." — never present it as an already-achieved fact.
