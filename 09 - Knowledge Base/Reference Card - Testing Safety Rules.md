---
type: reference-card
tags:
  - safety
  - scope
  - operations
created: 2026-05-23
---

# Reference Card - Testing Safety Rules

Quick reference for safe testing boundaries during authorized security research.

## GET-first Principle

| Method | Policy |
|--------|--------|
| `GET` / `HEAD` / `OPTIONS` | Execute freely |
| `POST` (read-only query) | Confirm no side effects first |
| `POST` (write) / `PUT` / `PATCH` | Confirm consequences; use isolated runner when risk is non-trivial |
| `DELETE` (not self-created) | **Never execute** |

## Before Any Active Test

1. Confirm the target is in scope (`SCOPE.md` or program page)
2. Confirm the test method is allowed by the program
3. Record the planned action in Operation Log
4. Define a stop condition before starting
5. Use VPS/isolated runner for noisy or risky operations

## Stop Conditions

Stop immediately and run `bb-incident-response` when:

- Target returns sustained 502/503/504 after your action
- Your action and the outage are clearly correlated
- Vendor reports downtime you may have caused
- Any unintended data modification is detected

## Never-Execute List

- Account deletion (unless self-created test account)
- Payment or financial transactions
- Actions affecting other users' data
- Bypassing WAF/firewall/rate limits without explicit program authorization
- Social engineering or phishing

## Runtime Decision

- **Local**: read-only checks, file inspection, report writing, status checks
- **VPS**: scans, fuzzing, payloads, high-rate recon, bbflow hunt/flow
- **Blocked**: unclear scope, unknown write effects, missing Operation Log

## Cross-References

- `bb-scope-safety-check` skill
- `bb-incident-response` skill
- `AGENTS.md §6 Operation Safety`
