---
type: pattern
title: Pattern - Unauthenticated Cron / Schedule Endpoint Invocation
tags: [cron, scheduler, access-control, cwe-284, dos, business-logic, bb-pattern]
status: active
last_updated: 2026-06-04
category: access-control
---

# Pattern — Unauthenticated Cron / Schedule Endpoint Invocation

> When a spider discovers a scheduler / job-execution endpoint with no auth, an attacker can trigger arbitrary background jobs on demand. Report this as CWE-284 Improper Access Control — **not SSRF**.

## Trigger Conditions

Spider discovers one of the following endpoints:

```
/cron  /scheduler  /jobs/run  /tasks/execute  /queue/process  /_cron
```

## Impact Tiers (by severity)

1. **DoS via resource exhaustion** — trigger heavy compute jobs repeatedly
2. **Business logic abuse** — force a billing cycle, bulk email send, or data export
3. **Security bypass** — trigger a cleanup job that deletes audit logs

## Verification Method (GET-first, do not re-trigger)

1. Send a GET first to confirm the endpoint exists.
2. Check whether the response contains an execution confirmation.
3. If it returns 200 + a job ID, stop there (**do not re-trigger**, to avoid actually flooding the job queue).

## Report Classification

CWE-284 Improper Access Control (not SSRF).

## Exclusions / Escalation

- If the cron endpoint is protected by a secret token (`?token=xxx`), assess whether the token is guessable / hardcoded.
  - Guessable / hardcoded token → still a valid finding.
  - Token is random and never leaked → not a valid finding.

## Related Patterns

- [[Pattern - API Self-Registration Endpoint Without Auth]]
- [[Pattern - Hardcoded Credentials]]
