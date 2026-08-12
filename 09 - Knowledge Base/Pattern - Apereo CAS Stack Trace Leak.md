---
type: pattern
title: Pattern - Apereo CAS Stack Trace Leak
tags: [pattern, apereo-cas, spring-webflow, stack-trace, cwe-209, info-disclosure, bb-pattern]
status: active
category: info-disclosure
last_updated: 2026-06-04
---

# Pattern — Apereo CAS Flow Execution Key Missing Validation

> If Apereo CAS doesn't validate the format of its `execution` parameter, submitting a malformed value can trigger a Spring WebFlow exception whose stack trace leaks CAS/Spring version, server paths, and possibly database configuration (CWE-209).

## Trigger Conditions

An Apereo CAS deployment is present (a `/cas/login` page is reachable).

## Trigger

Submit a malformed value (non-base64, containing special characters) for the `execution` parameter on `/cas/login`.

## Expected Result

| State | Behavior |
|------|------|
| Misconfigured | Spring WebFlow throws an exception → stack trace → leaks CAS version, Spring version, server paths, and possibly DB config |
| Correctly configured | A 400 error page with no stack trace |

## Test Payload

```
?execution=INVALID_KEY_FORMAT&_eventId=submit
```

## Reporting

Classify as CWE-209 Information Exposure Through Error Message.

## Related Patterns

- [[Pattern - Blind SQL Injection]]
