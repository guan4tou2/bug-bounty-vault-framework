---
type: pattern
title: Pattern - Error-Based SQL Disclosure via Type Confusion
tags: [pattern, cwe-209, sql, type-confusion, error-based, stack-trace, python, bb-pattern]
status: active
category: info-disclosure
last_updated: 2026-06-04
---

# Pattern - Error-Based SQL Disclosure via Type Confusion

> Sending a string value for an integer-typed parameter triggers a type error in the Python DB binding layer, leaking ORM query structure / table / column names / DB version. **This is not SQLi** (it's CWE-209), and it can occur even when prepared statements are used correctly.

## Trigger Condition

Any API endpoint with an integer-typed parameter: `id`, `offset`, `limit`, `page`, `count`.

## Payload

Replace the integer parameter value with a string:

```
?id=abc
?id='
?id=1a
?id=null
```

## Target Response

- A psycopg2 / SQLAlchemy stack trace
- Contains table name, column name, DB version

## Mechanism

Even when injection is impossible (because prepared statements protect the query), type confusion can still trigger a `ValueError` in the Python DB binding layer, leaking the ORM's query structure.

## Quick Confirmation

`?id=abc` returning **500 with a body > 5KB** likely contains a stack trace.

## Distinction from Blind SQLi

- This pattern requires **no injection** — only triggering a type error
- It **does not count as SQLi**; classify it as CWE-209 Information Exposure Through Error Message

## Related

- [[Pattern - SQL Injection]]
- [[Pattern - Laravel Debug Chain]]
