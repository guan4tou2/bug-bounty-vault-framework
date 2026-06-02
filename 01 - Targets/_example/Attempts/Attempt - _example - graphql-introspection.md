---
fileClass: Attempt
target: "[[Target - _example]]"
vuln_class: "GraphQL"
title: "GraphQL introspection / field suggestion on /graphql"
attempt_date: "2026-01-02"
attempt_time: "14:45"
hours_spent: 1
result: "not_exploitable"
result_reason: "other"
prerequisite: ""
killed_at: "2026-01-02 15:30"
should_retry_when: "schema changes, or a new GraphQL endpoint appears in scope"
related_recon: ["[[Recon - _example - initial]]"]
---

# Attempt — _example — GraphQL introspection

> Example Attempt (a negative result). Recording dead ends prevents re-testing them next session. See [[Pattern - GraphQL]].

## Hypothesis

`/graphql` might leak the schema via introspection, enabling field discovery and object-level auth testing.

## Action Taken

- Sent a standard `__schema` introspection query → `403`/disabled.
- Tried field-suggestion probing (malformed field names to elicit "Did you mean…") → server returned generic errors, no suggestions.

## Evidence Observed

Introspection disabled and suggestions suppressed; no schema leakage.

## Why It Did Not Become a Finding

No information disclosure and no auth bypass surfaced. This is the documented, expected hardening — not a vulnerability.

## Re-attempt Conditions

Revisit if the schema changes or a new GraphQL endpoint enters scope (introspection is often re-enabled in staging).
