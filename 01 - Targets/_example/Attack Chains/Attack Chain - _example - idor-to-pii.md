---
type: attack_chain
target: "[[Target - _example]]"
max_cvss: "6.5"
phases: 2
verified_phases: 1
status: "partial"
tags: [idor, pii, enumeration]
---

# Attack Chain: IDOR → bulk PII exposure

> Example Attack Chain note. Shows how individual primitives combine into a higher-impact narrative, with the verified-vs-theoretical boundary kept explicit.

## Phases

| # | Phase | Status | Evidence |
|---|-------|--------|----------|
| 1 | IDOR read of a single cross-account invoice | **verified** | [[Finding - _example - ACME-001]] |
| 2 | Bulk enumeration of the full invoice range | theoretical | not attempted (would require iterating IDs — out of safe scope without authorization) |

## Verified Impact

A single authenticated user can read another user's invoice PII by changing the numeric `id` (phase 1, proven).

## Theoretical Escalation (not claimed as fact)

Because IDs are sequential, the same flaw *could* allow enumerating the entire invoice set. This is **not** demonstrated — bulk enumeration was not performed. Report phase 1 as verified; mention phase 2 only as potential impact.

## Related

- [[Finding - _example - ACME-001]]
- [[Pattern - IDOR]]
