---
name: bb-submission-readiness
description: Use when creating, editing, finalizing, or reviewing a Submission or FORM to confirm dedupe, scope, evidence, attack-chain review, platform fit, severity, and hygiene.
---

# Bug Bounty — Submission Readiness

Use this as the final gate before Submission / FORM creation. It does not replace platform-specific skills; it decides whether the report is ready to enter them.

## Trigger

Run before:

- writing a Submission
- generating a FORM
- sending to HITCON / HackerOne / Bugcrowd / Intigriti / TWCERT / other platforms
- asking whether a Finding is ready to report
- changing status to `ready_to_submit`

## Required Gates

| Gate | Requirement |
|---|---|
| Finding exists | Finding is canonical source and has stable ID |
| Dedupe | `bb-dedup-finding` or equivalent precheck completed |
| Scope safety | `bb-scope-safety-check` completed for live verification |
| Attack chain | `bb-attack-chain-review` completed, or explicitly not applicable |
| Evidence | `bb-evidence-readiness` says ready |
| Severity | CVSS / severity reasoning exists when needed |
| Platform fit | Platform accepts this asset / vuln class / evidence type |
| Report hygiene | No internal IDs, no unverified CVEs, no theoretical overclaim |
| Knowledge capture | New reusable learning routed to KB / Lessons / Pattern |

## Output Format

```markdown
## Submission Readiness
- Status: ready / not ready / needs-revalidation
- Finding:
- Dedupe:
- Scope:
- Attack chain review:
- Evidence readiness:
- Severity / CVSS:
- Platform fit:
- Report hygiene:
- Knowledge capture:
- Next action:
```

## Hard Blocks

Do not create or finalize Submission / FORM when:

- Finding is missing
- evidence readiness is `not ready`
- dedupe is unresolved
- scope is unclear
- platform policy likely rejects the report
- CVE / advisory claims are unverified
- report relies on potential impact as if it were verified

## Next Step Routing

- HITCON FORM -> `bb-hitcon-form`
- CVE / advisory references -> `bb-cve-citation`
- CVSS / severity uncertainty -> `cvss-auto-scorer`
- Triage response after submission -> `bb-triage-response`
- Not ready -> `bb-attempt-recorder` or `bb-evidence-readiness`

## Cross-References

- `bb-dedup-finding`
- `bb-scope-safety-check`
- `bb-attack-chain-review`
- `bb-evidence-readiness`
- `bb-knowledge-capture`
- `AGENTS.md §3e.2 Finding → Submission → FORM`
