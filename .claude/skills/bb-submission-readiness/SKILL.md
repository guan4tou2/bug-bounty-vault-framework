---
name: bb-submission-readiness
description: Use when creating, editing, finalizing, or reviewing a Submission or FORM to confirm dedupe, scope, evidence, attack-chain review, channel fit, severity, and hygiene.
---

# Bug Bounty — Submission Readiness

Use this as the final gate before Submission / FORM creation. It decides whether the report is ready for a platform-neutral disclosure draft or a private downstream adapter.

## Trigger

Run before:

- writing a Submission
- generating a FORM
- sending to an external disclosure channel
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
| Channel fit | The intended downstream channel accepts this asset / vuln class / evidence type |
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
- Channel fit:
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
- downstream policy likely rejects the report
- CVE / advisory claims are unverified
- report relies on potential impact as if it were verified

## Next Step Routing

- Generic FORM / disclosure draft -> `bb-form-writer`
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
- `AGENTS.md §3e Finding → Submission → FORM`
