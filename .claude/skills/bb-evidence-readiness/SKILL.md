---
name: bb-evidence-readiness
description: Use when creating or reviewing a Finding, Submission, FORM, attack chain, or report evidence to verify reproducibility, Discovery Log completeness, audit references, and anti-overclaim discipline.
---

# Bug Bounty — Evidence Readiness

Use this gate before a Finding moves beyond draft and before any Submission or FORM is written.

## Trigger

Run this when:

- creating or editing a Finding
- preparing a Submission / FORM
- reviewing attack-chain evidence
- deciding whether a candidate is ready or should remain an Attempt
- user asks "證據夠嗎", "能送嗎", "report ready", or "reproducible?"

## Required Checks

| Gate | Ready condition |
|---|---|
| Repro steps | Another reviewer can reproduce with the given steps |
| Request evidence | Full request / curl / command is present when applicable |
| Response evidence | Relevant response excerpt, screenshot, file path, or raw artifact reference exists |
| Discovery Log | Includes time, source IP, target IP, audit ref, action + result |
| Scope | Target / endpoint / account is in scope |
| Impact | Impact is demonstrated, not only asserted |
| Anti-overclaim | The report separates verified impact from potential impact |
| Freshness | Evidence date is recent enough for the target and platform |

## Output Format

```markdown
## Evidence Readiness
- Status: ready / not ready
- Missing evidence:
- Discovery Log status:
- audit ref status:
- Reproducibility:
- Verified impact:
- Potential impact not yet proven:
- Next action:
```

## Readiness Decision

- `ready`: all required checks pass.
- `not ready`: any hard evidence, scope, or reproducibility item is missing.
- `needs-revalidation`: evidence is old, target changed, or the vulnerable behavior is not currently reproducible.
- `attempt-only`: hypothesis is useful but cannot support a Finding.

## Hard Rules

- Do not let a Submission or FORM proceed when this gate says `not ready`.
- Do not treat screenshots alone as proof if the request / response is missing.
- Do not cite CVE / disclosed report details without `bb-cve-citation`.
- Do not fill missing evidence with assumptions.
- If evidence is insufficient, use `bb-attempt-recorder`.

## Cross-References

- `bb-dedup-finding`
- `bb-attack-chain-review`
- `bb-submission-readiness`
- `AGENTS.md §3b Discovery Log`
- `09 - Knowledge Base/Reference Card - Testing Safety Rules.md`

