# Evidence Model

This public-safe evidence model defines when a candidate can move from recon output to Finding and Review.

The goal is to keep private evidence useful without turning the vault into a raw data dump.

## Evidence Quality

Evidence quality describes how much confidence the operator has in the candidate:

| Level | Meaning |
|---|---|
| missing | No usable evidence yet. |
| partial | A signal exists, but impact or scope is unclear. |
| reproducible | The behavior can be repeated within Authorized scope. |
| reviewed | The evidence was checked for scope, safety, and duplicate risk. |

## Reproducibility

Evidence reproducibility is required before a candidate is treated as report-ready.

Reproducibility means another authorized operator can understand:

- what was tested
- which scope allowed it
- what input was used
- what result was observed
- why the result matters
- what should not be repeated

Do not require raw sensitive data in the canonical note. Use a safe reference to a private `workspace/` artifact when needed.

## Safe Reference

A safe reference is a pointer to private evidence without copying the raw evidence into a public or shareable note.

Examples:

- `workspace/workshop/<target>/evidence/<artifact>`
- private screenshot reference
- redacted response summary
- reviewed command shape with placeholders

Do not store credentials, tokens, cookies, unrelated personal data, private account data, or raw sensitive data in public-safe notes.

## Finding Gate

Before creating a Finding, confirm:

- Authorized scope is documented.
- Duplicate risk was checked.
- Evidence quality is at least partial.
- Expected impact is described in scoped terms.
- Unsafe reproduction steps are not required.

## Review Gate

Before a candidate becomes report-ready, confirm:

- evidence is reproducible or the limitation is explicit
- scope is clear
- impact is not overstated
- raw sensitive data is referenced safely
- Knowledge Capture candidates are separated from private facts

## Workspace Boundary

`workspace/` is the correct place for raw artifacts, logs, screenshots, temporary outputs, and tool results in an adopted private vault.

Canonical notes should summarize and reference. They should not duplicate raw runtime data.
