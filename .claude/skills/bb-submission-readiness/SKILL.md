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
| **Quality gate (mechanical)** | Run `bash automation/check_report_quality.sh <FORM/Submission.md>` — must have 0 ❌ (exaggeration words + internal IDs). Catches what hygiene review misses. |
| **Adversarial calibration (judgment)** | Run the calibration pass below — does the evidence support the *claimed* severity/impact? Catches confident-but-unproven overclaim the keyword gate can't see. **Advisory: calibrates wording/severity, never auto-kills.** |
| Knowledge capture | New reusable learning routed to KB / Lessons / Pattern |

## Adversarial Calibration — two-directional, not just anti-overclaim

> The mechanical gate catches hedging words ("could potentially…") but not confident overclaim (evidence only shows info leak, report says ATO). Self-review is also weakly biased (a reviewer that passes 100% is a design flaw). So run one independent-perspective calibration before submitting.
> **Goal = calibration (align claim ↔ evidence), not destruction.** Too aggressive swings from over-claim (FP) to over-weakening (FN) — killing real findings, unjustified downgrades, refusing to report real bugs is equally a defect.

**How (pick one):**
- Light: the main LLM switches hats and answers the 4 questions below.
- Strong: spawn an independent skeptic subagent (ideally a *different/stronger* model, convention-injected) returning a structured verdict. A different model beats same-model self-review. Scale rigor with finding severity.

**4 calibration questions** (each needs a *specific evidence-based reason*, not "feels weak"):
1. What did the evidence actually prove? Check the Finding's `verified_evidence` (live / source_code / static / theoretical).
2. Does the claimed severity/impact *exceed* the evidence? (e.g. evidence = info leak, report = account takeover)
3. Is there a more mundane explanation? (default behavior / public-by-design / SPA catch-all / 404 ≠ excluded / config ≠ secret)
4. Strip all speculation — do the remaining facts still constitute a reportable vuln? (three-question filter)

**Verdict (pick 1) + reason + suggested severity:**
- `confirm` — evidence holds, submit as-is. **This is a valid, common outcome — not "found nothing wrong".**
- `tighten-wording` — finding is real, wording is inflated → **fix wording, don't drop the finding** (most common fix).
- `downgrade-severity` — real but severity too high → lower to the supported level.
- `needs-evidence` — right direction, insufficient proof → gather more before submitting (NOT a kill).
- `likely-invalid` — collapses once speculation is removed → only then consider kill / move to attempt-recorder.

**Anti-over-weakening rules (hard):**
- The skeptic **only advises; never auto-edits the finding/severity** — the human/main LLM decides.
- **Default action leans to "calibrate wording / downgrade", not "kill"** — most overclaims are real findings stated too strongly, not fake findings.
- A refutation **must cite a specific evidence gap or alternative explanation**; no concrete reason = not a valid refutation, ignore it.
- **One pass, not loop-until-dry** (refuting until nothing is left = over-weakening).
- Solid evidence → just `confirm`: kill-everything is the mirror defect of pass-everything.

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
