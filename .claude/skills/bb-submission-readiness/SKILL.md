---
name: bb-submission-readiness
description: Use when creating, editing, finalizing, or reviewing a Submission or FORM to confirm dedupe, scope, evidence, attack-chain review, channel fit, severity, and hygiene — the SUPERSET final gate before submitting. — distinct from bb-evidence-readiness: that is the SUBSET evidence-only completeness/reproducibility check; this wraps it plus dedupe, scope, chain, severity, and hygiene.
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
| Finding lifecycle | `validated` requires: (1) `expected_impact` defined, (2) `poc_ref` to a runnable PoC, (3) PoC achieves `expected_impact` on an authorized target or documented equivalent test environment, (4) `verification_level: dynamic_verified`. A `suspected` finding cannot proceed to submission — verify first or record as an attempt. Run `bash automation/check_verification_debt.sh <target>` to catch gaps |
| Dedupe | `bb-dedup-finding` or equivalent precheck completed |
| Scope safety | `bb-scope-safety-check` completed for live verification |
| Host-level scope match | Match every Affected Asset against the current program brief's named list / wildcard / exclusion rules (cite source date). No match, or an unlisted subdomain where the program is named-list-only and excludes wildcards → drop it or demote to a RECON_DB record; do not submit. Same parent domain / same QA brand / same provider does not imply scope ([[LL-404]]: an OOS submission costs −1 validity point beyond $0) |
| Attack chain | `bb-attack-chain-review` completed, or explicitly not applicable |
| Evidence | `bb-evidence-readiness` says ready |
| Current reproduction | Re-run the applicable PoC at delivery time within existing authorization; confirm the real request/response, version, role, and environment match the report. When a side effect makes replay inappropriate, record the reason and the existing usable evidence; do not require production harm |
| Reproduction completeness | Keep the conditions, steps, PoC / precise manual actions, actual result, impact, limits, and remediation that reproduce independently; chain/method tables go in the body or an appendix. Removing internal information must not cut technical content; word count or line-ratio to the original is not a pass criterion |
| Severity | CVSS / severity reasoning exists when needed |
| Channel fit | The intended downstream channel accepts this asset / vuln class / evidence type |
| Report structure essentials | See the section below ([[LL-411]]) — two-layer prerequisites, per-step session labels, expected-vs-actual, verified-vs-inferred, plus the presentation triplet |
| Provenance | A finding whose `provenance` is an automated-platform output / import and has not had independent Vault review is capped at `tested` and may not be submitted directly — fresh-context review + full readiness gate + title/impact alignment first. Treat automated platform output as a lead, not a finding |
| Report hygiene | No internal IDs, no unverified CVEs, no theoretical overclaim |
| **Quality gate (mechanical)** | Run `bash automation/check_report_quality.sh <FORM/Submission.md>` — must have 0 ❌ (exaggeration words + internal IDs). Catches what hygiene review misses. |
| **Mechanical pre-gates (block)** | Run the four pre-gates below (title / impact-sentence / money-flow / debris-vs-feature) — any failure blocks before the judgment pass. |
| **Adversarial calibration (judgment)** | Run the calibration pass below — does the evidence support the *claimed* severity/impact? Catches confident-but-unproven overclaim the keyword gate can't see. **Advisory: calibrates wording/severity, never auto-kills.** |
| **Language review (judgment)** | Plain-language pass per `Reference Card - Report Writing Standard`: too much jargon? derivations that belong in an appendix? hedges removed by editing? **Advisory: suggests wording only, never changes how sure a conclusion is; single pass.** Separate from calibration — that asks whether the evidence supports the claim; this asks whether the reader can follow it and the tone stayed true. |
| Knowledge capture | New reusable learning routed to KB / Lessons / Pattern |

## Mechanical Pre-Gates — four checks that block before judgment

> These run before the judgment calibration. Each is mechanical (grep / fill-in-the-blank / lookup); any failure blocks, no "feels fine" allowed.

**Common theme of all pre-gates:** things the counterparty can discover → disclose proactively (disclosing first = credibility; being caught = lost trust); things nobody knows → do not speculate (a guess writes the downgrade conclusion for them). The most lethal gap is a fact that contradicts your own impact claim sitting in your own report text.

1. **Title alignment** — Does the title name only the proven cause/impact? Using an unproven vulnerability-class name (API Key Exposure / ATO / RCE…) is a mismatch → fix the title. A triager who reads the title and cannot find matching evidence marks it N/A.

2. **Impact sentence (with victim hook)** — Can you fill in "as an attacker I could ___ **against something that is not myself** (another account / another tenant / vendor infra / a vendor secret), evidence at `file:line`"? Both hooks must pass: (1) a runnable PoC / evidence exists, (2) **victim ≠ attacker**. A demo that happens only on your own sandbox / self-registered account (a restricted user reading their own data; a hash you could not crack and did not prove usable) means the victim is yourself → **not impact**, and will hit the canned "must demonstrate an impact that can have an effect on the customer / its users." Cannot fill the victim slot → `needs-evidence` / `downgrade-severity`.

3. **Money-flow attribution** (run when impact rests on "consuming the counterparty's paid resource") — if impact is built on pay-per-use abuse / denial-of-wallet / quota abuse / "free-riding a paid API", first check whether the upstream provider and the target (and its parent company) are the **same corporate group**, and classify by money flow:

   | Money flow | Verdict |
   |---|---|
   | External **metered** billing (independent third-party provider, per-request price) | argument can stand; still attach the unit price / plan source |
   | External **flat** rate (all-you-can-eat) | no marginal cost → impact very weak, not a main pivot |
   | **Same group / own service** | **argument void → delete the cost paragraph; may not be used as an impact pivot** |

   ⚠️ The acquisition fact is often written in the report's own text (a Note paragraph saying "X … which Y acquired in …", while the impact rests on "free-riding Y's paid key"). So this pre-gate also requires: **scan the whole report and confirm no sentence contradicts the impact claim.** The refutation material you attach yourself is the most lethal. Method: the target's own press release / about page / Crunchbase. When the money argument fails, pivot to data confidentiality or another technical axis (SSRF, write access…), or honestly downgrade. ([[LL-413]])

4. **Debris vs feature** (run when the claim is that a test / debug / internal endpoint "shipped by mistake") — first grep the frontend bundle you already have: `grep -rhoE "/api/test/[A-Za-z0-9/_-]*" <js-dir> | sort -u` (together with flags like `showSkip*` / `isTestEnv` / `qaMode`).

   | Does the frontend call it | How to write it |
   |---|---|
   | No | may write "test-only route shipped" |
   | **Yes** | **must not call it debris** → acknowledge it exists by design, then locate the defect precisely |

   "By design" covers only "the feature exists", **not "the feature lacks an authorization binding"** — keep these separate in the report (a password-reset feature is by design; resetting *someone else's* password is not). Also determine whether the flag gates the UI or the endpoint, and use "a request with no cookie / CSRF / Authorization also succeeds" as evidence, not inference. ([[LL-414]])

## Adversarial Calibration — two-directional, not just anti-overclaim

> The mechanical gate catches hedging words ("could potentially…") but not confident overclaim (evidence only shows info leak, report says ATO). Self-review is also weakly biased (a reviewer that passes 100% is a design flaw). So run one independent-perspective calibration before submitting.
> **Goal = calibration (align claim ↔ evidence), not destruction.** Too aggressive swings from over-claim (FP) to over-weakening (FN) — killing real findings, unjustified downgrades, refusing to report real bugs is equally a defect.

**How (pick one):**
- Light: the main LLM switches hats and answers the 4 questions below. This does not replace `bb-evidence-readiness`'s fresh-context independent verification.
- Strong: spawn an independent skeptic subagent (ideally a *different/stronger* model, convention-injected) returning a structured verdict. A different model beats same-model self-review. Scale rigor with finding severity. `PR:N` or any C/I/A=H also runs `cvss-adversary`; a hat-switch self-review cannot clear those.

**4 calibration questions** (each needs a *specific evidence-based reason*, not "feels weak"):
1. What did the evidence actually prove? Check the Finding's `verified_evidence` (live / source_code / static / theoretical).
2. Does the claimed severity/impact *exceed* the evidence? (e.g. evidence = info leak, report = account takeover)
3. Is there a more mundane explanation? (default behavior / public-by-design / SPA catch-all / 404 ≠ excluded / config ≠ secret / a public CA cert or DSN is by design)
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

## Report Structure Essentials ([[LL-411]])

Four structural floors:
1. **Two-layer prerequisites** — separate "test setup (accounts/data I created)" from "real attacker prerequisites (what they actually need)". Knowing an ID during testing ≠ the attacker can obtain it.
2. **Per-step session labels** — every reproduction step states which session/account it uses (attacker / victim). Essential for OAuth, IDOR, cross-tenant.
3. **Expected vs Actual** — state the restriction that *should* have applied + the actual result. A lone `200` is not evidence — prove the content belongs to another account; `403`/`404` both count as correct denial.
4. **Verified vs inferred, separated** — cross-account single read ≠ bulk export; DNS callback ≠ internal access; JS execution ≠ ATO. When a rule cannot be crossed in testing, state the limit and the basis for inference; do not write inference as proven.

Three presentation items (evidence can be strong and still fail if the triager can't grasp it in 10 seconds):
5. **One-line TL;DR** — one sentence under the title giving the full chain + verified C/I/A.
6. **At-a-glance attack flow** — an ASCII sequence or a very short numbered flow, including the negative control and where each step lands.
7. **Paste-ready curl + full runnable PoC** — copy-paste curl for the key steps (masked token / placeholder host) so the triager need not read a script; the full PoC is hard-gated by `finding_validation_gate` + `poc_ref`. Screenshot quotes must faithfully include key characters (e.g. backslashes).

## R2 Verification Forcing Gate (hard — unlike the advisory calibration above, this one blocks)

> `status: verified / ready / submitted` **requires** `verified_evidence: live`. A hard gate, not advice (contrast the advisory calibration above, which "only advises, never auto-edits").
- `verified_evidence` still `theoretical / static / source_code` → **may not** be marked ready / submitted. Two paths: (a) obtain live (a deterministic check: real browser run / OOB callback / cross-origin real read / two identities actually crossing a boundary), or (b) keep it theoretical and route to `bb-attempt-recorder`.
- A theoretical / reflection hit may not be disguised as verified.
- **Soft enforcement**: only blocks a finding being upgraded now; does not retroactively touch legacy findings.

## Output Format

```markdown
## Submission Readiness
- Status: ready / not ready / needs-revalidation
- Finding:
- Dedupe:
- Scope:
- Host-level scope match:
- Attack chain review:
- Evidence readiness:
- Severity / CVSS:
- Channel fit:
- Report hygiene:
- Mechanical pre-gates: <title / impact-sentence / money-flow / debris-vs-feature — pass or which failed>
- Adversarial calibration: <confirm / tighten-wording / downgrade-severity / needs-evidence / likely-invalid> — <specific reason>
- Language review: <ok / revise> — <jargon / appendix / removed-hedge counts>
- Knowledge capture:
- Next action:
```

## Hard Blocks

Do not create or finalize Submission / FORM when:

- Finding is missing
- Finding is `suspected` (not `validated`) — verify first or record as attempt
- `validated` but no `poc_ref` — write a runnable PoC that achieves `expected_impact`
- `expected_impact` is undefined — can't judge whether the PoC succeeded without success criteria
- evidence readiness is `not ready`
- dedupe is unresolved
- scope is unclear
- Affected Asset does not match the program's named scope (host-level scope match) — an unlisted subdomain / excluded wildcard / scope inferred from a shared parent domain → drop or demote, do not submit ([[LL-404]])
- `provenance` is an automated-platform output / import without independent Vault review — capped at `tested`, not submittable directly
- title-evidence mismatch — the title names an unproven vulnerability class / impact (key not leaked but titled "API Key Exposure"; ATO not proven but titled "Account Takeover"). A triager who follows the title and finds no evidence marks it N/A. Rename to the proven cause/impact first.
- impact sentence cannot be filled / victim is yourself — cannot fill "as an attacker I could ___ against something that is not myself, evidence at `file:line`". Pure info disclosure / best-practice / quota abuse of public data, or a demo that happens only on your own sandbox / self-registered account (victim = attacker) → strengthen or downgrade, do not submit.
- downstream policy likely rejects the report
- CVE / advisory claims are unverified
- report relies on potential impact as if it were verified

## Next Step Routing

- Generic FORM / disclosure draft -> `bb-form-writer`
- CVE / advisory references -> `bb-cve-citation`
- CVSS / severity uncertainty -> `bb-cvss-score`
- Triage response after submission -> `bb-triage-response`
- Not ready -> `bb-attempt-recorder` or `bb-evidence-readiness`

## Cross-References

- `bb-dedup-finding`
- `bb-scope-safety-check`
- `bb-attack-chain-review`
- `bb-evidence-readiness`
- `bb-knowledge-capture`
- `AGENTS.md §3e Finding → Submission → FORM`
