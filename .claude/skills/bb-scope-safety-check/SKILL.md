---
name: bb-scope-safety-check
description: Use when scans, fuzzing, payloads, POST/PUT/PATCH/DELETE, bbflow hunt/flow, Osmedeus, Nuclei, BBOT, or live verification may write data or create service impact.
---

# Bug Bounty — Scope Safety Check

Use this gate before risky live actions. It keeps scan scale, scope, risk classification, and Operation Log requirements explicit.

## Trigger

Run before:

- bbflow `hunt` / `flow`, Osmedeus, Nuclei, BBOT, fuzzing, crawler expansion, or active scan
- POST / PUT / PATCH / DELETE
- payload upload, webhook, callback, SSRF, parser, import, or stored effect
- high-rate requests or actions that may affect service state
- user asks "can I scan", "run nuclei", "osmedeus", "bbot", "payload", or "verify"

When you start operating on a target, proactively state the actual audit-log path (e.g. `$LOGS_ROOT/claude_audit_YYYYMMDD.log`, by the recorder's UTC date) so the operator can trace actions; do not treat a stale relative `logs/` path as current, and do not read the whole log just to announce it.

## Required Checks

| Gate | Question |
|---|---|
| Scope source | Which `SCOPE.md`, program page, or written authorization allows this? |
| Asset match | Is every host / path / account in scope? |
| Risk tier | What changes if this request succeeds — read, state query, write, or service impact? |
| Rate / scale | Is the scan rate appropriate for the target and program? |
| Runtime / egress | Does SCOPE require a registered egress, an authorization window, or a permitted tool list? Then choose the allowed execution host. |
| Operation Log | Has the action been recorded in `RECON_DB.md ## Operation Log`? |
| Stop condition | What response, error, or impact signal stops the action immediately? |

## Output Format

```markdown
## Scope Safety Check
- Status: allowed / blocked / needs-human-confirmation
- Scope source:
- Asset match:
- Risk tier:
- Runtime / actual egress:
- Operation Log status:
- Rate / scale:
- Stop condition:
- Allowed command class:
```

## Runtime Decision

- **Obey this program's SCOPE first.** For a program with a `registered_ip`, target traffic may only exit from the designated egress host (`ssh <registered-vps> 'bb-curl …'`); local curl, PoC, or any other host cannot substitute. Authorization windows, host lists, and the permitted scanner set are checked the same way — never decided from stale deployment memory.
- When no fixed egress is required: a single allowed read-only confirmation, offline analysis, documentation, and dedupe may run locally; scan/fuzz/payload/high-rate recon run on the approved environment at the approved rate.
- Blocked: unclear scope, write side effects unknown, required Operation Log missing, or unsafe impact risk. Routine actions already covered by existing authorization may continue; only a new class of operation, writes/other-party data, or irreversible risk without authorization warrants stopping to ask.

## Safe-Alternative Ladder for Write-Gated Verification

"Verification requires a write" is not a reason to stop — it is a starting point. Stopping at "this would modify a real user's data" is correct; treating "no read-only method exists" as "no safe method exists" is not. (A password-reset endpoint can sit unverified for months because the only obvious test looks destructive, when several safe rungs were in fact available — see [[LL-407]].)

Before declaring `blocked`, walk every rung in order, recording "done / not-applicable + reason" for each:

| Rung | Method | Example |
|---|---|---|
| 1 Read the flow | GET-only: the form that calls the endpoint, its JS, the email-link format, API docs — recover parameter names and whether a token is required | a reset form's action and fields |
| 2 Non-existent object | Use an existing oracle to confirm an ID/account does not exist, then send the write against it and observe only the error difference | an account the login oracle reports as absent |
| 3 Self-owned object | Register or use your own account / tenant / object so the write affects only you | your own registered test account |
| 4 Isolated replica | A local or sandbox build of the same version (`sandbox-replay`), or vendor-provided staging | — |
| 5 Vendor collaboration | Request a test account, or ask the vendor to self-check; state exactly what you need | a self-check question in the disclosure |

- Only when all five rungs are "not applicable" or "blocked" does it count as `blocked`; record `result: blocked-needs-authorization` in the Attempt/Recon and add a `## Safe-Alternative Ladder` section (`check_parked_leads.py` checks for it).
- A parked lead needs an owner: write it into the ledger (`asg.py add-hypothesis`) or an Attempt with an explicit unlock condition — not only in Retest/Recon prose.
- No rung may write to anyone else's real account or data; rungs 2 and 3 are still bound by SCOPE and authorization.

## Exposure Window of Reversible Writes ("submit-then-cancel" is not atomic)

Rung 3 (self-owned object) is often implemented as "send a write, then immediately cancel it." **The gap between those two steps is how long the object is actually live in the counterparty's system** — and it is usually not the "instant" you assume. A cancel acknowledged with `200` can be the ack for a write that already took effect.

Before sending a reversible write, three questions:

1. **How long until the cancel can actually be sent?** Count rate limits, signature recomputation, manual confirmation, and session re-acquisition. Your own throttle settings become the exposure duration on their system.
2. **Who touches it during that window?** Shared resources (order books, queues, indexes, webhooks, notifications) can be read or consumed by a third party before you cancel. A write that affects only your own account can still enter a shared matching/dispatch path.
3. **Is the safety margin a distance or a relative position?** "Will not trigger now" and "cannot be triggered" are different. A relative offset (e.g. best-bid − 1 tick) moves with the market; an absolute value orders of magnitude away does not. The margin must survive a change in the underlying state, not hold only at the instant of submission.

After cancelling, read back the object itself ([[LL-415]]) — an asynchronous ack is not a result, and when it masks a write that did take effect, the cost is not an inaccurate claim but real impact. If the read-back shows the write took effect, retract any "will not take effect / zero impact" statement and assess whether the counterparty must be notified.

## OOS References in Config and Responses

An in-scope config, JS file, or document that references another URL does not grant permission to test that asset. The authorization list of named hosts is a hard boundary; a shared wildcard, company, certificate, or deployment relationship does not let you expand scope on your own.

- Record only in the target's RECON_DB "OOS references": source Record ID, in-scope file location, referenced asset, and an untested marker — do not curl, probe, log in, test credentials, or follow cross-scope redirects.
- A report may cite in-scope content you already obtained, but must label it "this asset is not on the authorization list; discovered only via an in-scope config reference, not actively verified" — an OOS reference must not be written up as confirmed impact.
- After obtaining written scope expansion, update SCOPE/ledger first, then act under the new authorization. Keep the source and limitations for any unclear or accidentally-obtained OOS evidence; do not expand contact to "confirm" it.

## Hard Rules

- Risk classification is mechanical, not a method guess: `curl_gate.sh` (PreToolUse) classifies every curl/wget via `risk_tier.py` — `reads_only`/`state_query` pass, `writes_data` warns, `service_impact` blocks. This skill judges SCOPE + AUTHORIZATION (is this host/action in scope, is the Operation Log present), not "GET vs non-GET". A write with defined, authorized impact is fine; declare `BB_RISK=<tier>` to correct a misclassification. (GET-first as a method rule is superseded — a destructive GET such as a jolokia stop is `service_impact`, which method-guessing missed.)
- Execution-host selection never overrides registered egress, authorization windows, or program controls.
- Do not bypass WAF, firewall, rate limits, or program controls unless explicitly authorized by scope.
- Do not proceed if an Operation Log is required but missing.
- If service impact appears, stop and run `bb-incident-response`.

## Cross-References

- `bb-incident-response`
- `AGENTS.md §6`
- `09 - Knowledge Base/Reference Card - Testing Safety Rules.md`
- `$WORKSHOP_ROOT/<target>/SCOPE.md`
