---
type: checklist
title: Checklist - FORM Description vs Discovery Log Consistency Gate
tags: [checklist, submission-quality, form, discovery-log, consistency, pre-submission, dedup, credibility]
status: active
category: Checklist
added: 2026-06-04
last_updated: 2026-06-04
source: Item #12 — FORM claiming "any unauthenticated user can access" while Discovery Log shows access required prior RCE token
integration: bb-submission-readiness (add as mandatory §FORM-CONSISTENCY block); bb-evidence-readiness (cross-reference)
---

# Checklist - FORM Description vs Discovery Log Consistency Gate

## TL;DR

Before finalising any FORM's impact statement, re-read the full Discovery Log for that finding. Confirm the access method described in the FORM matches how the vulnerability was actually reached. A single contradicted sentence — "any unauthenticated user can access" when the log shows the path required a prior RCE token — causes credibility collapse with triagers.

**This is a mandatory gate, not a suggested review.** It slots into `bb-submission-readiness` after evidence-readiness and before platform formatting.

---

## Failure Mode This Gate Prevents

**Post-exploitation dependent finding reported as independent unauthenticated access.**

Concrete example: A GCS bucket URL is discovered by reading environment variables from a compromised GKE pod (RCE path). The FORM description later states "any unauthenticated attacker can access `gs://prod-infra-backup/`". Both facts are true in isolation — the bucket is publicly readable — but the discovery path required prior RCE. If the triager asks "how did you find the bucket URL?" and the Discovery Log shows `GET /actuator/env → token → gsutil ls`, the FORM description is directly contradicted by your own notes.

Outcome: N/A or rejection on grounds of misleading impact statement, regardless of whether the bucket is actually misconfigured.

---

## When to Run This Checklist

Run immediately before writing or finalising the FORM **impact statement** and **steps to reproduce**, in any of these situations:

- The finding was discovered during a multi-step session (recon → exploitation → lateral movement → this finding).
- The finding candidate was created during or after another finding's verification.
- More than 24 hours passed between discovery and FORM creation.
- The Discovery Log for this target spans more than one session or handoff.

---

## Mandatory Pre-FORM Consistency Checks

### Check 1 — Access Method: How Was the Vuln Reached?

**Action:** Open the Discovery Log for this finding. Find the first line that references the vulnerable endpoint, credential, or resource. Read backwards from that line to identify what pre-conditions were in place.

**Ask:** Does the FORM's "Steps to Reproduce" describe those same pre-conditions as step 1?

**Pass condition:** The FORM steps start from the same authentication/access state that a real attacker would start from — not from the mid-session state you were in when you discovered it.

**Fail signals:**
- Discovery Log line: `[14:32] [RCE-session] curl -H "Authorization: Bearer $GKE_TOKEN" http://169.254.169.254/...`
- FORM steps: `1. Visit https://storage.googleapis.com/prod-infra-backup/`
- The curl command assumes a token already in hand; the FORM steps assume an anonymous browser visit.

**Fix:** Determine whether the bucket is independently discoverable (e.g., via Google Dorks, Shodan, source map leak) without the RCE token. If yes, document that independent discovery path in the FORM. If no, the finding must be framed as a post-exploitation escalation, not a standalone unauthenticated access issue.

---

### Check 2 — Independence: Does the FORM Claim Standalone When the Log Shows Chained?

**Action:** Identify every credential, token, session cookie, or internal URL referenced in the FORM's reproduction steps. For each one, find where it appears first in the Discovery Log.

**Ask:** Does each prerequisite appear before any exploitation step in the Discovery Log, or does it appear as output of a prior exploitation?

| Prerequisite origin in Discovery Log | Correct FORM framing |
|---------------------------------------|----------------------|
| Obtained from public source (Shodan, Wayback, source map, unauthenticated endpoint) | Standalone unauthenticated finding — allowed |
| Obtained from authenticated session with valid credentials | "Authenticated attacker" or "requires valid account" — must state this |
| Obtained as output of a prior exploitation step (RCE, SSRF response, token leak via another vuln) | Post-exploitation dependent — must state this; cannot claim "unauthenticated" |

**Fail signals:**
- FORM says "an unauthenticated attacker with knowledge of the bucket name"
- Discovery Log shows the bucket name was read from `/actuator/env` output after using a SSRF credential
- "Knowledge of the bucket name" is framed as if freely available, but the log shows it required exploitation

---

### Check 3 — Verification Commands: Are Steps Reproducible From Zero?

**Action:** Copy the FORM's "Steps to Reproduce" verbatim. Simulate running them starting from a fresh terminal with no prior session, no exported variables, no cookies.

**Paste this mental model check:**
```
STARTING STATE: anonymous, no tokens, no internal URLs, no prior access
RUN: [step 1 from FORM]
RUN: [step 2 from FORM]
...
RESULT: [does the final step produce the claimed evidence?]
```

**Pass condition:** Every curl command, every URL, every credential placeholder in the FORM can be populated by someone who has only the information available to an attacker at the claimed access level (unauthenticated, user-level, admin-level, etc.).

**Fail signals:**
```bash
# FORM step 3 (as written):
curl -H "Authorization: Bearer $SA_TOKEN" \
  https://storage.googleapis.com/storage/v1/b/prod-infra-backup/o

# But $SA_TOKEN only exists because:
# Discovery Log [11:47]: curl http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
# ...which required being inside a GKE pod (RCE step from a prior finding)
```

**Fix:** Either:
(a) Reframe the finding as "post-exploitation: GCS bucket publicly readable once SA token is obtained via SSRF/metadata endpoint" — change severity and impact accordingly.
(b) Find an independent path to obtain the bucket URL and SA token that does not require prior RCE, and document that path as step 1.

---

### Check 4 — Multi-Step Session: Re-Read Full Discovery Log Before Writing Impact Statement

**Trigger:** The finding FORM is being written after a session where you also exploited a different vulnerability on the same target.

**Action:** Before writing the impact statement, open the full Discovery Log (not just the most recent session section) and read the chronological sequence of events that led to this finding.

**Check the following:**
- [ ] The impact statement only claims impact achievable from the stated entry point.
- [ ] The impact statement does not use phrases like "any attacker" or "unauthenticated" if the Discovery Log shows the finding required a prior foothold.
- [ ] If the finding amplifies the impact of a prior finding, that dependency is stated explicitly: "This finding extends FINDING-ID by exposing..."
- [ ] The CVSS vector's Authentication/Privileges Required field matches the actual access level needed at entry.

---

## Quick Self-Test Before Submitting

Answer all four. One `NO` = do not submit; fix the FORM first.

| # | Question | Pass |
|---|----------|------|
| Q1 | Can a real attacker reach step 1 of the FORM's reproduction steps without relying on any output from a prior exploitation? | YES |
| Q2 | Does every token/credential/URL in the FORM steps appear in the Discovery Log as obtained via a path that matches the claimed access level? | YES |
| Q3 | Does the impact statement's scope (unauthenticated / authenticated / post-exploitation) match the Discovery Log's first reference to this resource? | YES |
| Q4 | If this is a multi-step session: did you re-read the full Discovery Log before writing the impact statement? | YES |

---

## Remediation Patterns

### Pattern A: Finding is genuinely independent but the FORM steps assumed session context

Fix: Rewrite steps to reproduce starting from zero. Test them in a fresh terminal. Export only variables that can be obtained at the claimed access level.

### Pattern B: Finding is post-exploitation dependent — cannot be made independent

Fix: Update the FORM:
- Title: prefix with "Post-Exploitation:" or "Requires Prior RCE:"
- Impact statement: "An attacker who has already achieved [prior access level] can additionally..."
- CVSS: set Privileges Required to High or Adjacent; reduce Attack Complexity if applicable
- Consider merging with the parent finding if root cause is the same (see dedup rule: same root cause = one report)

### Pattern C: Finding was documented too quickly during an exploitation session

Fix: Add a 24-hour cooling-off rule — do not write the final FORM impact statement in the same session where you discovered the finding via a multi-step chain. Return the next day with a fresh read of the Discovery Log.

---

## Integration Into Existing Gates

This checklist is a **distinct check** from `bb-evidence-readiness` and `bb-submission-readiness`. Those skills verify that evidence exists and is attached. This checklist verifies that the **narrative framing in the FORM matches what the evidence actually shows**.

Add to `bb-submission-readiness` as a mandatory block:

```
## §FORM-CONSISTENCY (mandatory — runs before platform formatting)
Source: Checklist - FORM Description vs Discovery Log Consistency Gate
Trigger: always, before finalising impact statement
Actions:
  1. Check 1 — Access method in FORM matches Discovery Log entry point
  2. Check 2 — Independence claim vs Discovery Log prerequisites
  3. Check 3 — Steps reproducible from zero without session context
  4. Check 4 — (if multi-step session) Full Discovery Log re-read completed
Fail action: block FORM submission; update impact statement or reframe finding
```

---

## Anti-Patterns

| Do not | Do instead |
|--------|-----------|
| Write the FORM impact statement in the same terminal session where you found the vuln via RCE | Return next session; re-read Discovery Log cold |
| Use "any unauthenticated user" without checking where the first URL/token came from | Grep Discovery Log for the first occurrence of the resource |
| Assume that because the endpoint is publicly accessible, it is independently discoverable | Verify there is a public path to the URL that does not require prior exploitation output |
| Merge two findings to inflate impact ("RCE + bucket access = total infrastructure compromise") | Report them separately with explicit dependency chain stated in each |
| Accept CVSS "AV:N/AC:L/PR:N" without checking if PR:N is justified | Cross-check Privileges Required against Discovery Log entry point |

---

## Related

- [[bb-submission-readiness]] — integrate §FORM-CONSISTENCY as mandatory block
- [[bb-evidence-readiness]] — ensures evidence files exist; this checklist ensures framing matches evidence
- [[Checklist - Same Target Multi-Platform Submission Split]] — dedup before splitting
- [[Reference Card - Bug Bounty Workflow 2026]] — gate sequence
- AGENTS.md §3e.2 — Finding → Submission → FORM lifecycle
- AGENTS.md §5 — anti-exaggeration and severity honesty rules
- Lessons Learned #72 — GKE SA Token reporting: must state token is long-lived, dependency on prior access
- Lessons Learned #77 — GCS Terraform state disclosure: infrastructure topology leak via post-RCE enumeration
