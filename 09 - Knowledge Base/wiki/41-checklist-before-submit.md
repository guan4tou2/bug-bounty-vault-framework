---
type: wiki
category: checklist
status: active
last-updated: 2026-04-21
---

# Pre-Submission Final Checklist

> Every report must pass through this checklist before submission, to avoid rejection / N/A / Duplicate.

## A. PoC verification

- [ ] Independently reproduced with plain `curl` (not dependent on a Burp session / cookie jar)
- [ ] Every curl command can be **copy-pasted and executed directly** (no placeholders)
- [ ] Response screenshots are clear (HTTP header + body)
- [ ] If login is required → provide a test account or advise the triager how to obtain one
- [ ] For government cases → provide domain WHOIS confirming the affected entity is a **local** company/agency

## B. Scope cross-check

- [ ] The target is on SCOPE.md's `in-scope` list
- [ ] The vulnerability type is not on the OOS (Out-of-Scope) list
- [ ] Not an out-of-scope attack surface (e.g. a target pivoted to from an untouched source asset)
- [ ] Meets the program's minimum severity requirement

## C. Duplicate check (the easiest thing to miss)

- [ ] Searched the program's **disclosed reports**
- [ ] Searched the program's **hacktivity** (both HackerOne/Bugcrowd have this)
- [ ] Google: `site:hackerone.com target vulnerability-type`
- [ ] Google: `site:bugcrowd.com target vulnerability-type`
- [ ] For CVE-class bugs: check the NVD / CVE database
- [ ] Graph query: search your KB index for "target + vulnerability type"

## D. Don't inflate severity

- [ ] Severity matches realistic platform standards (see the Severity mapping table in CLAUDE.md)
- [ ] Didn't write up an unrestricted API key as P2
- [ ] Didn't write up a source map as P1
- [ ] Didn't write up CORS reflection as P2 (unless the prerequisite has been verified)
- [ ] Didn't write up Actuator /health as P2
- [ ] If the VRT-suggested severity is too high → add a severity note

## E. Impact — write only what's verified

```markdown
## Impact

**Verified impact:**
- [What the PoC directly proves]

**Potential impact (requires additional conditions):**
- [Clearly state the prerequisite conditions]
```

- [ ] Every Verified item maps to a PoC step
- [ ] Potential items clearly state "requires X / if Y"
- [ ] No unfounded "could potentially lead to X" claims
- [ ] Static analysis is not written up as a "confirmed vulnerability"

## F. Report completeness

The report includes the following sections (see the mandatory rules in CLAUDE.md):

- [ ] **Vulnerability summary** — one-paragraph summary
- [ ] **Discovery process** — chronological, including failed attempts
- [ ] **Reproduction steps** — a concise version that can be directly copy-pasted and run
- [ ] **Attack chain** — if multiple vulnerabilities, show with →
- [ ] **Impact** — Verified / Potential separated
- [ ] **Tools used** — table (tool / URL / install / command)
- [ ] **Verification status** — ✅ Verified / ❌ Unverified (with reason)
- [ ] **Failed attempts** — to avoid duplicate future work
- [ ] **Remediation suggestions** — concrete and actionable

## G. Precise VRT classification

**Pitfall**: choosing the wrong category auto-suggests P1, and the triager will flag it as "inflated."

| ❌ Wrong classification | ✅ Correct classification |
|------------|-----------|
| Disclosure of Secrets For Publicly Accessible Asset (any public information) | The specific type |
| Sensitive Data Exposure (the source map itself) | Info Disclosure > JS Source Map |
| Broken Authentication (plain user enum) | Enum > User |
| Default suggestion is P1 but reality is P3 | Choose the P3 subcategory |

**Correct principle:**
- Choose the most precise subcategory
- When in doubt, go lower rather than higher
- Report what the vulnerability's actual core is (an XSS found inside a source map → report as XSS)
- If the VRT suggestion exceeds the actual severity → add a severity note

## H. Government cases / HITCON ZeroDay specific

- [ ] Title uses `{organization name}` to redact the entity
- [ ] Organization field is filled in with the full formal name
- [ ] Correct type selected (see CLAUDE.md §HITCON common vulnerability type mapping)
- [ ] Risk matches program standards
- [ ] Screenshots referenced with `{{IMG#*}}`
- [ ] If not a local company → do not submit to HITCON

## I. Bonus items (optional but recommended)

- [ ] Provide remediation suggestions (adds value to the report)
- [ ] Provide an impact-scope estimate (number of affected users / amount of data)
- [ ] Attach supporting evidence (developer git log / third-party data)
- [ ] Bundle multiple related findings into an attack chain (a combination is worth more than a single point)

## J. Update immediately after a triage reply

Once a triage reply comes in, follow CLAUDE.md §Triage Reply Handling:

- [ ] Update operator project notes
- [ ] Update operator memory index
- [ ] Update `vault/Target - *.md` (frontmatter + triage result)
- [ ] If it touches a general pattern → update `Pattern - *.md`
- [ ] Write any new lesson into `Lessons Learned.md`
- [ ] git commit → hook auto-rebuilds knowledge graph

## K. Common rejection reasons (avoid repeating these)

| Rejection type | Reason | Prevention |
|---------|------|------|
| N/A | Source map had no sensitive token | Find an exploitable vulnerability from the source first, don't report the source map alone |
| N/A | Cisco Meraki token not sensitive | Classify VRT precisely, don't pick "Disclosure of Secrets" |
| N/A | acme-corp OCC anonymous access is expected behavior | Analyze the business logic, confirm it's a vuln not a feature |
| Duplicate | Popular pattern + big vendor | Submit as soon as possible after discovery, check disclosed reports |
| Informative | Theoretical (CORS prerequisite unverified) | Fully verify the attack chain before submitting |
| Out-of-Scope | Pivoted to a target outside scope | Strictly stay within the original scope, no pivoting off in-scope assets |
| Self-XSS | Can only attack yourself | Confirm the impact scope first |

## Related files

- [40-checklist-new-target.md](40-checklist-new-target.md)
- CLAUDE.md §Bug Bounty Report Anti-Inflation Rules
- CLAUDE.md §Triage Lessons
