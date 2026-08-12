---
type: wiki
category: flow
tool: hackerone,bugcrowd,intigriti
status: active
last-updated: 2026-04-21
---

# Dupe Hunting + Report Writing (2026 Edition)

> **Purpose:** 2026 reality: common patterns on popular programs (source maps / Actuator / CORS / user enum) have almost all already been reported. **A 15-minute dupe search before submitting** can save you a lot of credibility. This doc combines: dupe search workflow + VRT calibration + report structure + avoiding N/A.

## 0. Three Bottom Lines

1. **Only write what you can prove:** impact must be backed by a PoC (never write "possibly")
2. **Realistic VRT:** an unrestricted API key on a big vendor is P4, not P2
3. **Search for dupes first:** popular patterns on big vendors have been reported by at least one person

Violating any of these → N/A / Informative / Severity downgrade / credibility hit.

## 1. Dupe Search Workflow (mandatory)

### 1.1 HackerOne Hacktivity

```
https://hackerone.com/hacktivity?querystring=<domain>
https://hackerone.com/<program>/hacktivity    (public disclosures)
```

Filters:
- Program: target program
- Keyword: vuln name / endpoint / CVE
- Status: Resolved / Informative

### 1.2 Bugcrowd Crowdstream

```
https://bugcrowd.com/crowdstream?category=<target>
```

### 1.3 Intigriti

```
https://www.intigriti.com/public/trending
Search for the program's accepted reports
```

### 1.4 Google Dorks

```
site:hackerone.com "target.com" "<vuln keyword>"
site:bugcrowd.com "target.com"
"target.com" "Triaged" OR "Resolved" filetype:pdf
```

### 1.5 Twitter / Blogs

```
site:twitter.com "target.com" bounty
site:medium.com "target.com" bug bounty
```

### 1.6 Pentester-land / Bug Bounty Writeups

https://pentester.land/ — aggregates all public writeups

```
Search for the target / similar patterns
```

### 1.7 GitHub Search

```
site:github.com "target.com" "vulnerability"
site:github.com "target.com" "P1" OR "P2"
```

### 1.8 Check CVEs

```
https://nvd.nist.gov/vuln/search
Search for target.com vendor
```

### 1.9 Program's disclosed.md

Many programs maintain their own acknowledged list — check it.

## 2. VRT Reality Check (avoid overstating)

### 2.1 Bugcrowd VRT 2026

https://bugcrowd.com/vulnerability-rating-taxonomy

### 2.2 Common Overstatements → Reasonable Rating

| Category | Typically overstated as | Reasonable rating | Note |
|------|---------|---------|------|
| Info disclosure / source map | P2 | P5 / N/A | Unless it contains a sensitive, exploitable secret |
| Unrestricted API key (Maps/Firebase) | P2 | P4 | Unless you can quantify financial impact |
| User enumeration alone | P3 | P5 Informational | Only escalates when chained to ATO |
| Missing header (X-Frame-Options etc.) | P4 | N/A | Most programs explicitly list this as OOS |
| Spring Boot Actuator /health | P2 | P3-P4 | Depends on what's leaked; /env with a secret = P2 |
| Clickjacking with no impact | P4 | P5 / OOS | |
| Open redirect alone | P3 | P5 / N/A | Chained to OAuth code theft = P1-P2 |
| CSRF on a no-impact endpoint | P3 | N/A | |
| Reflected XSS in POST only | P3 | P3-P4 | |
| Stored XSS on an authenticated user's own page | P3 | P4 | |
| CORS wildcard with credentials=true | P2 | P2 | Still valid |
| IDOR reading public info | P3 | P4 | |
| IDOR reading PII | P2 | P2 | |
| IDOR write | P1-P2 | P1-P2 | Genuinely high |
| Hardcoded secret (test env) | P2 | P5 / P4 | Depends on whether it's usable in prod |
| Subdomain takeover (no session scope) | P2 | P3 | Depends on the carrier |
| Subdomain takeover (session scope) | P1 | P1-P2 | |

### 2.3 VRT Classification Traps

```
Wrong: Source map exposure -> pick "Disclosure of Secrets" (VRT suggests P1)
Right: Pick "Publicly Accessible Asset - Minor Info Leak" -> P4-P5

Wrong: Public Google OAuth client_id -> "Disclosure of Secrets"
Right: Don't report it, or report it "for completeness" and mark it Informational

Wrong: User enumeration -> "Broken Authentication" (P1)
Right: "Business Logic - User Enumeration" -> P5
```

**2026 complaint from big vendors: triagers who see an overstated VRT will just mark it N/A (treated as noise).**

## 3. When to Submit, When to Hold

### 3.1 Submit

- Exploitable, high-severity issues (RCE, ATO, SQLi, IDOR write)
- Produces a concrete financial / user impact
- PoC reproducible in 5 minutes
- Dupe search found no similar report

### 3.2 Hold

- Found via static analysis but no live exploit yet
- Preconditions not met (subdomain takeover not actually tested, OAuth state possibly guessable)
- Info disclosure only, no chain
- This pattern already has a disclosed report on the target

### 3.3 Don't Submit

- Hits OOS (scope explicitly excludes it)
- Theoretical attack (no PoC)
- Known issue / already documented
- Best-practice violation with no real risk

## 4. Report Structure (common to H1 / Bugcrowd)

```markdown
## Summary
[1-2 sentences: what the vulnerability is + how to exploit it + max impact]

## Severity
[VRT classification + Severity + corresponding CVSS]

## Vulnerable Endpoint
[URL / method / parameter]

## Steps to Reproduce
1. [concrete step]
2. [concrete step]
...

### PoC
```bash
curl ... -d '...'
```

Response:
```
HTTP/1.1 200 OK
...
```

## Impact
[Only write verified impact. Each bullet maps to a PoC step]

## Remediation
[Concrete fix suggestions the dev can act on]

## References
[Related CVE / OWASP / PortSwigger links]
```

### 4.1 Writing the Summary

```
Bad: "I found XSS"
Good: "Stored XSS in /profile endpoint via name field allows code execution in other users' browsers when they view the victim's profile, enabling session theft."
```

Formula: `{vuln name} in {endpoint} via {parameter} allows {who} to {action}, enabling {impact}.`

### 4.2 Writing Impact

**Write it in layers:**

```markdown
## Impact

**Verified impact:**
- [List only what's verified]
- Attacker can read arbitrary other users' emails (IDOR on GET /api/users/{id})
- Includes PII (name, email, phone, address)

**Potential impact (requires additional conditions):**
- If the target has an email confirmation flow bypass -> ATO (needs separate verification)
```

**Forbidden:** "full compromise", "complete takeover", "critical security risk" (unless you have direct evidence)

### 4.3 Writing the PoC

```
# Full curl / screenshot / video
# Reviewer should be able to reproduce within 5 minutes

curl -X GET 'https://target.com/api/users/1' \
  -H 'Authorization: Bearer <my_token_REDACTED>'

# Response:
# {"id":1,"email":"admin@target.com","role":"admin"}

Screenshot: [attached]
Video: [link to unlisted YT / loom]
```

### 4.4 Writing Remediation

```
Good:
1. Implement ownership check: `if (req.user.id !== req.params.id && !req.user.isAdmin) return 403;`
2. Add middleware `authorizeResource` on all /api/users/:id routes
3. Review OWASP API Top 10 BOLA section

Bad:
"Fix the authorization issue"
```

## 5. Common N/A Reasons

### 5.1 VRT Mismatch

- Vulnerability classified at too high a severity
- Triager thinks the classification is wrong

### 5.2 OOS

- Scope explicitly excludes the asset
- Excluded vulnerability type (e.g. "missing headers")

### 5.3 No Impact

- No user impact / theoretical vulnerability
- Best-practice violation with no exploit

### 5.4 Already Reported

- Duplicate
- Known issue

### 5.5 Informative

- Interesting but not a real vulnerability
- Info disclosure with nothing sensitive

### 5.6 Report Quality

- PoC unclear / fails to reproduce
- Impact overstated
- Missing step-by-step instructions

## 6. Pre-Report-Writing Checklist

```
[ ] Dupe search: 3 platforms + Google + Twitter, at least 15 minutes
[ ] VRT classification: pick the precise subcategory, don't chase the highest severity
[ ] Severity comparison table vs my rating -> am I overstating it
[ ] PoC tested 3 times to confirm it's stable
[ ] Every impact bullet maps to a PoC step
[ ] Remediation is concrete and actionable
[ ] Checked against every OOS item
[ ] Report contains none of: full compromise / critical / severe / complete takeover
[ ] Screenshots / videos redact my own and others' sensitive info
[ ] Re-read once more: can the triager understand it within 5 minutes?
```

## 7. Follow-up Etiquette

### 7.1 When Responding to Triage

```
Accepted / Triaged:
- Thank them + wait for final severity
- If severity is downgraded too much: politely request re-evaluation (with extra PoC attached)

Duplicate:
- Ask for the original submission date (confirm chronological order)
- Acknowledge and move on to the next target

N/A / Informative:
- Read the triager's reasoning
- If you have new evidence: politely supplement it (don't argue)
- If it truly doesn't hold up: learn the lesson, write it into memory

Resolved:
- Thank them + ask about bounty timeline
- If asked to re-test -> cooperate
```

### 7.2 Prohibited

- Repeatedly pinging to rush the bounty
- Publicly posting the report (most programs are under NDA)
- Threatening / emotional follow-ups

## 8. Accumulating Experience

```
After every triage result, update:
1. Operator's per-target project notes (case-specific)
2. Lessons Learned.md (general lessons)
3. The triage-lessons section of CLAUDE.md (if it's generalizable)
```

## 9. Target-Specific Research

### 9.1 Read the Scope First

```
Scope -> in-scope assets / OOS / excluded bug types
Severity rules
Bounty range
Disclosed reports
```

### 9.2 Read 5 Disclosed Reports

```
Learn the program's preferences / common rejection reasons / unique vulnerability types
```

### 9.3 Triager Preferences

Read historical triager comments and learn their language.

## 10. Mindset

- Don't treat "N/A" as a failure -> it's VRT calibration data
- Getting dupe'd is a **race against time**, not a sign you can't find bugs
- Time spent writing reports = 30% of time spent finding bugs -> budget accordingly
- Quality > quantity: 10 N/As vs 3 P2s -> the latter has far higher credibility

## Related Documents

- [41-checklist-before-submit.md](41-checklist-before-submit.md) — submission checklist
- [40-checklist-new-target.md](40-checklist-new-target.md) — new target checklist
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md) — scope and quick wins
- Bugcrowd VRT: https://bugcrowd.com/vulnerability-rating-taxonomy
- Pentester Land writeups: https://pentester.land/writeups
- HackerOne Hacktivity: https://hackerone.com/hacktivity
