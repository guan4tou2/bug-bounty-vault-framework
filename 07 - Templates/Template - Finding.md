---
fileClass: Finding
finding_id: ""
target: "[[]]"
host: ""
platform: ""  # Leave blank; platform is decided at FORM stage (see AGENTS.md §3e.1)
vuln_class: ""
cwe: ""
cvss: ""
severity: "P1 | P2 | P3 | P4 | P5"
risk: "critical | high | medium | low | info"
verification_level: "A | B | C | D"
verified_evidence: "live | source_code | static | theoretical"
status: "discovered | verified | ready | submitted | duplicate | na | accepted | fixed | on_hold | killed"
discovered_date: <% tp.date.now("YYYY-MM-DD") %>
discovered_time: <% tp.date.now("HH:mm") %>
last_verified: <% tp.date.now("YYYY-MM-DD") %>
hours_spent: 0
chain: false
related_recon: []
related_attempts: []
related_pattern: []
helped_by: []   # which KB artifacts led to this finding (Pattern/Playbook/Checklist/LL ids); empty = original. Effect loop, see automation/kb_roi.sh
related_submission: ""
dedupe_checked_at: <% tp.date.now("YYYY-MM-DD HH:mm") %>
dedupe_query: ""
dedupe_hits: []
tags: []
---

# Finding — {{TARGET}} — {{TITLE}}

> **Discovery note only**: A Finding records how you found the issue, how you verified it, and your reasoning at the time.
> Write the formal external report in `Submissions/Submission -*.md` and `FORM -*.md`.
>
> **Section rules** (see AGENTS.md §3b):
> - **Must-have**: Summary / Discovery Log / Reasoning / Evidence / Impact / Follow-up
> - **Nice-to-have**: Related / Vulnerable Code / Remediation / CVSS / Verification Status — include only if there is content
> - H2 headings must be in English; body text may be in any language
> - Delete any section you do not need — do not leave empty shells

## Summary

One paragraph: what + current state + why it matters. Include only the key information needed for a discovery note.

| Field | Value |
|------|-----|
| Target | `[[]]` |
| Host | |
| Finding ID | |
| Status | |
| Severity | |
| Verification | |
| Discovered | {{date}} {{time}} |

---

## Discovery Log

> **Required five columns**: local time / source IP (local machine or VPS) / target IP (resolved via dig) / audit ref (`[audit:SESSION8@UTC_HH:MM:SS]`, matching §6f Bash audit log) / action + result. See AGENTS.md §3b + §6f.
>
> Retrieve audit ref: `head -1 logs/claude_audit_$(date -u +%Y%m%d).log` (use first 8 chars of the session ID)

- `YYYY-MM-DD HH:MM` `[source IP → target IP]` `[audit:XXXXXXXX@HH:MM:SS]` what was done, what was observed, why proceeding to next step
- `YYYY-MM-DD HH:MM` `[source IP → target IP]` `[audit:XXXXXXXX@HH:MM:SS]` which hypothesis was confirmed / which was ruled out

<!-- Example:
- `2026-05-16 14:32` `[114.45.x.x → 203.69.x.x]` `[audit:d2addc4f@06:32:18]` curl GET /api/users/1 with own cookie, returned 200 + own data
- `2026-05-16 14:48` `[114.45.x.x → 203.69.x.x]` `[audit:d2addc4f@06:48:05]` changed user_id=2, returned 200 + another user's PII -> IDOR confirmed

To replay "what command was used at this step" during a future takeover:
  grep "session:d2addc4f.*06:48:05" logs/claude_audit_20260516.log
-->

---

## Reasoning

- Initial hypothesis:
- Reason for pivoting mid-way:
- Ideas worth picking up next session (not yet verified):

---

## Evidence

> **Required: complete, directly runnable curl / payload** (not just the response). Include headers / cookies / payload.

```bash
# Key curl / payload / query / grep (fully reproducible)
curl -i 'https://target/api/endpoint' \
  -H 'Cookie: session=...' \
  -H 'Content-Type: application/json' \
  -d '{"...":"..."}' | jq
```

- Response snippet / screenshot path:
- PoC file location:

---

## Impact

**Verified (proven by PoC):**
-

**Potential (requires additional conditions, low confidence; delete this section if unsure):**
- _Prerequisite:_

---

## Follow-up

- Corresponding Submission:
- Status (submitted / withdrawn / superseded / needs-revalidation):
- Next steps:

---

## Related

- Target: [[]]
- Pattern: [[]]
- Submission / FORM: [[]]
- Recon: [[]]
- Attempt: [[]]
- Attack Chain: [[]]

---

<!-- ====== Sections below are nice-to-have; delete the entire section if there is no content ====== -->

## Vulnerable Code

> Paste only the problematic segment, with file path and line numbers.

```
// file: path/to/file, line 120-145
```

## Remediation

-

## CVSS

`AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_` → Score N.N

## Verification Status

- [ ] HTTP response confirmed
- [ ] Source code confirmed
- [ ] Live PoC executed (non-destructive)
- [ ] Screenshot / video captured

---

## Dedupe Gate

```bash
bash automation/vault_precheck.sh <target> "<keyword>" "<host_or_endpoint>"
```

- Match summary:
- Why this is not a duplicate (if matches found):

## Tasks

- [ ] #task @<target> Write up as formal FORM
- [ ] #task @<target> Add screenshots
