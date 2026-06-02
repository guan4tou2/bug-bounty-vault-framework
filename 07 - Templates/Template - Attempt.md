---
fileClass: Attempt
target: "[[]]"
vuln_class: ""
title: ""
attempt_date: <% tp.date.now("YYYY-MM-DD") %>
attempt_time: <% tp.date.now("HH:mm") %>
hours_spent: 0
result: "exploitable | not_exploitable | inconclusive | blocked | parked"
result_reason: "prerequisite_unmet | waf_blocked | no_session | not_in_scope | duplicate_likely | other"
prerequisite: ""
killed_at: ""
should_retry_when: ""
related_recon: []
related_pattern: []
upgraded_to_finding: ""
tags: []
---

# Attempt — {{TARGET}} — {{TITLE}}

> **Discovery note**: An Attempt is a discovery note like a Finding; use canonical English H2 headings (AGENTS.md §3b).
> Discovery Log five columns: time / source IP / target IP / `[audit:SESSION8@HH:MM:SS]` / action.

## Summary

> What were you trying to do? 1-2 line conclusion (exploitable / not exploitable / blocked / prerequisite unmet)

---

## Discovery Log

> Timeline of the Attempt (same five-column format as Finding)

- `YYYY-MM-DD HH:MM` `[source IP → target IP]` `[audit:SESSION8@HH:MM:SS]` what was done, what was observed
- `YYYY-MM-DD HH:MM` `[source IP → target IP]` `[audit:SESSION8@HH:MM:SS]` further observation / bypass tried / conclusion

---

## Reasoning

- Initial hypothesis:
- Why you thought this would work:
- Why it ultimately did not hold:

---

## Why Stopped

> State the specific gate / prerequisite to avoid repeating the same path next time.

- **Direct cause:** (e.g., endpoint requires Bearer token; no cookie session available)
- **Prerequisite unmet:** (e.g., requires victim already logged into a specific subdomain, but subdomain does not allow takeover)
- **Program rules:** (e.g., large programs are known to N/A theoretical CORS findings — see [[Lessons Learned]])
- **Time cost exceeds expected return:** (hours_spent vs. estimated bounty)

---

## Partial Evidence

> Observations worth keeping even though the Attempt did not succeed (fingerprints / WAF behavior / indirect evidence / potential chain pivot)

```bash
# Key command snippet
```

- Endpoint X returned status code Y
- WAF behavior: blocks `<script>` but not `<svg/onload=>`
- Rate limit present / absent
- Screenshot: [[../poc/...]]

---

## Lessons Learned

- **New Pattern candidate?** Yes / No — link [[Pattern - ...]]
- **Update Lessons Learned?** Yes / No
- **Applicable across other targets?**

---

## Re-attempt Conditions

> Under what circumstances would you restart this direction? ("Unless...")

- Unless `<prerequisite>` changes
- Unless new source maps / new endpoints are available
- Unless program policy changes

---

## Related

- Target: [[]]
- Recon: [[]]
- Related Pattern: [[]]
- Upgraded to Finding? [[]] (if applicable)
