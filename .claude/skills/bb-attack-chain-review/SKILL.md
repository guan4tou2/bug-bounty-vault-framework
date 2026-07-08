---
name: bb-attack-chain-review
description: Use when a new finding candidate, interesting observation, info leak, auth bug, IDOR, CORS, SSRF, token leak, debug endpoint, source map, or unauth API may chain into higher impact — the lightweight review AFTER dedup that decides whether a candidate warrants escalating to the attack-chain-deep-dive agent. — distinct from bb-exploit-chain: that is the inline 6-question reflex run the moment a vuln is found; this runs after dedup to gate escalation.
---

# Bug Bounty — Attack Chain Review

Use this as the lightweight gate after dedupe and before creating or finalizing a Finding. It answers one question:

**Can this primitive reasonably chain into a stronger, in-scope impact without exaggerating evidence?**

## Trigger

Run this when:

- a candidate finding appears after recon / bbflow / manual testing
- an info leak might expose tokens, endpoints, roles, internal services, or tenant identifiers
- a low / medium issue might combine with auth, tenant, role, write, SSRF, callback, or async behavior
- a report severity feels uncertain
- the user asks "還能串嗎", "deep dive", "chain", "impact", or "深入挖掘"

## Required Inputs

- Target and scope source
- Current primitive
- Evidence already verified
- Relevant Finding / Attempt / Recon links
- Known constraints from `SCOPE.md`, `HANDOFF.md`, and `RECON_DB.md`

## Review Checklist

| Question | What to look for |
|---|---|
| Auth pivot | Can the primitive cross user, role, org, tenant, workspace, or admin boundary? |
| Data pivot | Does it reveal IDs, tokens, paths, source maps, internal hosts, object keys, or API schema? |
| Write pivot | Can read-only evidence become write, delete, invite, config change, callback, or stored effect? |
| Async pivot | Is there delayed processing, webhook, queue, email, notification, parser, import, or cron behavior? |
| Environment pivot | Does it connect SaaS, mobile, desktop, firmware, cloud bucket, CI, or internal service boundaries? |
| Fix boundary | Would the chain require a different fix than the base Finding? |
| Scope boundary | Is every proposed next step explicitly in scope and safe? |

## Output Format

```markdown
## Attack Chain Review
- Current primitive:
- Existing evidence:
- Possible pivots:
- Missing evidence:
- Safety boundary:
- Stop condition:
- Escalate to agent: yes/no
- Reason:
```

## Escalation Rules

Escalate to `attack-chain-deep-dive` only when at least one is true:

- a verified primitive crosses a trust boundary
- the next missing evidence is concrete and safe to collect
- two or more existing Findings / Attempts may form one chain
- the likely impact changes report framing or platform choice
- the chain may produce a reusable Pattern / Lesson

Do not escalate when:

- the idea is purely theoretical
- it requires unsafe write actions without authorization
- it depends on bypassing scope, rate limits, WAF, or access controls in a way not already authorized
- the base Finding already fully explains the impact

## Hard Rules

- do not upgrade severity without evidence.
- Do not execute payloads from this skill.
- Do not auto-create Submission or FORM.
- If the review fails, create or update an Attempt note instead of forcing a chain.
- If a new concept appears, run `bb-knowledge-capture`.

## Cross-References

- `.claude/agents/attack-chain-deep-dive.md`
- `bb-evidence-readiness`
- `bb-scope-safety-check`
- `bb-attempt-recorder`
- `09 - Knowledge Base/Reference Card - Knowledge Capture Quality Rubric.md`
