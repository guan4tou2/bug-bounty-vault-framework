---
name: bb-counterevidence
description: "Mandatory counterevidence gate before any Finding promotion or severity upgrade. Forces the strongest case AGAINST the finding being real or having its stated severity. Triggers: before creating Finding, before severity upgrade, before attack chain submission, before stakeholder report, 'challenge this finding', 'is this real'."
---

# Bug Bounty — Counterevidence Gate

Mandatory gate: every Finding must carry a counterevidence section before promotion to `verified` or higher. Adapted from Decepticon's counterevidence methodology — the strongest case against yourself.

## Trigger

Run before:

- Promoting a candidate to Finding (after `bb-evidence-readiness`)
- Upgrading severity of an existing Finding
- Submitting a chained attack path
- Writing a report for stakeholders
- User says "challenge this", "is this real", "devil's advocate"

## Three-Axis Challenge

For every Finding, construct the strongest counterargument across three axes:

### Axis 1: Root Cause Challenge

| Question | What it catches |
|---|---|
| Is this intended behavior or a documented feature? | Feature misread as bug |
| Is there an upstream validation layer not yet tested? | Hidden server-side control |
| Does a WAF, CDN, or gateway silently block the exploit path? | Environment-specific false positive |
| Could this be a honeypot or deception endpoint? | Canary trap |
| Is the "vulnerability" actually the security mechanism working? | Rate limit, lockout, CAPTCHA |

### Axis 2: Impact Challenge

| Question | What it catches |
|---|---|
| What is the actual blast radius? (1 user? all users? admin only?) | Impact inflation |
| What preconditions must hold for exploitation? | Unlikely prerequisite chain |
| How sensitive is the exposed data, specifically? | "PII" that is actually public profile data |
| Does the target's architecture limit lateral movement? | Contained blast radius |
| Is the impact theoretical or demonstrated in the PoC? | Unproven impact claim |

### Axis 3: Exploitability Challenge

| Question | What it catches |
|---|---|
| Does the PoC work against the production environment, not just staging? | Environment mismatch |
| Does exploitation require victim interaction? What kind? | Overstated attack complexity |
| Are there detection/prevention controls the PoC bypassed in testing but exist in prod? | Test-only bypass |
| Is the exploit timing-dependent or race-condition-based? How reliable? | Intermittent exploit |
| Could the vendor patch this with a config change vs. code change? | Mitigating factor for severity |

## Confidence Rating

After completing the three-axis challenge, assign confidence:

| Level | Criteria | Action |
|---|---|---|
| **High** | PoC confirmed on target, impact demonstrated, no mitigations found after searching | Proceed to Finding |
| **Medium** | PoC works but impact is theoretical, OR mitigations exist but can be bypassed | Proceed with caveats in report |
| **Low** | Behavior observed but exploitation unconfirmed, OR strong counterargument exists | Record as Attempt, do NOT promote to Finding |

## Output Format

Add this section to the Finding note, between Evidence and Severity:

```markdown
## Counterevidence

### Strongest case against this finding
<!-- The single best argument that this is NOT a real vulnerability or is lower severity -->

### Root cause challenge
<!-- Is this a feature? Is there an untested control? -->

### Impact challenge
<!-- Actual blast radius? Preconditions? Data sensitivity? -->

### Exploitability challenge
<!-- Works in prod? Needs interaction? Reliable? -->

### Confidence: High / Medium / Low
### Confidence rationale:
<!-- Why this confidence level, referencing specific evidence -->

### Severity change conditions:
<!-- What new evidence would raise or lower severity -->
```

## Hard Rules

- Do NOT write "None", "N/A", or "This is definitely a real vulnerability" as counterevidence — these are explicitly rejected
- The counterevidence must be SPECIFIC to this finding, not generic
- If the counterevidence is stronger than the evidence, downgrade to Attempt
- Theoretical attack chains must not be written as facts (anti-exaggeration rule)
- A finding at any severity that lacks counterevidence is not ready for submission
- Counterevidence quality is proportional to severity: Critical/High findings need deeper challenge
- If counterevidence reveals an untested control, test it before proceeding
- Severity stacking (adding CVSS scores of chained vulns) is prohibited — score the chain's final impact

## Integration Points

- After `bb-evidence-readiness` and before `bb-submission-readiness`
- When `bb-attack-chain-review` or `attack-chain-deep-dive` proposes severity upgrade
- When `cvss-adversary` agent requests counterevidence input
- Cross-reference: `bb-cvss-score` for severity calibration anchors

## Anti-Patterns (from Decepticon methodology)

1. **Fantasy chains**: untested transitions claimed as verified
2. **Severity stacking**: summing CVSS scores of individual vulns in a chain
3. **Assuming WAF blocks**: "WAF probably stops this" without testing
4. **All XSS = High**: reflected XSS with user interaction is Medium at best
5. **Theoretical RCE as Critical**: without a working PoC, downgrade
6. **Ignoring preconditions**: "full account takeover" that requires physical access to victim device
