---
type: playbook
title: "Ultimate Guide to Red Teaming (Bugcrowd Summary)"
tags: [red-team, methodology, framework, mitre-attack, kill-chain, purple-team, ttps]
status: draft
last_updated: 2026-08-12
category: hunting
estimated_time: "20-30 min reading/reference"
---

# Playbook - Ultimate Guide to Red Teaming (Bugcrowd Summary)

> **TL;DR**: Red teaming traces back to 1960s RAND Corporation Cold War wargaming, where Soviet forces were marked red and friendly forces blue — the red-team-vs-blue-team framing has persisted ever since. Unlike bug bounty or standard pentesting, a red team engagement is fully adversarial, open in scope, and typically conducted without the defending (blue) team's knowledge. This playbook summarizes the four-phase red team kill chain (IN -> THROUGH -> OUT -> ASSESS), the common governing frameworks, and how red-team thinking translates into stronger bug-bounty reporting.
>
> Source: adapted from Bugcrowd's "Ultimate Guide to Red Teaming" (bugcrowd.com, published 2025-04).

## Scope / When to use

Use this playbook as a reference when: (a) planning or participating in an actual red team engagement, (b) evaluating whether a finding or set of findings should be written up as an attack-chain narrative rather than a single-vulnerability report, or (c) explaining to a client/stakeholder how red teaming differs from penetration testing or bug bounty in scope, adversarial posture, and depth.

**Red teaming vs. other security testing types**

| Method | Scope | Adversarial | Depth | Stealth |
|---|---|---|---|---|
| **Red Teaming** | open | fully adversarial | deep | blue team is unaware |
| Pen Testing | specific functionality | partial | medium | none |
| Bug Bounty | open (usually) | does not assess impact | broad but shallow | none |
| VDP | open (usually) | does not assess impact | broad but shallow | none |

**Purple Team** = a non-stealthy variant of red teaming:
- **Collaborative**: the blue team communicates with the red team in real time to validate detection/response processes.
- **Passive**: the blue team observes red-team activity but does not communicate during the engagement.

## Phases

### Phase 1: IN (initial access)

Goal: obtain initial access to the target system.

OSINT collection categories:

| Category | What to collect |
|---|---|
| Organization | building locations, team structure, business units, phone numbers, email, core products |
| Employees | email addresses, phone numbers, LinkedIn profiles |
| Tech stack | technology vendors, email configuration, public IPs, open ports |
| OSINT | historical breaches, credential dumps, public vulnerabilities |

Attack-vector design:
- Combine multiple vulnerabilities, misconfigurations, social engineering, and legitimate tooling.
- Settle on an initial-access vector, a threat-actor persona, and a target.
- Keep adjusting the vector as the engagement progresses.

### Phase 2: THROUGH (lateral movement)

Goal: move laterally within the system/network/organization and escalate privileges.

Common techniques:
- Phishing employee accounts.
- Exploiting cloud misconfigurations.
- **Chained attacks**: each vector provides a small privilege increment that accumulates toward the objective.

### Phase 3: OUT (impact simulation)

Goal: demonstrate plausible real-world damage without actually causing it.

Impact simulation examples:
- Deploying ransomware scoped to encrypt only specific test files.
- Accessing an executive's email account.
- Simulating exfiltration of key user data.

After execution: **clean up** — remove any Indicators of Compromise (IoCs) left behind.

### Phase 4: ASSESS (reporting)

A red team report must include:
- **Attack narrative**: every attempt made, including failed ones.
- **Root cause issues**: the vulnerabilities found and their underlying root causes.
- **Defense-bypass details**: how existing defenses were circumvented.
- **A complete attack-chain diagram** (graph format, showing the attack path chronologically).
- **Remediation recommendations**: specific guidance for each root cause.

The report's goal is to give the security team a complete understanding of "how we got in," turning the engagement into a security roadmap for the whole organization.

## Decision Points

**Governing frameworks**

*MITRE ATT&CK*
- 14 tactic categories, each with specific techniques underneath.
- Example lateral-movement techniques: internal spearphishing, remote service session hijacking.
- **When to apply it**: for post-engagement classification, not during the engagement itself (which needs creativity, not a checklist).
- Benefit: standardizes communication, making it easy for triagers/stakeholders to understand findings.

*CBEST (UK financial sector)*
- Four phases: Initiation -> Threat Intelligence -> Penetration Testing -> Closure.
- Pioneered the "intelligence-led red team assessment" model.
- Spawned related frameworks: iCAST, CORIE, TIBER.

*Other frameworks*

| Framework | Applicable domain |
|---|---|
| Lockheed Martin Cyber Kill Chain | general purpose |
| ICS-CERT | industrial control systems |
| DORA | EU financial digital resilience |
| TIBER-EU | EU financial-sector threat-intelligence-led red teaming |

**Advantages and challenges of red teaming**

Advantages:
- Simulates real threat-actor TTPs.
- Surfaces cross-system root-cause issues, not just isolated bugs.
- Gives the blue team practice at detection/response/recovery.
- Continuous testing rather than a traditional single point-in-time assessment.
- Red-blue interaction improves both sides' capability (the Purple Team effect).

Challenges:
- Hard to find a red team with sufficiently broad attack-surface skills.
- A static red team may not fit a specific attack surface well.
- Boutique consultancies are expensive and slow.
- Consultants typically can't help with remediation after the engagement ends.

**How red-team thinking applies to bug bounty**

| Dimension | Bug Bounty | Red Team |
|---|---|---|
| Goal | find a vulnerability | demonstrate a full attack chain and its impact |
| Scope | defined by the platform | open |
| Report | single vulnerability | complete attack narrative |
| Continuity | per-vulnerability | continuous engagement |
| Impact | technical impact | business impact (ransomware, data exfiltration) |

Practical takeaways for bug-bounty work:
- Attack-chain reports — combining multiple findings into one narrative rather than reporting each in isolation — approximate red-team thinking and tend to land higher severity/payout.
- Don't stop at reporting a single vulnerability; where possible, chain findings into a complete attack path.
- Borrow the attack-narrative style in reports: a chronological record including failed attempts, not just the final successful step.
- MITRE ATT&CK classification can add professionalism and clarity to a bug-bounty report, especially for chained findings.

## Expected Outputs

- (Formal red team engagement) an attack narrative, root-cause list, defense-bypass documentation, an attack-chain diagram, and remediation recommendations.
- (Bug-bounty application) a decision on whether a set of related findings should be written up as a single chained report rather than separate single-vulnerability reports, plus a chronological narrative draft if so.

## Related

- [[Playbook - API Attack Surface]]
- [[Checklist - XSS Rat 2026]]
