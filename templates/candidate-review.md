# Candidate Review

Use this template for a `candidate found` that is not yet a Finding.

## Candidate Summary

- Candidate ID:
- Source:
- Target:
- Asset / endpoint:
- candidate_type:
- Initial hypothesis:
- Evidence refs:

## Scope Safety Check

- Skill: `bb-scope-safety-check`
- Status: allowed / blocked / needs-human-confirmation
- Scope source:
- GET-first status:
- Runtime:
- Stop condition:

## Exploit Chain (6 questions)

- Skill: `bb-exploit-chain`
- Q1 leaked identifier usable directly:
- Q2 read → write escalation:
- Q3 other endpoints on same system:
- Q4 reuse on other in-scope systems:
- Q5 severity escalation path:
- Q6 same root cause in other components:
- Chain result: extended / dead end / new finding

## Attack Chain Review

- Skill: `bb-attack-chain-review`
- Current primitive:
- Possible pivots:
- Missing evidence:
- Escalate to agent: yes/no
- Stop condition:

## Evidence Readiness

- Skill: `bb-evidence-readiness`
- Status: ready / not ready / needs-revalidation / attempt-only
- Missing evidence:
- Verified impact:

## Candidate Decision

- Decision: finding / attempt / drop / revisit
- Reason:
- Next action:
- Knowledge capture: `bb-knowledge-capture` destination:

