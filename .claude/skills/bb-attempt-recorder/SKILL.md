---
name: bb-attempt-recorder
description: Use when a test, hypothesis, attack chain idea, payload, endpoint, scan result, or verification path does not produce a Finding but should be recorded as a raw negative result or stop condition for THIS target. — distinct from bb-knowledge-capture: this logs a target-specific negative outcome as-is; that promotes a generalizable, reusable lesson or pattern to the KB.
---

# Bug Bounty — Attempt Recorder

Use this skill to preserve failed or inconclusive work. Good negative results prevent repeated effort and improve future decisions.

## Trigger

Run this when:

- a hypothesis was tested and disproven
- a candidate fails `bb-evidence-readiness`
- `bb-attack-chain-review` says no chain
- a scan hit is false positive / out of scope / duplicate / non-exploitable
- a safety check blocks the action
- user says "record failure", "doesn't hold", "false positive", "stop condition", or "stop for now"

## Required Fields

```markdown
## Attempt Recorder
- Target:
- Hypothesis:
- Action taken:
- Evidence observed:
- Tool/environment failure ruled out: <yes — how / no, could not rule out>
- negative result:
- Reason it did not become a Finding:
- stop condition:
- Revisit condition:
- KB update needed:
- Attempt note: created / updated / not needed
```

**"Tool/environment failure ruled out" is not optional filler.** A timeout, an empty response body, a connection reset, a dead credential, or a tool call that silently returned nothing can look exactly like a genuine negative result. Before writing "negative result: technique doesn't work" or "target is clean," check the raw evidence for a failure signature (non-2xx transport error, 0-byte body, auth-expired response) — if you can't positively confirm the probe actually executed and returned a real response, the correct entry is `inconclusive — <reason>`, not a negative result. An inconclusive attempt should still get a `Revisit condition` (e.g. "retry once tool X is confirmed working" or "retry with a fresh session token").

## Attempt Note Criteria

Create or update an Attempt note when:

- the same false positive is likely to appear again
- the test consumed meaningful time
- the result affects future scan settings or hunter logic
- a duplicate / out-of-scope / non-exploitable conclusion needs proof
- the failure teaches a Pattern / Lesson

Do not create an Attempt note for tiny dead ends that are already obvious from the current Recon note, unless they are likely to be repeated.

## Hard Rules

- Do not delete failed evidence just because it is not a Finding.
- Do not convert a negative result into a theoretical Finding.
- Do not store reusable learning only in HANDOFF.
- If a new lesson appears, run `bb-knowledge-capture`.
- If the attempt involved live action, ensure Operation Log exists.

## Cross-References

- `bb-evidence-readiness`
- `bb-attack-chain-review`
- `bb-knowledge-capture`
- `01 - Targets/<target>/Attempts/`
- `$WORKSHOP_ROOT/<target>/RECON_DB.md`

