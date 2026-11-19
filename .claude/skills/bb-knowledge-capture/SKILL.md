---
name: bb-knowledge-capture
description: Use when a session, finding candidate, failed attempt, attack chain review, tool result, triage reply, or new observation teaches something reusable that should update Pattern, Lessons Learned, Checklist, Tool notes, or bbflow templates — promotes a GENERALIZABLE lesson/pattern to the KB. — distinct from bb-attempt-recorder: that records a raw target-specific negative result; this promotes reusable knowledge across targets.
---

# Bug Bounty — Knowledge Capture

Use this gate as soon as reusable learning appears. Do not wait for session close or context compaction.

## Trigger

Run this when:

- a new technique, bypass, failure mode, chain idea, triage lesson, or tool behavior appears
- `bb-attack-chain-review` identifies a reusable pivot
- `bb-attempt-recorder` records a useful negative result
- a Recon note's Knowledge Capture Gate needs content
- a bbflow / hunter / Nuclei / BBOT / Osmedeus idea should be generalized

## Classification

| Destination | Use when |
|---|---|
| `Pattern - *.md` | Reusable attack technique or detection logic |
| `Lessons Learned.md` | Decision, pitfall, false positive, triage lesson, stop condition |
| `Checklist - *.md` | Repeatable review gate |
| `Playbook - *.md` | Multi-step workflow |
| `05 - Tools/` | Durable tool usage note or configuration rationale |
| [[Backlog - Experience to Tool]] | Rule-detectable pattern → queue to crystallize into a nuclei template / hunter / RE script (the living-scanner feed point) |
| Attempt note | The main value is a negative result for one target |

## Sedimentation Pool Model (capture → settle → crystallize → classify → drain)

> **Do not classify at capture time.** At capture you cannot tell whether an observation is hunting experience, process discipline, or one-off noise; minting a formal LL on the spot is exactly what produces mis-filed lessons and a flood of zero-citation entries. Drop it in the pool first, and **fish it out once it takes shape.**

**The pool = four existing low-cost holding layers (don't create new ones; treat them as one):**

| Pool | What settles here |
|---|---|
| `bb-attempt-recorder` (target Attempt) | Raw negatives / attempts for a single target |
| `Ledger - <class> Tried.md` | Commands / payloads already tried |
| [[Backlog - Experience to Tool]] | Mechanizable candidates |
| Auto-memory "reminders without a home yet" | Noise that has not found a destination |

**Three valves (in / crystallize / drain):**

1. **In (dump mindlessly):** at capture, drop it into the matching pool — **no classification, no ID** — at near-zero cost.
2. **Crystallize (classify only after fishing it out):** when the same root cause accumulates **≥2 cases and a stable shape** in the pool → only then classify and assign an ID. Classify with three questions:

   | Question | → Experience (LL / Pattern) | → Process (skill / gate) |
   |---|---|---|
   | About what? | How a target / system / triager behaves | How we do it every time |
   | How used? | Recalled when a situation arises | Auto-enforced every time |
   | Needs judgment? | Yes — read the situation | No — run deterministically |

   Answers lean left → experience layer; lean right → process layer; **inconsistent = two things, split them.**

3. **Drain (flush):** zero citations + first seen > 6 months ago → archive (set frontmatter `status: archived`; it drops out of retrieval, git keeps the history).
   Detection: `automation/uvrun python3 automation/lesson_citation_report.py --stale` (wired into `vault_maintenance.sh`).
   This is the pool's **only exit**; without it, a pool that only fills and never empties is the root cause of lesson-count explosion.

**Graduation edge (experience → process, usually partial):** the slice of a lesson that **can be written as a deterministic check with an acceptable false-positive rate** graduates to a gate; **the judgment core stays in the original LL.** Test: can you write a deterministic check? → that slice graduates; cannot? → it stays in the experience layer. (The existing "write a gate on the third occurrence" rule is the graduation trigger — but only for the slice that can graduate; the judgment residue stays put.) Example: "don't overclaim when impact only reaches public data" graduates into a submission impact-sentence gate; "does this data count as a paid tier" is a judgment call and stays in its lesson ([[LL-412]]).

> ⚠️ **Split process vs experience first (the three questions), then decide how to fill fields** — a "mandatory mechanization path" field only holds for *process* lessons. Forcing a pure hunting-experience lesson to produce a mechanization path only yields a bad gate or a filler field.
>
> A *process* lesson (how we act every time, runnable deterministically) must state a concrete enforcement path; if it cannot, mark it honestly as `reference` rather than let it pose as a control. An *experience* lesson (truth about a target/technique, judgment + recall) fills that field with `N/A: judgment-recall` — a complete answer, not an unfinished one — and is not downgraded to reference. Its quality bar is instead (1) a strong `trigger:` (zero-citation entries usually die from a bad trigger, not from not deserving to exist), and (2) graduating any mechanizable slice to a gate via the graduation edge.

## Output Format

```markdown
## Knowledge Capture
- Reusable learning:
- Existing KB coverage:
- Destination:
- New note needed: yes/no
- Pattern / Lesson / Checklist update:
- tool crystallization (rule-detectable → append to [[Backlog - Experience to Tool]], tag domain + target format nuclei/hunter/RE; skip judgment-needed ones):
- Recon note link:
- Done:
```

## Existing Coverage Check

Before saying no new Lesson is needed:

1. Read the closest Pattern / Lesson.
2. Ask whether another agent could reproduce this insight from the existing text.
3. If not, create a new Lesson or update the Pattern.

## Hard Rules

- New concept must become a new Lesson or an explicit Pattern update.
- HANDOFF is not KB; do not store reusable learning only in HANDOFF.
- If context is getting long, write the Recon note and KB delta now.
- Sanitize target-specific secrets, tokens, customer names, and private endpoints before promoting to KB or bbflow.
- Do not update bbflow with target-specific or sensitive data.

## Cross-References

- `AGENTS.md Knowledge Capture Gate`
- `09 - Knowledge Base/Reference Card - Knowledge Capture Quality Rubric.md`
- `09 - Knowledge Base/Wiki Schema.md`
- `bb-attempt-recorder`

