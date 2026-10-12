---
type: attack_narrative
fileClass: Note
target: "[[]]"
engagement: "{{name}}"
last_updated: "{{date}}"
tags: [redteam, narrative, attack-chain, engagement]
---

# Attack Narrative — {{name}}

> The core of an engagement report. **Executives read this, not the finding table.**
> The per-finding table still goes in whatever reporting format the client requires; the two complement each other and neither replaces the other.
> For the technical chain of individual findings, use [[Template - Attack Chain]]; this page tells the story end to end.

## One sentence

> From \<starting position\>, within \<time\>, we reached \<objective\>; the decisive weakness was \<single weakest link\>.

## Timeline

| # | Time (local / UTC) | Phase | Action | Result | Finding | ATT&CK |
|---|---|---|---|---|---|---|
| 1 | | Initial Access | | | {{finding_id}} | T1190 |

> Every row must trace back to an entry in the target's **Operation Log** (`RECON_DB.md ## Operation Log`, AGENTS.md §6d).
> Use MITRE ATT&CK technique IDs for the last column.

## Attack chain diagram

```
External, unauthenticated   Foothold            Lateral movement     Objective
─────────────────────       ─────────           ────────────────     ─────────
 <entry point>        →     <what we got>  →    <how we moved>  →    <objective>
 {{finding_id}}             {{finding_id}}      {{finding_id}}       OBJ-1
```

## Decisive links (what the defender should fix first)

| # | Link | If blocked here, does the whole chain break? | Fix cost |
|---|---|---|---|
| 1 | | yes / no | low / medium / high |

> **Chain-breaking points are worth more than a vulnerability count.** The client wants to know which single fix buys the most.

## Anti-exaggeration statement (AGENTS.md §5)

| Claim | Evidence actually observed | Unverified inference |
|---|---|---|
| | | |

> Split every "we could do X" into "done, with evidence" and "theoretically possible, not executed".
> Anything not executed does not go in the timeline.
