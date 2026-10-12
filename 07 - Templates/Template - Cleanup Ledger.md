---
type: cleanup_ledger
fileClass: Note
target: "[[]]"
engagement: "{{name}}"
status: open
last_updated: "{{date}}"
tags: [redteam, cleanup, opsec, engagement]
---

<!--
Save as: 01 - Targets/<target>/Cleanup Ledger - <target>.md
automation/cleanup_ledger_gate.sh looks for a "Cleanup*Ledger*.md" file in the target
folder of an engagement-profile target and warns at session end while the status is "open".
Allowed values for the status field: open | all-removed | client-verified
-->

# Cleanup Ledger — {{name}}

> **Record everything you place in the client environment at the moment you place it.** Reconstructing it afterwards always misses something.
> The most common audit failure in an engagement is not a missed vulnerability — it is something left behind.
> The engagement is **not finished** until this ledger's status is `client-verified`.

## Implants and artifacts

| # | Time (UTC) | Host / system | Type | Identifier (path / account / ID) | Placed by | Removed at | Client confirmed |
|---|---|---|---|---|---|---|---|
| A-1 | | | file | | | | ☐ |

**Types:** file · account · scheduled task / service · registry key · ACL / policy change · credential / ticket · C2 implant · DNS record · firewall rule · database row

> Name everything with the prefix agreed in the rules of engagement (e.g. `rt-{{year}}-`) so defenders and auditors can recognise it at a glance.

## Configuration changes (what changed, and the original value)

| # | System | Setting | Original value | Changed to | Restored at | Client confirmed |
|---|---|---|---|---|---|---|
| C-1 | | | | | | ☐ |

> **No recorded original value means no restore.** Read the setting before changing it and write the value here on the spot.

## Credentials and data obtained (to be destroyed)

| # | Content | How obtained | Storage location | Destroyed at | Client confirmed |
|---|---|---|---|---|---|
| D-1 | | | local encrypted volume | | ☐ |

> Client data stays local. Do not upload it to third-party services — that includes online hash cracking, rented cloud GPUs, and hosted AI services.

## Close-out checks

- [ ] All implants and artifacts removed and confirmed by the client.
- [ ] All configuration changes restored to their original values.
- [ ] All credentials and data destroyed, and the destruction method communicated to the client.
- [ ] This ledger attached to the report so the client can review it independently.
- [ ] Anything that could not be removed is listed explicitly and communicated in writing (with reason and residual risk).
- [ ] Frontmatter `status` updated (`all-removed` → `client-verified`).
