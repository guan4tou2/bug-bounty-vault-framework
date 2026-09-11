---
fileClass: ReferenceCard
type: reference-card
title: Evidence Retention Policy
last_updated: 2026-05-22
tags: [evidence, retention, vault, workspace, sensitive-data, bb-referencecard]
source: internal
added: 2026-05-22
---

# Reference Card - Evidence Retention Policy

> Purpose: Define the evidence boundary between the Vault and the workspace, preventing raw scan output, large files, and secret-bearing evidence from being committed, while retaining the traceable evidence that reports require.

---

## Boundary

| Evidence type | Location | Rule |
|---|---|---|
| Canonical reproduction steps | Finding / Submission / FORM | Vault keeps canonical evidence summaries |
| Minimal curl / request shape | Finding Evidence | May go in the Vault; strip secrets |
| Raw scan output | external workspace | workspace keeps raw artifacts |
| PoC bundle / exploit script | external workspace `poc/` | store only path + hash in the Vault |
| Rootfs / binary extraction | external workspace | does not go into Obsidian / git |
| Screenshots | Vault only if small and sanitized | screenshots allowed in Vault only when sanitized |
| Token / cookie / credential response | external workspace or redacted summary | do not commit secret-bearing evidence |

---

## Vault Evidence Requirements

The Vault should retain:

- Steps sufficient to reproduce.
- sanitized request / response excerpt.
- impact explanation.
- hash and path reference to raw artifact when needed.
- audit ref or operation log reference.

The Vault should NOT retain:

- do not commit raw scan output.
- full credential dump.
- unredacted cookies / tokens / API keys.
- large binary / rootfs / tool cache.
- vendor private data beyond what the report requires.

---

## Redaction Checklist

redaction checklist:

- [ ] token / cookie / bearer / session id removed
- [ ] private IP only kept if directly relevant and scoped
- [ ] customer / tenant data minimized
- [ ] screenshot cropped or blurred if needed
- [ ] raw artifact path points to workspace, not Vault
- [ ] hash recorded when raw artifact matters

---

## Related Notes

- [[Reference Card - Testing Safety Rules]]
- [[Reference Card - Workflow State Machine and Gates]]
- [[Reference Card - New Target and Finding Creation SOP]]
- [[Wiki Schema]]
