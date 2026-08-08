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

> 目的：定義 Vault 與 workspace 的 evidence 邊界，避免 raw scan output、大檔、secret-bearing evidence 被 commit，同時保留報告需要的可追溯證據。

---

## Boundary

| Evidence type | Location | Rule |
|---|---|---|
| Canonical reproduction steps | Finding / Submission / FORM | Vault keeps canonical evidence summaries |
| Minimal curl / request shape | Finding Evidence | 可進 Vault；去除 secrets |
| Raw scan output | external workspace | workspace keeps raw artifacts |
| PoC bundle / exploit script | external workspace `poc/` | 只在 Vault 放 path + hash |
| Rootfs / binary extraction | external workspace | 不進 Obsidian / git |
| Screenshots | Vault only if small and sanitized | screenshots allowed in Vault only when sanitized |
| Token / cookie / credential response | external workspace or redacted summary | secret-bearing evidence 不 commit |

---

## Vault Evidence Requirements

Vault 裡應保留：

- 足夠重現的步驟。
- sanitized request / response excerpt。
- impact explanation。
- hash and path reference to raw artifact when needed。
- audit ref 或 operation log reference。

Vault 裡不保留：

- do not commit raw scan output。
- full credential dump。
- unredacted cookies / tokens / API keys。
- large binary / rootfs / tool cache。
- vendor private資料超出報告必要範圍。

---

## Redaction Checklist

redaction checklist：

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
