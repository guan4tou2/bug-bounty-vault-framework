---
fileClass: Target
type: target
status: hunting
org: "{{competition-org}}"
domain: ""
platform: "competition"
category: competition
target_kind: competition
competition_id: "{{competition_slug}}"
competition_start: "{{YYYY-MM-DD}}"
competition_end: "{{YYYY-MM-DD}}"
scoring_rules: "{{e.g., 80% CVSS + 20% completeness; same system merges}}"
team: "{{team-name}}"
team_account: "{{handle}}"
ip_constraint: "{{台灣 IP / VPS allowed yes/no}}"
risk: medium
first_seen: "{{YYYY-MM-DD}}"
external_findings_count: 0
external_withdrawn_count: 0
teammate_findings_count: 0
---

# {{Competition Name}}

> Competition-specific target. Findings tracked here use `external_id` (platform ID like `HT0218`) as the dedup key, not vault-internal Finding IDs. **KB-purity rule: competition specifics MUST NOT enter `09 - Knowledge Base/`** (audit kb-purity §16b enforces).

## 1. Snapshot

| Item | Value |
|------|-------|
| Competition | {{name}} |
| Period | {{start}} ~ {{end}} |
| Portal | {{URL}} |
| Scoring | {{rules}} |
| Team | {{team}} |
| Status | 🏃 Hunting |

## 2. External Findings(platform IDs)

> Each row = 1 platform-side report. Linked via `external_id`. Vault Finding files (if any) live in `Findings/` and reference `external_id` in frontmatter.

| # | external_id | hostname | vuln_class | CVSS | status | root_cause(short) |
|---|---|---|---|---|---|---|
| 1 | (none yet) | — | — | — | — | — |

## 3. Withdrawn / Out-of-Scope

| external_id | reason |
|---|---|
| (none) | — |

## 4. Teammate / Other Researchers

> Public-side findings from other competitors — read for dedup. Source: platform feed.

| external_id | researcher | hostname | vuln_class | dedup_note |
|---|---|---|---|---|
| (none) | — | — | — | — |

## 5. Disclosed Pre-Read

`bash automation/check_disclosed_preread.sh {{target}}` should return ✅ before any candidate is opened. Evidence file: `$WORKSHOP_ROOT/{{target}}/disclosed_pre_read.md`.

## 6. Session Log

| date | session | actions | result |
|---|---|---|---|
| {{YYYY-MM-DD}} | — | — | — |

## 7. KB Purity Boundary

What goes WHERE:
- 競賽-specific（scoring/rules/platform IDs/teammate findings）→ this file or memory
- 抽象化教訓（攻擊模式、推論方法）→ `09 - Knowledge Base/Lessons/LL-NNN-*.md`
- 工具配方（generic、不限本競賽）→ `09 - Knowledge Base/Pattern - / Playbook -`

## Related

- [[Checklist - Disclosed Findings Pre-Read Gate]] — mandatory before hunt
- [[Playbook - Trigger Chain Dry-Run]] — pre-hunt 紙上跑
- `automation/check_disclosed_preread.sh` — evidence file gate
- `automation/skill_gap_matrix.sh` — Step 3 矩陣產出
- `automation/dedup_hints.sh` — Step 5 dedup 前手動 grep
