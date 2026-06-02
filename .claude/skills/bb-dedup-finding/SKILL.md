---
name: bb-dedup-finding
description: Use when opening a new Finding or FORM, checking duplicate likelihood, deciding whether to merge reports, handling same endpoint/different user evidence, or user says "wasn't this already found" / "same vulnerability" / "should I merge". Triggers: 這不是挖過了嗎/同一漏洞/該不該合併
---

# Bug Bounty — Duplicate Finding Determination (§3f Rules + 6 Steps)

> **Promoted from AGENTS.md §3f to a standalone skill (2026-05-16):** "Must pass this check before opening a new Finding/FORM" and "user suspects a duplicate" are high-frequency triggers. A standalone skill guarantees this fires every time.

## Core Question (single test)

**"Could a single commit fix all the PoCs at once?"**
- YES → Same vulnerability; **merge into 1 report** (list all endpoints + representative PoCs + company list in an appendix)
- NO → Different vulnerabilities; submit separately

## §3f.1 Decision Tree — Three Questions (in order)

| Q | Question | Yes | No |
|---|----------|-----|----|
| Q1 | Same backend code path? (same missing auth check / same IDOR field) | → Q2 | Not a duplicate; submit separately |
| Q2 | Can a single fix repair all of them? | **Merge into 1 report** | Submit separately (e.g., same host but SSRF + IDOR are different root causes) |
| Q3 | What changed? | | |
|    | Changed sub-endpoint / changed HTTP method | **Merge** | — |
|    | Changed query string pulling different company / different user_id | **Merge** (enumeration evidence) | — |
|    | Changed host (PROD ↔ SIT ↔ DEV, same backend) | **Either** (some platforms allow separate submissions; conservative choice is to merge) | — |
|    | Changed backend / different auth system / different fix required | — | **Submit separately** |

## §3f.2 Three Common Scenarios

| Scenario | Example | Action |
|----------|---------|--------|
| **Same missing auth, different sub-endpoints** | `/api/v1/{alpha,beta,gamma}` all skip the `planner_id` check | Merge into 1; list endpoints in a table; pick 1 read + 1 write as representative PoCs |
| **Same backend code, different hosts** | PROD `api.example.com` + SIT `api-sit.example.com` share the same `/data/v1/*` handler | Merge into 1 (list under `## Affected Hosts`); or submit separately with mutual cross-references |
| **Different root causes, happen to share a host** | Same service has both IDOR and SSRF | **Submit separately** (different fixes required) |

## §3f.3 "Different Company / Different user_id" Is Almost Never a New Finding

- Changing the query string to pull a different victim = **enumeration evidence** for the same vulnerability, not a new finding
- Write it up by adding all confirmed companies/users to an appendix table (strengthens severity; do not split into N reports)
- Exception: if different victims correspond to **different backends / different permission models** → count separately

## §3f.4 Merged Report Template

```markdown
## Affected Endpoints (same root cause)
| Endpoint            | Action          | Verified |
|---------------------|-----------------|----------|
| /api/v1/alpha       | Read CRM data   | YES      |
| /api/v1/dispatcher  | Read CRM data   | YES      |
| /api/v1/beta        | Write report    | YES      |
| /api/v1/gamma       | Read + Write    | YES      |

## PoC (2 representative examples)
1. **Read**: alpha endpoint — retrieved customer records for victim org
2. **Write**: beta endpoint — injected data with planner_id=99999

## Enumerated Victims (appendix — strengthens severity)
Org-A / Org-B / Org-C / Org-D / ...
```

## §3f.5 Withdrawal / Merge Process (mandatory)

When N reports are determined to be the same vulnerability and must merge into 1:

1. **Pick the primary ID**: priority = submitted > ready_to_submit > needs_revalidation > draft; at the same stage, pick the highest severity
2. **Rewrite the primary report**: merge endpoint list + PoCs + victim appendix; take the highest severity (read+write combined typically upgrades to P1); add `components: [<merged IDs>]` and `merged_date` to frontmatter
3. **Merged-away reports**:
   - Append `(superseded by #N)` suffix to the filename
   - Set frontmatter `status: withdrawn` (use `withdrawn`, not a new `superseded` value — consistent with the index filter logic used elsewhere)
   - Add frontmatter: `superseded_by: <primary ID>`, `superseded_date`, `superseded_reason`
   - Keep the file; do not delete (useful for later reference)
4. **Sync RECON_DB / FINDINGS_QUICK_REF**: regenerate FINDINGS_QUICK_REF (if your setup provides an index generator)
5. **Commit message**: `refactor(<target>): merge #A/#B/#C → #N (root cause: <one-line summary>)`

> **Why `withdrawn` instead of `superseded`:** The index / FINDINGS_QUICK_REF pipeline already has `withdrawn` filter logic. Adding a new `superseded` value increases schema complexity. The `superseded_by` field already records the merge relationship; a separate status value is not needed.

## §3f Pre-check Before Opening a New Finding (mandatory)

Any agent must run these steps before creating a new Finding or FORM:

```bash
# 1. Read FINDINGS_QUICK_REF — check whether the root cause is already covered
cat workspace/workshop/<target>/FINDINGS_QUICK_REF.md | grep -i "<keyword>"

# 2. Run vault_precheck — endpoint / host comparison
bash automation/vault_precheck.sh <target> "<endpoint or host>" "<service>"

# 3. Self-audit using the §3f.1 three-question decision tree
```

Any match → stop creating a new Finding; switch to the "merge" or "Attempt" workflow instead.

## Handling "Wasn't This Already Found?" — SOP

Red flag: user says "wasn't this already found?" / "we already dug this" → **stop immediately**, **do not continue hunting**, and do the following:

1. Read `workspace/workshop/<target>/FINDINGS_QUICK_REF.md` (and the parent target's QUICK_REF if this is a sub-target)
2. List **all** Finding IDs that cover this area
3. Classify:
   - **True duplicate** (same endpoint + same technique + same finding) → STOP; ask the user what new area to investigate
   - **New information on a known endpoint** (new credential / new path / new behavior, not yet in RECON_DB) → Not a dup; **explicitly state** "[ID] covers this endpoint, but [X] is new"; update RECON_DB, then continue
   - **Attack chain** (known A + new B = new impact) → Not a dup; **explicitly state** "I'm using [Finding ID] + this new discovery to build a chain; goal is [Z]"; state the chain goal first, then continue

**Prohibited pattern:** saying "I'm using it for a different purpose" WITHOUT naming a specific new piece of information or a concrete chain goal → this is a rationalization red flag = duplicate → STOP

See also `09 - Knowledge Base/Lessons Learned.md` for lessons on duplicate root-cause judgment and goal-shifting rationalization.

## Cross-reference

- AGENTS.md §3f (promoted to this skill)
- `09 - Knowledge Base/Lessons Learned.md`
- automation/vault_precheck.sh
- `workspace/workshop/<target>/FINDINGS_QUICK_REF.md`
