---
name: bb-triage-response
description: Use when user pastes triage replies or says Accepted, Duplicate, N/A, Informative, Triaged, Resolved, bounty result, severity decision, vendor reply, or triage result.
---

# Bug Bounty — Triage Response Handling

> High-frequency trap: when a user pastes a triage reply, the tendency is to discuss the result without updating any files. This skill forces a multi-location sync to prevent state drift.

## Trigger Red Flags

Any of the following phrases must trigger this skill:
- "triage reply / result"
- "N/A" / "Duplicate" / "Triaged" / "Accepted" / "Informative" / "Resolved"
- "vendor reply / bounty / VRT verdict"
- Pasting a disclosure-channel or vendor comment

**Prohibited: discussing the triage result without syncing the files.**

## Mandatory Sync Order (Submission → Kanban → Target hub → Dashboard → KB → commit)

All paths are relative to the vault root (repo root directory).

### 1. `01 - Targets/<target>/Submissions/Submission - <target> - <ID>.md`

Update frontmatter:

```yaml
status: accepted | duplicate | na | informative | resolved | fixed
triage_status: <one-line platform response verbatim>
triage_date: YYYY-MM-DD
triager: <triager name or anonymous>
bounty: <amount or N/A>
```

Add a `## Triage Result` block to the body:

```markdown
## Triage Result

- **Date**: YYYY-MM-DD
- **Status**: <Accepted/Duplicate/N/A/Informative/Resolved>
- **Triager**: <name>
- **Response**:
  > <paste the platform's original reply verbatim; keep at least 2-3 sentences for context>
- **Bounty**: $XXX / N/A
- **Severity note**: <if severity was adjusted>
- **Lessons**: <any lesson worth recording>
```

### 2. Kanban

- `01 - Targets/<target>/Kanban - <target>.md` — per-target board
- If you maintain a cross-target overview (e.g., a Kanban / Dataview board under `00 - Dashboard/`), sync the card there as well

**Card movement rules:**

| Triage result | From column | Move to column |
|---|---|---|
| Accepted / Resolved | Submitted — Waiting | Triaged / Closed |
| Duplicate | Submitted — Waiting | Triaged / Closed (mark as dup) |
| N/A / Informative | Submitted — Waiting | Triaged / Closed (mark N/A) |
| Pending more info | Submitted — Waiting | On Hold (awaiting vendor) |

### 3. `01 - Targets/<target>/Target - <target>.md`

Update the Submission Status section (both frontmatter and the table) in the target hub file.

### 4. `00 - Dashboard/Dashboard.md`

Update `last_updated` and Quick Stats (skip if Dashboard is auto-aggregated by Dataview).

### 5. `09 - Knowledge Base/Lessons Learned.md` (if a lesson applies)

Add a new Lessons Learned entry only when one of the following is true:

- Platform policy surprised you (N/A reason was unexpected)
- Severity correction changes your understanding of severity calibration
- Triager explained a framework or policy you were unaware of
- Recurring mistake (same pattern resulted in N/A again)

New entry format:

```markdown
### LL #NN — <short title> (YYYY-MM-DD <target>)

**Context**: <one sentence>
**Triager response**: <verbatim quote>
**Lesson**: <how to avoid this in the future / how to frame it>
**Cross-ref**: [[Submission - <target> - <ID>]] / [[Pattern - ...]]
```

### 6. Commit

```bash
git add "01 - Targets/<target>/" "09 - Knowledge Base/" "00 - Dashboard/"
git commit -m "[triage] <target> <ID>: <Accepted|Duplicate|N/A> — <one-line summary>"
```

> If your private setup has a post-commit index / graph rebuild hook, the commit will trigger it automatically; otherwise rebuild the index manually.

## Additional Files to Update (if relevant)

- `01 - Targets/<target>/Findings/Finding - <target> - <ID>.md` — sync `status` and `last_verified` in frontmatter
- `09 - Knowledge Base/Pattern - <related pattern>.md` — if the triager corrected the VRT classification

## Prohibited Patterns (high-frequency traps)

| Mistake | Why it is harmful |
|---|---|
| Discussing triage result without editing files | The next session cannot see the outcome; state drifts |
| Updating only one location, skipping Kanban | Board still shows "Submitted Waiting" |
| Cross-target and per-target Kanban boards inconsistent | Two views contradict each other |
| No commit | Index / cross-target queries do not see the update |

## Full Checklist (60 seconds after receiving triage)

- [ ] Submission frontmatter + `## Triage Result` block
- [ ] Per-target Kanban card moved
- [ ] Cross-target Kanban card moved (if applicable)
- [ ] Target hub Submission Status section updated
- [ ] Dashboard `last_updated` updated (if not auto-aggregated)
- [ ] (If lesson applies) New entry added to Lessons Learned
- [ ] Commit `[triage] <target> <ID>: <status>`

## Cross-reference

- `AGENTS.md §9` (triage response handling)
- `bb-submission-readiness` (pre-submission gate)
- `bb-knowledge-capture` (lesson backfill to KB)
- `09 - Knowledge Base/Lessons Learned.md`
