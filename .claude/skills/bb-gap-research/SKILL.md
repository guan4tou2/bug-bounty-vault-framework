---
name: bb-gap-research
description: Use when filling a knowledge gap from the Learning Backlog — user says "fill gap", "research the backlog", "research gaps", or picks an open gap to turn into a playbook. Trigger-based (NOT autonomous): you dispatch parallel research subagents, write playbooks, and mark the backlog status table.
---

# Bug Bounty — Gap Research (Triggered Knowledge Gap Filling)

Session briefs surface open knowledge gaps. **Filling is triggered (this skill), not automatic** — because research conclusions require judgment (e.g., a ProxyShell exploit is a stop-loss on an already-patched build; naive auto-fill would write an exploit for a non-vulnerable target).

## Single Source of Truth

Maintain a Knowledge Gaps & Learning Backlog document (e.g., `09 - Knowledge Base/Reference Card - Knowledge Gaps & Learning Backlog.md`) with a status tracking table:

```
| Gap | Status | Playbook |
|-----|--------|----------|
| ... | open/done/stop-loss | link |
```

## Process

1. **Select gap**: List open items from the backlog. If the user specifies one, use that; otherwise pick by ROI (highest impact on active targets first).

2. **Parallel research (subagent-first)**: For each gap, dispatch a `general-purpose` agent. The prompt MUST include:
   - Research objective + which target/finding it unblocks (for context).
   - **Use WebSearch/WebFetch for current, accurate information** (CVE version applicability, official advisories, original writeups).
   - Output: write a Playbook document with frontmatter `fileClass: Playbook` / `type: playbook`.
   - Content must include: version applicability table, GET-first safe detection steps, full chain logic, **stop-loss conditions**, and a `## Sources` section with complete URLs.
   - **Convention injection (mandatory)**: GET-first (detection is read-only; exploit steps marked "requires authorization"), anti-exaggeration ("if X then Y is possible" — never state as established fact), no internal finding IDs in body text, complete URLs in Sources.
   - Return only 3-5 line summary (do not return full content — protect main context budget).
   - Multiple gaps -> dispatch all agents in a single message for parallel execution.

3. **Judge conclusions**: Read each agent's summary. Research may overturn ROI assumptions — confirm the ceiling (already patched / requires account / unreachable) = **stop-loss** (equally valuable: saves wasted effort).

4. **Update status table**: Change the gap's status from `open` to `done` (actionable playbook) or `stop-loss` (ceiling reached). Fill in the playbook link. Write stop-loss reasoning into the backlog's notes area so it is remembered and not re-researched.

5. **Verify + commit**: Run workspace audits to confirm the playbook does not break anything. Commit the playbook + updated backlog with explicit pathspec.

6. **Knowledge capture**: If research produces generalizable lessons (new detection methods / stop-loss criteria), promote via `bb-knowledge-capture` (Pattern/Lesson).

## Prohibitions

- Do not auto-fill the entire backlog unsupervised (judgment cannot be automated).
- Do not write exploit playbooks for already-patched or unreachable targets (confirm version/reachability first).
- Do not write playbook conclusions as established vulnerabilities (anti-exaggeration).

## Related

- Findings reveal gaps -> research -> re-hunt (iterative recon principle)
- Knowledge base health checks, learning backlog automation
- See the External Skills Catalog for technique-specific research references
