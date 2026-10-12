---
type: reference
category: checklist
tags: [checklist, subagent, orchestrator, pre-flight, convention-injection, delegation]
added: 2026-10-12
---

# Checklist — Subagent Pre-Flight

> **Trigger:** before the orchestrator dispatches any subagent. Creating a task-list entry is not a dispatch; this runs at the moment of delegation.
> **Relationship:** AGENTS.md §Subagent Convention Injection defines *what* to inject per task tier; this checklist is the orchestrator's self-check that it actually did. Delegation principles: AGENTS.md §6b3 and §6b4.

---

## Context and convention injection

- [ ] Context mode is known: a fresh-context agent does **not** see the parent conversation, files already read, or skills already loaded; some agent types also skip project instruction files. Fill the gaps in the prompt — do not paste the whole rulebook.
- [ ] The task tier is explicit (recon / analysis / output / review / research), and the prompt states the scope, evidence available, acceptance criteria, and return format.
- [ ] Effort is set for the tier (AGENTS.md §6b4). CVE or vulnerability judgment: effort at least `medium`, plus "search public advisories/PoCs first".

## Large-file reads

- [ ] If the subagent must read a large file (`Lessons Learned.md`, a target's `RECON_DB.md`, `FINDINGS_QUICK_REF.md`), the prompt names the section heading or an `offset` + `limit`. No unbounded full reads of large KB files.

## Online sources

- [ ] For repository content on a code-hosting site, prefer the site's CLI or API (raw file / API endpoints) over fetching rendered HTML pages — HTML fetches hit rate limits, parse badly, and waste tokens.

## Dedup and safety

- [ ] Analysis subagents: told to check `FINDINGS_QUICK_REF.md` (and `bb-dedup-finding`) before proposing a new Finding.
- [ ] Testing subagents: given the GET-first principle and the never-execute list (AGENTS.md §6a, §6b), and told to run risky or automated operations from an isolated runner (AGENTS.md §6c).
- [ ] Every active step stays inside the confirmed scope; the subagent cannot widen authorization.

## Output quality

- [ ] Subagents that write tests: told that assertions must verify the behaviour under test, not just that a value is truthy or non-empty.
- [ ] Subagents that process a batch list of targets or domains: told to verify domain-to-organization ownership before attributing anything.
- [ ] Raw logs and long outputs go to files; the subagent returns conclusions, `file:line` references, and open items.

## Stop conditions

- [ ] The subagent has an explicit done-condition and a budget (turns, requests, or time) so it cannot crawl indefinitely.
- [ ] Hitting the budget or a tool failure is reported as partial/blocked — never as "done" or "not vulnerable".
- [ ] The subagent must not commit or push unless the orchestrator explicitly authorized it, and must not dispatch further subagents.
- [ ] Parallel subagents do not write the same files; see [[Playbook - Multi-Agent File-Ownership Partitioning]].

## Related

- [[Reference Card - Orchestrator Architecture]]
- [[Reference Card - Testing Safety Rules]]
