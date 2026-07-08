# Bug Bounty Workflow Specification

> Full workflow reference. Quick path: [AGENTS_QUICK.md](AGENTS_QUICK.md). Structure: [STRUCTURE.md](STRUCTURE.md).

---

## §0 Session Protocol

### §0a Session Start

```bash
bash automation/check_active_sessions.sh    # list active locks
bash automation/claim.sh <scope>            # acquire scope lock
# or
python3 automation/start_session.py <scope>
```

Scopes: `_meta` (docs/automation), `<target>`, `<target>/<sub-service>`, `<target>/<sub-service>/<vuln-class>`.

### §0b New Target

```bash
bash automation/init_target.sh <target>
```

Then fill: `SCOPE.md` (program boundaries) + `Target - <target>.md` (vault hub page).

First time on a machine, establish the tool layer (Ring 2) once via `bb-tool-setup` / [bbflow/setup.md](bbflow/setup.md). Then the first hunting action is **always** `bb-surface-mapping` (vuln-agnostic surface map) — never jump straight to a scanner. See §3e.1.

### §0c Knowledge Base Lookup

Query the KB at three moments:
1. **Before research** — is there a Pattern for this tech stack?
2. **During hunting** — has this technique been documented?
3. **Before reporting** — check Lessons Learned for triage calibration

### §0d Session End

```bash
python3 automation/end_session.py <scope>
```

### §0e Target Work DAG

Use `07 - Templates/Template - Target Work DAG.md` when a target has multiple surfaces, validation branches, decision gates, pentest routes, or exploit-chain candidates. The DAG is effectiveness-first: it should improve coverage, exploitable-path discovery, evidence decisions, and stop conditions. Token savings are secondary.

Delegate verbose, self-contained nodes to convention-injected subagents (main loop = orchestrator + judge, node = disposable worker): exploration noise stays in the worker's context, the main loop records only `status` + evidence path. This bounds main-loop tokens, prevents over-long sessions, and lets state be rebuilt from the DAG after compaction. Trivial checks stay inline; judgment (reproducibility / anti-exaggeration / dedup) stays central; cross-node nuance goes in the template's Carry-state ledger. See the template's "Subagent 委派" section + AGENTS.md Subagent Convention Injection.

The contract is a four-column edge list: `from | edge | to | status`. DAGs grow dynamically as new surfaces, capabilities, evidence, and blockers appear. Do not prune high-impact or high-uncertainty edges just to keep the file short. At session start, use:

```bash
bash automation/dag_gaps.sh <target>
bash automation/dag_gaps.sh <target> --kind recon
bash automation/dag_gaps.sh <target> --kind decision
```

Pick the highest-ROI or uncertainty-reducing `⏳` edges first. The legacy `chain_gaps.sh` command is a compatibility wrapper for exploit-chain DAGs.

### §0g Version + CVE Pre-flight

**Before any software/firmware/SaaS analysis:**

1. Check vendor's latest stable version
2. Search NVD / GHSA / vendor advisories for the target version
3. Check recent disclosed reports on the platform
4. Write results to `RECON_DB.md ## Pre-flight Checks`

**Stop-loss:** If the target runs an old version with known CVEs, document and move on.

---

## §1 Target Structure

Every target gets:
- **Vault:** `01 - Targets/<target>/` with Findings, Submissions, Forms, Attempts, Recon, Services, Attack Chains, Screenshots
- **Workspace:** `workspace/workshop/<target>/` with SCOPE.md, RECON_DB.md, HANDOFF.md, FINDINGS_QUICK_REF.md, poc/, scan_results/

**Rule:** Vault stores canonical knowledge. Workspace stores process artifacts.

### §1a Canonical Data Is Never Auto-Deleted

Never auto-delete Vault target directories. `01 - Targets/<target>/` is canonical research history, even when a target looks empty, orphaned, stale, or accidentally scaffolded.

Allowed actions:
- Report the issue in the session summary.
- Mark it for `quarantine/manual-review`.
- Ask for explicit user confirmation before any filesystem removal.

Forbidden actions:
- Agent-initiated `rm -rf` on `01 - Targets/<target>/`.
- Cleanup tasks that delete Findings, Submissions, FORMs, Recon notes, Attack Chains, Services, screenshots, or evidence.
- Treating audit or orphan detection as permission to delete canonical records.

---

## §3 Finding Pipeline

### §3a Finding Creation

> **Principle: Finding first, auto-create.** Every confirmed vuln gets a Finding immediately. Don't wait, don't batch.

- **Finding** — auto-create on discovery
- **Submission** — propose to user for approval
- **FORM** — user explicitly triggers

### §3b Discovery Log Format

Five columns, mandatory in every Finding:

```
- `YYYY-MM-DD HH:MM` `[source IP → target IP]` `[audit:ref]` action → result
```

### §3e Pipeline Chain

```
Finding → Submission → FORM
```

All three share the same ID. No Submission-only workflow — every Submission must have a parent Finding.

### §3e.1 Candidate Lifecycle Gates

The full path runs through the four-ring loop (see [docs/architecture-closed-loop.md](docs/architecture-closed-loop.md)). Establish the tool layer once, then every target passes the hunting gates, then every candidate passes the lifecycle gates:

```
# once per machine — establish Ring 2 (the tool layer)
→ bb-tool-setup             # install/verify bbflow (or a contract-conforming scanner)

# per target — hunting phase (Ring 3), order matters
→ bb-surface-mapping        # FRONT gate: vuln-agnostic attack-surface map (explore-first)
→ Target Work DAG          # recon/validation/decision/pentest route state, grows as findings appear
→ bb-web-vuln-scan          # OWASP Top 10 coverage + version→CVE + WAF bypass

candidate found            # a scanner hit is a LEAD here, not a Finding
→ bb-dedup-finding          # duplicate check
→ bb-scope-safety-check     # scope + safety gate (before live verification)
→ bb-exploit-chain          # 6-question chain on any finding — escalate before the next system
→ bb-attack-chain-review    # chain potential assessment
→ bb-evidence-readiness     # evidence completeness
→ Finding                   # create if ready
→ attack-chain-deep-dive    # optional agent for complex chains
→ bb-submission-readiness   # final gate before report
→ Submission / FORM         # platform-specific output
→ bb-knowledge-capture      # capture reusable learning (Ring 4 — runs even on a parked session)
```

Failed candidates → `bb-attempt-recorder` (preserves negative results for future reference).

**The front gate is non-negotiable:** `bb-surface-mapping` runs *before* any pattern/hunter/scan is trusted as your vuln lens — skipping straight to pattern-matching is the streetlight effect. Each gate is implemented as a skill in `.claude/skills/`. The gates can also be performed manually — the workflow documents describe the same checks as prose — but LLM-agent operation is the intended mode.

### §3f Dedup Rules

**Same Finding:** Same root cause, same endpoint, same parameter.
**Different Findings:** Same vuln type but different parameters/resources = separate Findings.

Check before creating: `FINDINGS_QUICK_REF.md` + `RECON_DB.md` Known Artifacts.

---

## §5 Anti-Exaggeration

- Theoretical attack chains must not be written as accomplished facts
- "If X then Y" is acceptable; "attacker gains Z" requires PoC
- Severity must match verified evidence, not theoretical maximum

---

## §6 Operation Safety

### §6a GET-first Principle

| HTTP Method | Policy |
|-------------|--------|
| `GET` / `HEAD` / `OPTIONS` | Execute freely |
| `POST` (read-only query) | Confirm no side effects first |
| `POST` (write) / `PUT` / `PATCH` | Confirm consequences; use an isolated runner when risk is non-trivial |
| `DELETE` (not self-created) | **Never execute** |

### §6b Never-Execute List

- `stop` / `destroy` / `shutdown` / `kill` / `restart` operations
- Bulk delete / truncate / drop
- Endpoints that trigger Email / SMS notifications

### §6b2 Tool-call token economics (narrow before you fire)

GET-first governs *safety* (don't execute unknown consequences); this governs *tokens* (don't flood context with noise). Same root, different goal.

**Core: think-depth scales with the cost of wrong parameters, not with tool complexity.**

- **High-output / retry-prone / persistent** calls (broad scans, fuzzing, crawls, subdomain enum, large responses) → narrow scope + state the rationale *before* firing. Tool noise dwarfs thinking tokens, and it is re-read on every later turn (cross-turn compounding); narrowing once saves many times. A failed call is double waste (input + error output + a re-run).
- **Trivial deterministic** calls (read a known path, one CVE lookup, single-param GET) → just call; writing reasoning for them is pure overhead.
- **Isolation beats thinking-longer for token savings**: push verbose exploration to a disposable subagent (see §0e Target Work DAG delegation). The main loop reasons only about *what to delegate and at what scope* and ingests only `status` + evidence path. A main loop that thinks, runs, and eats raw output is triple-charged (and the reasoning is re-read across turns).
- **Raw logs are for humans; distilled state is for the LLM.** Keep raw action/audit logs in files (out of git, out of session-start context); the agent reads distilled state instead (e.g. RECON_DB's tested/excluded/to-verify attack-surface table). Never read a human action log back at session start. And do not mechanically classify status codes into state (`404`→excluded, `200`→confirmed): WAF/auth-gating make `404` unreliable and SPA catch-alls return `200` for everything — distillation is an LLM judgment, not a `grep`.

### §6b3 Commander stays out of the weeds (delegate aggressively)

The main conversation is the **commander**: keep only **decisions, synthesis, user-facing communication, and small targeted edits** in it. Every heavy operation belongs in a fresh-context subagent whose *conclusion* — not its working noise — comes back.

- **Delegate by default.** Reading multiple files, cross-repo diffs, scanning a large file (more than a few hundred lines), batch verification, semantic extraction, and broad searches all go to a subagent. Do not Read large files into the main context — ingest only the distilled result.
- **Fan out in one message.** Independent heavy nodes dispatch as parallel subagents in a single turn, not one after another.
- **Plan as a DAG.** For any multi-step task, lay out a task list with dependencies and delegate each heavy node; the main thread is the join point where results are merged and judged.
- **Why.** A bloated main context costs tokens and cache misses, and mixing many files' raw detail degrades judgment — the two failure modes compound across turns.
- **Pairs with verify-not-self-verify.** Route every "done / correct" conclusion to a fresh-context agent to check, rather than confirming your own work in the same context that produced it.

### §6c Isolated Runner Boundary

**Recommended isolated runner/VPS:** bbflow, nuclei, ffuf, sqlmap, osmedeus, bbot, and automated scanning.
**Local OK:** single GET, reading tool output, writing reports.

### §6d Operation Log

Record in `RECON_DB.md ## Operation Log` **before** executing:

| Local Time | UTC Time | Source IP | Method | Target URL | Intent | Result |
|---|---|---|---|---|---|---|

Update `Result` immediately after.

---

## §8 Severity Calibration

| Level | Criteria |
|-------|----------|
| P1 Critical | RCE, full admin takeover, mass data breach |
| P2 High | Significant data access, auth bypass, stored XSS in admin |
| P3 Medium | Limited data access, requires conditions |
| P4 Low | Info disclosure, requires chaining |
| P5 Info | Best practice violation, no direct impact |

**Rules:** Severity must match `verified_evidence` field. `live` supports full claim. `static`/`theoretical` caps at P3.

---

## §9 Triage Response

When vendor responds:
1. Update Submission status
2. Update Kanban
3. Capture lessons
4. If Duplicate: record, don't rationalize. Move on.

---

## Knowledge Capture Gate

| Type | When to Create |
|------|---------------|
| Attack technique (Pattern) | New vuln class or novel method |
| Decision tree (Playbook) | Repeatable multi-step process |
| Attack chain | Multi-vuln chain amplifying impact |
| Stop-loss (Lesson) | Spent >2h on abandoned direction |
| Pitfall (Lesson) | Preventable error |
| Checklist | Reusable verification steps |

### Effect Loop (measure retrieval, not just capture)

Capture (session -> KB -> template -> gate) is one-directional. Without a reverse
loop you cannot tell which KB/templates actually help hunting, so artifacts grow
unbounded with no evidence to prune. Close the loop with three measurements:

| Gap | Tool | Measures |
|-----|------|----------|
| Did a KB artifact produce a finding? | `automation/kb_roi.sh` + Finding `helped_by:` | credited (keep) vs uncredited (prune evidence) |
| Did the right KB surface at point of need? | `automation/surface_kb.sh <target>` | tech fingerprint -> relevant Pattern/Playbook |
| Which templates are shelf-ware? | `automation/check_shelfware.sh` | instance count per template; 0 = unused |

On confirming a finding, fill its `helped_by:` with the KB ids that led to it.
Forward measurement beats retro-mining: shelf-ware shows up immediately instead
of being discovered after dozens of unused sessions. Mechanical detection, LLM
judgment — uncredited/0-instance is a prune *candidate*, not an auto-delete.

---

## Subagent Convention Injection

| Tier | Task Type | Must Inject |
|------|-----------|-------------|
| Recon | Scope, subdomain enum, fingerprint | GET-first, operation log |
| Analysis | Vuln verification, PoC | + dedup, anti-exaggeration, VPS |
| Output | Finding / Submission / FORM | + pipeline, discovery log, severity, no internal IDs |
