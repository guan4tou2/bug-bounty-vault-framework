---
fileClass: ReferenceCard
type: reference-card
title: Hunt Loop Architecture
category: methodology
tags: [reference-card, hunt-loop, cgt, dag, priority-scoring, workflow]
added: 2026-08-29
---

# Reference Card — Hunt Loop Architecture

> Formalizes a full hunt-loop: surface-map through KB capture, with priority scoring and exit conditions.
> Each stage maps to an existing skill/script. The loop is the spine.

> **⚠️ Status reconcile (2026-09-12).** This card describes a **CGT-centric, opt-in DEEP variant** of the loop.
> The canonical, load-bearing loop is now narrower and lives elsewhere — do not read this as the mandatory
> per-round protocol:
> - **Canonical orchestrator**: `automation/hunt_autodrive.py` — one ASG ledger (`.state/asg-events.jsonl`)
>   → select valuable+ready hypothesis → dispatch worker → **control-comparison oracle** → update → auto-replan.
>   Reference implementation: the `automation/hunt_autodrive.py` + `automation/hunt_live.py` modules in this seed.
> - **Load-bearing parts only**: **autogen** (rank anomalous surfaces) + **oracle** (control comparison blocks
>   fake 200s). Everything else (CGT pin/traverse, ledger-resume, bbflow ingest) is **opt-in**, not per-round.
> - **CGT is opt-in, not "the nervous system"**: mandatory P/R tagging was retired; CG→DAG auto-reachability
>   (`dag-suggest`) is parked/dead (0 triggers). A deliberate deep chain pass (capability pin + traverse) is opt-in — do it when a confirmed
>   capability-granting finding makes chaining worthwhile, not as a per-round gate.
> The priority formula and exit-condition tables below remain good general references.

---

## Hunt Loop Stages

```
  [1] Surface Map ──→ [2] CGT Pin ──→ [3] Capability Traverse
         │                                      │
         ▼                                      ▼
  [8] KB Capture ◄── [7] Submit ◄── [6] Chain ◄── [5] Test ◄── [4] Prioritize
```

| # | Stage | Skill / Script | Input | Output |
|---|-------|---------------|-------|--------|
| 1 | **Surface Map** | `bb-surface-mapping` + `pre-recon` agent | Target scope | Attack Surface Graph (nodes, edges, capability_state) |
| 2 | **CGT Pin** | capability pin (opt-in; helper not shipped in this seed) | Graph yaml | Session-start capability_state pin |
| 3 | **Traverse** | capability traverse (opt-in; helper not shipped in this seed) | capability_state + findings P/R | Unlocked vs blocked partition |
| 4 | **Prioritize** | Priority formula (below) + `automation/dag_gaps.sh` | Unlocked set + DAG gaps | Ranked work queue |
| 5 | **Test** | `bb-web-vuln-scan` / `web-hunter` agent / manual | Top-priority candidate | Verified finding or recorded attempt |
| 6 | **Chain** | `bb-exploit-chain` (Q1-Q8) | Verified finding | P/R tags, capability_state update, chain extensions |
| 7 | **Submit** | `bb-dedup-finding` → `bb-evidence-readiness` → `bb-submission-readiness` → `bb-form-writer` | Chained finding | FORM / Submission |
| 8 | **KB Capture** | `bb-knowledge-capture` | Session learnings | Pattern / Lesson / Checklist / bbflow update |

**Loop re-entry**: After Stage 6 (Chain), new capabilities feed back to Stage 3 (Traverse) -- newly unlocked nodes re-enter at Stage 4.

---

## Priority Scoring Formula

Each candidate node receives a composite score. Higher = work first.

```
score(f) = tier_weight(f) + severity_weight(f) + unlock_bonus(f) + gate_opener_bonus(f)
```

| Component | Values | Rationale |
|-----------|--------|-----------|
| `tier_weight` | T1=3, T2=2, T3=1 | T1 = LLM-addressable (highest ROI); T3 = needs manual/specialized tooling |
| `severity_weight` | P1=5, P2=4, P3=3, P4=2, P5=1 | Higher severity = higher program payout |
| `unlock_bonus` | +2 if all R: tags satisfied | Ready to test now -- no blockers |
| `gate_opener_bonus` | +1 per downstream finding this node's P: tags would unlock | Findings that open paths for others are force multipliers |

**Example**: T1 finding, P2 severity, unlocked, opens 3 downstream nodes:
`score = 3 + 4 + 2 + 3 = 12`

**Tie-breaking** (same score):
1. Prefer findings whose P: tags satisfy the most blocked nodes (maximize unblock fan-out)
2. Prefer findings on surfaces not yet tested (coverage diversity)
3. Prefer findings with existing PoC sketch (lower effort to verify)

**Parallel edge identification**: `dag_gaps.sh` already detects independent edges (no dependency between TO/FROM). Run candidates at the same priority level concurrently via subagents.

---

## Hunt Loop Exit Conditions

Stop hunting a target when ANY of these hold:

| Condition | Signal | Action |
|-----------|--------|--------|
| **Surface exhausted** | All Graph nodes tested (no pending DAG edges) | `dag_gaps.sh --count` returns 0 |
| **Capability ceiling** | All blocked nodes require capabilities that are out-of-scope or infeasible to acquire | the (opt-in) capability traverse shows only blocked nodes with unacquirable R: tags |
| **Diminishing returns** | Last 3+ test cycles produced only attempts, no new findings | Check Attempts/ count vs Findings/ count ratio |
| **Budget exhausted** | Session token budget or calendar time exceeded | Handoff via `bb-context-handoff` |
| **Program blocked** | Needs account/KYC/hardware/VPN not available | Park target, record blocker in HANDOFF.md |
| **Scope risk** | Further testing would require dangerous/out-of-scope operations | `bb-scope-safety-check` flags red |

**Partial exit**: Park blocked branches (mark DAG edges as blocked with reason), continue on unlocked branches. A target is fully parked only when ALL branches hit an exit condition.

---

## Stage Details

### Stage 1: Surface Map (anti-streetlight)

The gate that prevents pattern tunnel vision. Must produce an Attack Surface Graph with nodes before any hunter/pattern scan runs. `surface_map_gate.sh` enforces this at scan time.

### Stage 4: Prioritize (work queue construction)

```bash
# 1. Get unlocked/blocked partition
# (opt-in) capability traverse: partition unlocked vs blocked
# 2. Get pending DAG edges with tier distribution
bash automation/dag_gaps.sh <target>
# 3. Score and rank (manual or future automation)
# Pick top 1-3 candidates per session cycle
```

### Stage 4b: Dimension stall check (the escape hatch)

**Problem:** a loop can spend many rounds inside one dimension (e.g. unauthenticated HTTP probing) and miss entire categories of information (OSINT, infra layer, employee leaks) that a single-round jump to a different *reconnaissance* dimension would surface. Shuffling hypotheses within the *testing* dimensions does not fix this.

**Mechanism:** after each round (or after 3 consecutive attempts with no new finding), read `ASG.recon_dimensions` and check:
1. Any `pending` dimension? → propose switching to it before going deeper in the current one.
2. Version→CVE stale? → any component discovered >1 round ago but not yet CVE-searched → fire now.
3. `passive_osint` still `pending`? → hard block: do not proceed to Stage 5 testing until OSINT is at least `partial`.

**Dimension-jump priority** (when several are pending) — a floor, not a ceiling:
1. `passive_osint` (highest — zero risk, seeds everything)
2. `infra_layer` (DNS / IP / TLS — finds hidden hosts)
3. `employee_osint` (public code leaks — credentials, internal structure)
4. `tech_stack_deep` (sourcemap / config mining — hidden endpoints)
5. version→CVE is auto-fired, not manually scheduled

Targets may add their own dimensions (the ASG schema accepts arbitrary dimension keys); they are checked after the floor dimensions.

**Key insight:** a dimension jump is not "give up on the current dimension" — it is "interleave one round of a different category, bring back new seeds, then continue". A single round that jumps from HTTP probing to DNS/infra mapping can surface a high-severity host that many rounds of HTTP probing never would.

### Stage 5: Test — dynamic verification flow

A candidate must pass a structured verification flow before its `status` is promoted:

```
candidate → assess actual effects + existing authorization
  allowed → execute bounded test → evidence review
    reproduced boundary violation + claimed impact achieved → validated
    insufficient / cannot test / not reproduced → suspected + verification plan
    disproven by adequate controls → refuted
  authorization/effects unclear → park + a concrete question → recheck after approval
  prohibited → block (ordinary approval does not override a prohibition)
```

Per-finding ASG record (fields → [[Reference Card - Attack Surface Graph Schema]]):
- `suspected` → fill `verification_plan` (what verification is next) + `verification_risk`
- `validated` → fill `verification_method` (what was done, what was observed) + `evidence_ref`
- not every finding reaches `dynamic_verified` — some need an account / environment / authorization → mark `blocked` + `verification_plan` for the next session

Principles:
1. **suspected ≠ validated** — a version match or a static-only confirmation is `suspected`; only dynamic verification can be `validated`.
2. **dynamic verification requires a full PoC** — not "there was some dynamic interaction", but a complete, re-runnable PoC (a script or precise manual steps) achieving the `expected_impact` against the authorized target or a proven-equivalent controlled environment. A sanitizer/harness trigger is static-confirmed; a short-term measurement wobble is not confirmed; "the packet was sent" is not impact.
3. **the PoC must be re-runnable and reach the expected effect** — a screenshot with no reproducible procedure is not a PoC; a partial effect is not achievement; a one-off is not reproducible. `poc_ref` points at the script/procedure; `verification_method` records the observed effect.
4. **only `validated` enters a report** — a `suspected` finding is an honest intermediate state handed to the next session, not a downgraded report.
5. **not every dynamic check needs to ask** — check authorization and real side effects first; proceed when in-scope and the consequences are known, ask when unknown, block what is prohibited.
6. **record failed verification too** — tried but not reproduced → `false_positive` + `verification_method` noting what was attempted.

**Discovery feedback (5 → 0/1 loop):** when testing surfaces a new attack surface (a new subdomain, internal IP, API endpoint, or credential in a response):
1. add the new node to the ASG (`origin: discovered`, `recon_source: test-feedback`)
2. re-run the passive-OSINT floor on the new scope (CT logs, Wayback, …)
3. the new node enters Stage 4 prioritization

### Stage 6: Chain (the multiplier)

Q8 of `bb-exploit-chain` feeds back into the loop:
1. Tag P/R on the new finding
2. Update capability_state in the Attack Surface Graph
3. Re-run the (opt-in) capability traverse -- newly unlocked nodes enter the priority queue
4. Q7 clue-correlation re-scans blocked attempts for retest triggers

This creates a positive feedback loop: each finding potentially unlocks the next.

---

## Cross-Cutting: Search-First Principle (applies at every stage)

**No factual claim about the external world may rest on training data or memory alone. Search to confirm it.** This is not a single stage's rule — it is a discipline for every step of the loop, and it is not limited to version numbers and CVEs: it applies to anything that can change over time.

### Fact classes that must be searched

| Class | Example | Why memory is not enough |
|---|---|---|
| **Version / CVE / PoC** | "<product> <version> has a CVE"; "this CVE has a public PoC" | Advisories update; PoCs appear or get pulled |
| **Tech-stack behavior** | "Spring Boot exposes actuator by default"; "Django DEBUG is off by default" | Defaults change between versions |
| **WAF / defenses** | "Cloudflare blocks this payload"; "this bypass works" | WAF rules update continuously |
| **Default credentials** | "<product>'s default login is admin/admin" | Vendors change defaults |
| **Program state** | "this BBP is live"; "scope includes `*.example.com`" | Programs adjust scope / pause / close |
| **Exploit techniques** | "this SSTI payload works on Jinja2"; "this bypass still works" | Frameworks patch; syntax changes |
| **API / docs** | "this API accepts a JSON body"; "this endpoint returns user data" | APIs version |
| **Vendor patch status** | "this is fixed"; "no patch yet" | New patches ship at any time |
| **Prior research** | "has anyone written this attack up?"; "best practice for this technique" | New writeups publish continuously |

### How

You need no special trigger — whenever you are about to make a factual judgment (not a deduction, but a claim about the *state of the external world*) at any stage, search first. Source priority:
1. **Injected context** (environment block / vault state) — most authoritative right now.
2. **WebSearch / a multi-source search** — external facts after the training cutoff.
3. **Training data** — only for stable invariants (HTTP protocol semantics, crypto algorithm properties, language syntax).

**Test:** if "it was A a year ago, it might not be A now" → search. If "it has not changed since the RFC defined it" → answer directly.

### Application by stage

| Stage | Typical judgment to search |
|---|---|
| OSINT | the target's tech stack, subdomains, employee info, historical vulns |
| Version→CVE | version↔CVE mapping, PoC availability, patch status |
| Surface Map | framework default behavior, known component weaknesses |
| Prioritize | current exploitability of a vuln class |
| Test | payload validity, WAF-bypass techniques, default credentials |
| Chain | feasibility of a chaining technique, prior writeups |
| Submit | the program's current scope / status, vendor response policy |

---

## Invariants

1. **No testing before mapping** -- Stage 5 never precedes Stage 1 (enforced by `surface_map_gate.sh`)
2. **No submission before chaining** -- Stage 7 never precedes Stage 6 (enforced by `bb-submission-readiness`)
3. ~~**Every finding gets P/R tags** -- Q8 mandatory~~ **RETIRED (2026-09-12)**: mandatory CGT P/R tagging was
   retired (adoption ≈0). P/R tagging is now opt-in for a deliberate chain pass; the loop no longer gates on it.
4. **Every session ends with KB capture** -- Stage 8 runs at session close (enforced by `vault-sync` agent)
5. **Capability_state is monotonic (when used)** -- in the ASG ledger the capability layer is a projection over
   an append-only event log; a capability can be withdrawn when its supporting verdict is refuted/revoked
   (least-fixed-point), so "only added, never removed" holds for events, not for the derived capability set.

---

## Cross-References

- [[Reference Card - Attack Surface Graph Schema]] -- capability_state / P/R / tier schema
