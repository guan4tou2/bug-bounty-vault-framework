---
fileClass: ReferenceCard
type: reference-card
title: "Orchestrator Architecture — Model Routing, Subagent-First Dispatch, and Token Optimization"
---

# Reference Card — Orchestrator Architecture

> Fills the automation gap in model dispatch doctrine: complexity scoring, model routing, clean-context subagent dispatch, result collection, verification, and budget tracking.
> Design principles draw from: field-tested dispatch experience + FrugalGPT/RouteLLM/AutoMix academic validation + context-explosion post-incident analysis + model-downgrade incident lessons.
> This card is for the **commander** (main-loop model); subagents never see this card — they only receive their dispatch prompt.

## Validation Status

| Section | Status | Notes |
|---------|--------|-------|
| 1a Tier Definitions | **proven** | Used in every session |
| 1b Provider Mapping | **partial** | Claude column field-tested; GPT/Gemini/local columns retained for reference, not battle-tested |
| 2 Complexity Scorer | **proven** | Mental-math version in daily use |
| 3 Risk Override | **proven** | Adversarial verification is a concrete instance of risk-to-L3 escalation |
| 4 DAG Job Schema | **proven** | Built in every multi-step hunting session |
| 5 Return Contract | **proven** | Subagent conclusion+path pattern is stable |
| 6a Cascade Escalation | **proven** | L2-to-L3 escalation path triggers routinely |
| 6b Uniform-Result Trigger | **future work** | Concept valid (field lesson confirmed); the >80% threshold and auto-spawn logic are automation requirements, not manually testable — deferred to backlog |
| 6c L0 max-attempt=2 | **reasonable default** | Reasonable default; L0 tasks rarely exceed 2 attempts in practice, but lacks large-scale statistical validation |
| 7a Dispatch Flow | **proven** | Every subagent dispatch follows this |
| 7b Skill Gate Pre-check | **proven** | Confirmed necessary after a session where skipping it led to incomplete recon |
| 7c Prompt Three Elements | **ready to validate** | Concept is sound (field lesson confirmed); delegation templates exist, validate on next real dispatch |
| 7d Adaptive Probe Protocol | **background reference** | Feedback loop is manual judgment, not automated; academic citations retained as design rationale, not executable spec — not scheduled for backlog |
| 8 Token Budget Tracking | **proven** | Context handoff rules in daily use |
| 8b Context Pinning & Compression | **partial** | P0/P1 tiers implicitly landed (system prompt + on-demand skill loading); DAG-aware eviction is design-stage |
| 9 Concurrency Safety | **proven** | DAG depends_on in daily use |
| 10b Graph Integration Scope | **proven** | [D]-only-into-graph rule is clear |
| 10c Recon-in-Graph | **future work** | Requires structured schema support from graphify; 3-phase roadmap shelved — awaiting typed-node support or alternative tooling |

> **How to read**: **proven** = trust and follow. **partial** = partially landed, details need validation. **reasonable default** / **ready to validate** = concepts are sound but thresholds/templates need validation. **future work** = deferred to backlog, retained but not occupying session context. **background reference** = design rationale retained, not executable spec. No **needs_tooling** items remain.

---

## 0. Design Principles

1. **Subagent-first, not subagent-always**: Default to subagent dispatch (context isolation, token savings), but keep judgment, design decisions, and trade-offs in the main loop. Decision criterion: "Would this step dump raw non-decision material into the main context?" If yes, delegate it out.
2. **Complexity selects the model; risk has veto power**: Task complexity picks the baseline model, but high risk can force an upgrade (risk override).
3. **Cascade, not one-shot**: Start with the cheapest model; escalate only when quality is insufficient. Academic evidence: FrugalGPT achieves GPT-4-equivalent quality at 98% lower cost; RouteLLM routes only 14% of queries to the strong model while maintaining 95% quality (ICLR 2025).
4. **Structured returns, conclusions not raw text**: Subagents return 50-100 token conclusions + file paths, never code dumps.
5. **Tokens are a budget, not an infinite resource**: Each DAG node has a `context_budget`; exceeding it triggers stop, compress, or escalate — never infinite stuffing.

---

## 1. Four-Level Model Routing (L0-L3) — Provider-Agnostic

The routing logic selects a **capability tier**, not a specific model. Concrete model names come from the mapping table and can be swapped per provider/session/cost constraints.

### 1a. Tier Definitions (Stable)

| Level | Capability Requirement | When to Use | Typical Tasks |
|-------|----------------------|-------------|---------------|
| **L0** | No LLM (deterministic) | Programmable | CVE version comparison, frontmatter lint, regex extraction, rename |
| **L1** | Fast/cheap, no judgment | Mechanical | Batch-apply a solved pattern, structured extraction, bulk shallow grep |
| **L2** | Balanced (**default**) | General work | Report drafts, code implementation, recon analysis, most delegated tasks |
| **L3** | Strong reasoning, high reliability | High-risk judgment | Attack chain viability, architecture decisions, adversarial verification |

### 1b. Provider Mapping Table (Configurable)

| Tier | Anthropic (Claude) | OpenAI (GPT) | Google (Gemini) | Local/Other |
|------|-------------------|--------------|-----------------|-------------|
| **L0** | — | — | — | grep / jq / bash script |
| **L1** | Haiku | GPT-4.1-nano | Gemini Flash | Qwen3-8B / Llama-3-8B |
| **L2** | Sonnet | GPT-4.1 / o4-mini | Gemini Pro | Qwen3-32B |
| **L3** | Opus | o3 / GPT-4.5 | Gemini Ultra | — (local usually insufficient) |

> **How to choose a provider**:
> - **Claude Code session**: Use Claude family (`model` parameter: `haiku`/`sonnet`/`opus`)
> - **Automated agent (VPS)**: Follow your agent config's `model_tiering`
> - **Manual research (ChatGPT/Gemini)**: Operator chooses, but respect the same tier capability requirements
> - **Cross-provider verification**: For high-risk judgments, deliberately use a different provider's L3 for a second opinion (reduces systematic bias from same-family models)

### 1c. Selection Flow (Pseudocode)

```
function select_model(task, provider="claude"):
    complexity = score_complexity(task)        # -> L0/L1/L2/L3
    risk       = score_risk(task)              # -> low/medium/high/critical
    
    tier = complexity_to_tier(complexity)       # complexity sets baseline
    
    # Risk override: risk can upgrade but never downgrade
    if risk == "critical":  tier = max(tier, L3)
    if risk == "high":      tier = max(tier, L2)
    
    return PROVIDER_MAP[provider][tier]         # look up concrete model
```

> **Cross-provider second opinion** (optional): `if risk == "critical": second_opinion = select_model(task, provider=OTHER_PROVIDER)`

---

## 2. Complexity Scorer

Assess four dimensions, each scored 0-2; the total determines the tier:

| Dimension | 0 pts | 1 pt | 2 pts |
|-----------|-------|------|-------|
| **Reasoning Depth** | Single step / direct lookup | 2-3 step chain | 4+ steps, requires backtracking |
| **Judgment Ambiguity** | Clear correct answer | Judgment needed but has checklist | Taste question / open-ended |
| **Cross-Domain Knowledge** | Single file/tool | Spans 2-3 systems | Spans architecture layers / multiple targets |
| **Failure Cost** | Redo is easy | Wastes 30 minutes | Pollutes report / wrong submission / irreversible |

| Total | Tier | Notes |
|-------|------|-------|
| 0 | L0 | If a script can do it, don't use an LLM |
| 1-2 | L1 | Haiku + low effort |
| 3-5 | L2 | Sonnet + medium effort (default landing zone) |
| 6-8 | L3 | Opus + high/xhigh effort |

> Don't overthink it — spend 5 seconds on mental math. **The goal is to prevent two kinds of waste**: using Opus for grep (cost waste), using Haiku for attack chain judgment (quality waste).

---

## 3. Risk Override Rules

Risk is independent of complexity — simple tasks can still be high-risk.

| Risk Level | Trigger Conditions | Forced Minimum Tier |
|------------|-------------------|-------------------|
| **Critical** | Submission content, external communications, irreversible operations, PII handling | L3 (Opus) |
| **High** | Finding validity judgment, severity determination, attack chain completeness | L2 (Sonnet), verification at L3 |
| **Medium** | General implementation, search, report drafts | No override |
| **Low** | Format conversion, batch file changes, lint | No override |

> **Academic basis**: Dekoninck et al. (ICML 2025) demonstrate that the optimal cascade routing strategy is "complexity selects baseline + escalate on insufficient quality"; however, when cost-of-error is high, jumping directly to L3 has lower expected cost (because retry costs include contamination propagation).

---

## 4. DAG Job Schema

Each DAG node (= one delegatable work unit) carries the following metadata:

```yaml
node_id: "recon-endpoints"
description: "Scan all target endpoints and rank by interest"
depends_on: ["init-target"]           # DAG dependency
complexity: 3                          # 0-8, see section 2
risk: "medium"                         # low/medium/high/critical
model_class: "L2"                      # from select_model()
model: "sonnet"                        # concrete model name
reasoning_effort: "medium"             # low/medium/high/xhigh/max
context_budget: 8000                   # expected subagent token consumption limit
return_schema: "endpoint_list"         # expected return structure (see section 5)
parallel_safe: true                    # can run in parallel with unrelated nodes
verification_required: false           # whether completion requires fresh-agent verification
```

**parallel_safe criteria**:
- No `depends_on` overlap -> `true`
- Writes to the same file -> `false`
- Reads/writes to the same shared data source -> serialize (or use append-only + merge)

> **Academic basis**: Yang et al. (arXiv 2606.00953) formalize multi-agent orchestration as a graph partitioning problem, using static analysis to build dependency graphs, community detection for partitioning, and dependency-aware schedulers for execution — directly corresponding to this DAG's `depends_on` + `parallel_safe`.

---

## 5. Return Contract (Return Schema)

Subagent returns must be **conclusions + metrics**, never raw text. Common schemas:

| Schema Name | Fields | Purpose |
|-------------|--------|---------|
| `endpoint_list` | `[{url, interest_score, reason}]` | Endpoint ranking |
| `finding_candidate` | `{id, title, severity, evidence_path, confidence}` | Candidate finding |
| `verification_verdict` | `{confirmed: bool, reasoning, counter_evidence?}` | Verification result |
| `search_result` | `{query, hits: [{title, url, relevance}], summary}` | Search conclusions |
| `file_change` | `{files_changed: [path], summary, needs_review: bool}` | Batch file changes |
| `generic` | `{conclusion, evidence_paths: [path:line], confidence, caveats}` | General purpose |

> Long artifacts (>200 lines) go to scratchpad or a designated path; only the path is returned. **Never paste raw content back into the main loop.**

---

## 6. Cascade Escalation Protocol

```
L1 fails once -> escalate directly to L2 (no same-tier retry)
L2 fails twice on the same subtask -> escalate to L3 with full failure trace
L3 also fails -> stop; ask the user or present 2-3 options with uncertainty flagged
Pattern solved -> drop back to L1 for batch application
```

> Same as standard doctrine, but adds **L0 triage**: if a script can solve it, don't even enter L1 — first ask "Does this step need an LLM?"

### 6b. Uniform-Result Trigger

> **Lesson learned**: When 8/10 endpoints all returned 500, the orchestrator did not trigger a comparison group, nearly resulting in a rejected P1 submission.

**Rule**: When subagent results are **>80% identical** (e.g., all 500s, all timeouts, all 403s), the orchestrator must:

1. **Stop expanding the same test** (if 10 all return 500, testing 20 more will also return 500 — wasted tokens)
2. **Spawn a comparison agent that changes one variable**:
   - All identical HTTP errors -> try authenticated vs unauthenticated
   - All timeouts -> try a different egress (different network path)
   - All 403s -> try different User-Agent / IP
3. **Report the pattern, not individual results**: "N/M endpoints returned X" instead of N identical table rows

```
if agent.results.unique_ratio < 0.2:
    spawn_comparison_agent(change_one_variable=True)
    do_not_expand_same_test()
```

### 6c. L0 Max-Attempt Rule

L0 deterministic tasks (version detection, specific pattern grep) that fail **2 consecutive times with the same method** -> mark `inconclusive`, do not retry with variations. Prevents scenarios like spending 5 curl attempts on version detection with no result.

**Academic basis**:
- FrugalGPT (Chen et al. 2023): LLM cascade starts from cheapest, escalates on insufficient quality, achieves GPT-4 equivalence at 98% cost reduction.
- AutoMix (NeurIPS 2024): Small model self-verifies first, routes to large model only when uncertain; three-tier classification (easy/hard/unsolvable).
- "Routing Collapse" (Lai & Ye 2026): As budget increases, routers degenerate to sending everything to the large model — requires EquiRouter-type correction.

---

## 7. Subagent-First Dispatch Flow

```
User request
    |
Commander splits into DAG (section 4)
    |
Each node -> select_model() -> dispatch subagent
    |-- Independent nodes dispatched in parallel (same message)
    |-- Dependent nodes serialized
    +-- Decision gates -> evidence collection delegated, final choice stays in main loop
    |
Collect conclusions (section 5 return schema)
    |
Needs verification? -> dispatch fresh-context L3 agent
    |
Main loop consolidates -> respond to user
```

**When NOT to dispatch a subagent (keep in main loop)**:
- Judgment itself ("what to do", "is this correct")
- Trade-off decisions (final choice between plan A vs plan B)
- Communication with the user
- Edits of 5 lines or fewer
- Small queries about information already in main-loop context

### 7b. Skill Gate Pre-check

> **Lesson learned**: Rushing to test a new architecture without running surface-mapping and version-CVE-precheck led to incomplete recon.

**Rule**: Before starting a hunting DAG, the first node is always a gate check:

```
DAG node[0] = {
    task: "gate_check",
    model_class: "L0",
    steps: [
        "Has surface-mapping been run (check for Attack Surface section in recon data)?",
        "Has version-CVE-precheck been run (check for Pre-flight section in recon data)?",
        "Have existing findings been read for dedup?"
    ],
    on_fail: "Run the missing gate skill first — never skip"
}
```

Even for "quick tests" or "just one endpoint," the gate check is not skippable.

### 7c. Probing Agent Prompt — Three Required Elements

> **Lesson learned**: A probing agent was told "test for auth bypass" but not told what would disprove the hypothesis.

All probing/hunting subagent prompts must include three elements:

1. **Hypothesis** (positive claim): "We believe the POST endpoint bypasses authentication"
2. **Counter-evidence** (what would disprove it): "If an authenticated POST also returns 500, the route doesn't exist — this is not an auth bypass"
3. **Uniform-result instruction**: "If the first 3 results are identical, STOP and report the pattern; let the orchestrator decide next steps"

Template:
```
## Hypothesis
We believe [CLAIM]. 

## What would disprove this
If [COUNTER-EVIDENCE], then [CLAIM] is false — report this immediately.

## Uniform result protocol
If >3 endpoints return identical response, STOP testing more endpoints.
Report the pattern and suggest what variable to change for comparison.
```

### 7d. Adaptive Probe Protocol

Orchestrator feedback loop after receiving subagent results:

```
Agent result -> Orchestrator judgment
  |-- Result clearly confirmed -> auto-spawn adversarial agent (L3)
  |-- Result uniform/ambiguous -> auto-spawn comparison agent (section 6b)
  |     +-- Change one variable (auth state / IP / UA / method)
  |-- Result refuted -> record negative result, move on
  +-- Result partial -> enrich next agent prompt with findings so far
```

**Key principles** (from field experience):
- "Re-fetch state before retrying" — on uniform errors, obtain fresh auth state before retesting
- "Batch + validate small before scaling" — send 1 agent to test 2-3 targets first; confirm the pattern before batch dispatch
- "Change only one variable at a time" — comparison groups should vary only auth/method/IP, not multiple factors simultaneously

> **Academic background** (reference, not executable specification): Adaptive multi-agent orchestration literature supports these concepts:
> - Recursive decomposition on failure rather than pre-decomposition (ADaPT, NAACL 2024)
> - Mid-execution DAG restructuring (DynTaskMAS, DeMAC)
> - Quality classifier (not binary pass/fail) for cascade escalation decisions (Dynamic Model Routing Survey)
> - Small model orchestrating + large model executing (ParaManager)
> - History-guided routing (Experience as a Compass)
> - Post-incident analysis: under-delegation is the root cause of context explosion

---

## 8. Token Budget Tracking

### Concept

- Main-loop context is a **non-renewable resource** — every non-decision payload shoved in pushes out decision memory.
- Subagent context is a **disposable resource** — used and discarded, never polluting the main loop.
- Goal: **Main-loop context grows only with decisions and conclusions.**

### Execution Discipline

| Signal | Action |
|--------|--------|
| Main-loop context at ~50% remaining | Proactively delegate unfinished heavy work; stop main-loop file reads |
| Main-loop context at ~30% remaining | Trigger context handoff; write handoff notes |
| Subagent returns >200 lines | Request re-submission; write to file, return path only |
| Same file read >2 times in main loop | That file's analysis should be delegated |

### Cost Intuition (Mental Math for Model Selection)

| Upgrade | Cost Multiplier | When It's Worth It |
|---------|----------------|-------------------|
| L0 -> L1 | From 0 to some | When semantic understanding is needed |
| L1 -> L2 | ~3-5x | When judgment is needed |
| L2 -> L3 | ~3-5x | When error cost is high (one bad finding > 10 Opus calls) |

### 8b. Context Pinning & Compression Strategy

> **Problem**: Summarization-based compaction silently drops governance constraints (Governance Decay, arXiv 2606.22528 — measured 30-59% violation rate). System rules and skill triggers are constraints, not conversation history — they must not be compressed.

#### Three-Tier Pinning Model

| Tier | Content | Treatment | Reference |
|------|---------|-----------|-----------|
| **P0 — Always Pinned** | Golden rules, skill trigger table, GET-first principle, anti-exaggeration rules | Never compress, never summarize — stays verbatim in system prompt | Constraint Pinning (arXiv 2606.22528) |
| **P1 — Load on Demand** | Reference Cards, Playbooks, KB patterns, Templates | Not pinned in system prompt; loaded via Skill/Read when triggered, released after use | TokenPilot prefix stabilization (arXiv 2606.17016) |
| **P2 — Compressible** | Conversation history, subagent return summaries, tool output, intermediate analysis | Automatically summarized by harness; compression can be aggressive | LLMLingua (EMNLP 2023), ACON (ICLR 2026, arXiv 2510.00615) |

#### Compression Only Happens at P2

```
Context Window Structure:
┌─────────────────────────────────────┐
│ P0: golden-rules + skill triggers   │ ← Never compressed
│     (~2-3K tokens, fixed)           │
├─────────────────────────────────────┤
│ P1: On-demand Reference Cards       │ ← Loaded when triggered, released after
│     (0-8K tokens, dynamic)          │
├─────────────────────────────────────┤
│ P2: Conversation history + output   │ ← Harness auto-compresses
│     (remaining space)               │
└─────────────────────────────────────┘
```

#### DAG-Aware Eviction (CWL Concept)

Active DAG node context = P1 (pinned until node completes); completed DAG node context = P2 (compressible).

```
if dag_node.status == "active":
    pin(node.context)          # P1: retain until completion
elif dag_node.status == "completed":
    compress(node.context)     # P2: keep conclusion only
    evict(node.raw_output)     # raw output already saved to file
```

> **Academic references**:
> - CWL typed dependency graph + graduated eviction (arXiv 2606.11213)
> - VISTA proprioceptive dashboard (arXiv 2606.30005): agent sees own context usage for eviction decisions
> - DACS asymmetric context isolation (arXiv 2604.07911): prevents cross-agent context pollution
> - MemGPT / Letta (ICLR 2024, arXiv 2310.08560): OS-style main context ↔ recall ↔ archival memory

---

## 9. Concurrency Safety

Conflict prevention when running multiple subagents in parallel:

| Risk | Mitigation | Reference |
|------|-----------|-----------|
| Two agents write the same file | `parallel_safe: false`, serialize | CoAgent MTPO (arXiv 2606.15376) |
| Two agents read/write the same shared data | Append-only + main-loop merge | Atomix progress-aware transactions (arXiv 2602.14849) |
| Agent A's result is Agent B's input | DAG `depends_on` enforces serialization | SGH (arXiv 2604.11378) |
| Agents return contradictory conclusions | Main loop decides, or dispatch a third agent to arbitrate | Standard multi-answer adjudication |

---

## 10. Relationship to Other Documents

| Document | Gap This Card Fills |
|----------|-------------------|
| Model Dispatch Doctrine | Adds L0 triage + complexity scorer + DAG job schema + token tracking |
| Judgment Rubrics | "When to escalate" rubric now has quantified dimensions (section 2 four-dimension scoring) |
| Delegation Templates | Adds return schema enforcement (section 5) + parallel_safe marking |
| Subagent Scope-Tiered Injection | Tier 1/2/3 injection unchanged; this card adds model routing before tier selection |

---

## 10b. Graph Integration Scope (What Goes into the Graph, What Doesn't)

> Answering "would stuffing everything into the graph be too bloated?" — the answer is layering, not all-in.

### Enters Persistent Graph (Knowledge/Capability Graph)

| Data | Source | Condition |
|------|--------|-----------|
| Finding's Discovery Verification Card fields | Finding template | Always enters |
| Verification Trace `[D]` steps | Same | `[D]` = confidence 1.0; worth recording as attack-path edge |
| Exploitability / confidence level / prerequisites | Same | Node attributes |
| CVE associations | CVE precheck | When CVE confirmed to affect target |
| capability_state / P/R tags | Capability graph model | Already present |
| **Recon asset topology** | Recon data | See section 10c |

### Stays as Local Metadata (Does Not Enter Graph)

| Data | Reason |
|------|--------|
| Verification Trace `[H]` steps | Hypotheses, unverified; entering graph would pollute confidence |
| Verification Trace `[I]` steps | Inferences; only enter graph after upgrade to `[D]` |
| Orchestrator DAG (section 4 job schema) | Pure runtime scheduling structure; discarded after session |
| Complexity scorer intermediate calculations (section 2) | Runtime decisions; not persisted |
| Cascade escalation/de-escalation records | In session logs; not needed in graph |
| Hallucination risk flags | For human review; not graph structure |

### Principles

1. **Only `[D]`-level evidence produces graph edges** — `[I]` and `[H]` are Finding-internal metadata.
2. **Discovery Verification Card table fields = node attributes** — lightweight, non-bloating.
3. **Orchestrator DAG is runtime-only** — never written to the persistent graph.
4. **The graph's responsibility is "attack surface topology + verified attack paths"**, not "all speculation."

### 10c. Recon-in-Graph: Attack Surface Asset Topology

> Recon data (hosts, endpoints, tech stacks, credentials, certificates) also enters the graph, but as an **asset layer** (separated from the Finding **vulnerability layer**).

#### Why Recon Should Enter the Graph

| Problem | How Recon-in-Graph Solves It |
|---------|------------------------------|
| Cross-session forgetting of explored surfaces | Graph has `[Host]->[Endpoint]` topology; query graph at session start to see what's known |
| Unknown which endpoints remain untested | `coverage_state: untested/tested/finding` label on edges |
| New recon results have no context | Graph auto-links `[Host]->[TechStack]->[CVE]` |
| Plain-text recon data is hard to query | Graph enables structured queries ("all Spring Boot hosts with untested actuator endpoints") |

#### Node Types

```
[Target] --owns--> [Host]
[Host] --serves--> [Endpoint]
[Host] --runs--> [TechStack]        # e.g., ASP.NET 4.0, Umbraco 13.9.8
[TechStack] --affected_by--> [CVE]
[Endpoint] --has_param--> [Parameter]
[Host] --exposes--> [Credential]    # only if leaked/discovered
[Host] --cert--> [Certificate]      # SSL cert info
[Host] --resolves--> [IP]
```

#### Edge Attributes

```yaml
edge:
  from: "[Host] app.example.com"
  to: "[Endpoint] POST /api/settings"
  coverage_state: "tested"          # untested | tested | finding | negative
  last_tested: "2026-09-02"
  finding_ref: "EXAMPLE-001"        # null if no finding
  auth_required: true
  methods: ["GET", "POST"]
```

#### What Enters / What Stays Out

| Enters Graph (Structured Assets) | Stays in Recon Notes (Prose) |
|----------------------------------|------------------------------|
| Host / IP / CNAME chain | Scanner raw output |
| Endpoint path + method + params | Per-line curl responses |
| Tech stack + version | Full banner text |
| Coverage state (tested/untested) | Intermediate test attempts |
| Credential (already leaked) | Expired session cookie values |
| CVE associations | Full advisory text |

#### Cross-Layer Intersection with Findings

```
[Endpoint] --coverage:finding--> [Finding]
[Finding] --verified_by--> [Evidence Step]    # already present, section 10b
[TechStack] --affected_by--> [CVE] --exploited_by--> [Finding]
```

When the two layers intersect, the graph can automatically answer: "This target's Spring Boot hosts have 3 actuator endpoints; 1 has a finding, 1 tested-negative, 1 untested" — this is **coverage gap analysis**.

#### Implementation Roadmap

1. **Phase 1 (Low cost)**: After surface-mapping completes, automatically output structured JSON (host/endpoint/tech) for graph ingestion. No format changes to existing recon notes — just add an export step.
2. **Phase 2**: Graph semantic extraction adds a recon data parser (extracts nodes from Attack Surface / Endpoints sections).
3. **Phase 3**: Automatic `coverage_state` tracking — when a new Finding is created, update the corresponding endpoint edge state.

> **No rush to do everything.** Phase 1's structured JSON export alone enables coverage gap queries.

---

## Quick Reference

1. First ask "Does this need an LLM?" — if not, use L0 (script).
2. If yes, four-dimension scoring -> L1/L2/L3.
3. Risk override: critical -> L3, high -> L2.
4. Default to subagent dispatch; main loop receives conclusions only.
5. Independent nodes dispatched in parallel (same message).
6. Returns use schema; long artifacts written to file, path returned.
7. Escalation carries full failure trace; solved patterns drop back to batch mode.
8. Start delegating when main-loop context hits 50%; handoff at 30%.
9. Tier = capability level; concrete model looked up via section 1b mapping table (Claude/GPT/Gemini/local all supported).
10. Only `[D]` evidence enters the graph; `[I]`/`[H]` and DAG are runtime metadata.
11. Uniform result (>80% identical) -> change one variable and spawn comparison; do not expand the same test (section 6b).
12. Probing agent prompt three elements: hypothesis + counter-evidence + uniform-result instruction (section 7c).
13. Hunting DAG's first node is always a skill gate check (section 7b).
14. Recon assets enter graph as asset layer; Findings as vulnerability layer; intersection = coverage gap (section 10c).
15. Context three-tier pinning: P0 (golden-rules, never compress) -> P1 (Reference Cards, load on demand) -> P2 (conversation history, compressible) (section 8b).
