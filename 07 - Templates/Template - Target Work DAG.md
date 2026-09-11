---
type: target-subpage
subpage: target-work-dag
target: "[[Target - {{name}}]]"
last_updated: "{{date}}"
---

# {{name}} — Target Work DAG

> [!warning] Build only for XL multi-system / multi-finding targets; skip for single-finding targets — the DAG records, it doesn't drive decisions, and ROI scales with target size (broad use → low adoption).

> An effectiveness-first DAG for recon / validation / decision gates / pentest route / exploit-chain bridge.
> **When to use: many surfaces, many entry points, many validation branches, or when it's easy to forget the next step between sessions. Skip for a single request / single finding.**
> **Automation contract: maintain only the four-column table `from | edge | to | status`; a `status` (column 4) that contains `⏳` is what makes `automation/dag_gaps.sh` treat an edge as untested.**
> **Priority: first improve hunting / penetration capability (coverage, exploitable paths, evidence quality, stop conditions), then save tokens as a bonus.**

Status markers: ✅ covered / ❌ dead end / ⏳ pending / 🔴 confirmed high ROI / ⚠️ stopped by safety or scope

## Usage Rules

- The DAG grows dynamically as you discover: new surfaces, new capabilities, new evidence, and new blocking conditions can all be appended as edges.
- Don't delete high-impact / high-uncertainty edges just to be brief; preserve attack-decision value first, then control narrative length.
- Each session, start from the `⏳` edge with the highest ROI / the greatest uncertainty to resolve; if several qualify, pick at most 3 active edges, unless they are explicitly split across parallel agents.
- Once an edge is tested, just update the row status — don't write a separate long narrative.
- New leads go into the DAG first; evidence, raw responses, and audit refs then go into RECON_DB / Finding.
- Render Mermaid only for the final report or when a human needs to review it; don't draw diagrams routinely.
- Start a session by running `bash automation/dag_gaps.sh <target>`; add `--kind recon` to look at recon only.

## Recon DAG

> Goal: avoid chasing only the brightest lead; keep discovery method and surface coverage as continuable edges.

| from (seed/source) | edge (discovery method) | to (surface/asset) | status |
|---|---|---|---|
| Program scope | CT / subfinder / ASN | host inventory | ✅ |
| host inventory | alt-port sweep | unknown service list | ⏳ |
| unknown service list | tech fingerprint | stack-specific test plan | ⏳ |

## Validation DAG

> Goal: break "suspicious" down into falsifiable conditions, so you don't re-read the same evidence.

| from (signal) | edge (success criterion) | to (evidence/decision) | status |
|---|---|---|---|
| login redirect candidate | valid account confirms post-login redirect | open redirect evidence | ⏳ |
| source map endpoint | extracts API route and parameter | validation request list | ✅ |
| SSRF parameter | internal metadata response | confirmed SSRF | ❌ |

## Decision Gate DAG

> Goal: express "how to choose the next step" as verifiable forks. This is a decision-tree function, but it still belongs in the DAG because multiple paths merge, share evidence, and accumulate across sessions.

| from (current state) | edge (decision condition) | to (next route / stop condition) | status |
|---|---|---|---|
| unknown web stack | fingerprint identifies WordPress | WP route / generic web route | ⏳ |
| candidate finding | evidence meets reproducibility + impact bar | Finding / Attempt | ⏳ |
| exposed version | current vendor advisory covers root cause | abort-known / proceed-zero-day | ⏳ |
| write-capable endpoint | scope and safety allow mutation test | VPS verification / stop at read-only evidence | ⚠️ |

> **Fan out each decision's evidence-gathering:** the facts a branch depends on (fingerprint, reproducibility check, advisory lookup) are self-contained → dispatch independent ones as parallel subagents; the branch choice itself (which `to`) stays in the main loop (see §Subagent delegation, "judgment stays central"). A decision gate is a delegation point — don't run all the evidence inline before deciding. Likewise every `⏳` edge is one delegation unit (node → worker).

## Pentest Route DAG

> Goal: track the path from current access / capability to the next foothold, not just a single vulnerability type.

| from (access/capability) | edge (action) | to (next foothold/decision) | status |
|---|---|---|---|
| read-only account | enumerate tenant IDs | IDOR candidate list | ⏳ |
| exposed admin page | 401/403 bypass matrix | authenticated-only route map | ⏳ |
| upload feature | extension / MIME / transform tests | upload-to-execution decision | ⚠️ |

## Exploit-chain Bridge

> Once you find a chainable finding / data, move it into `Template - Exploit Chain DAG` for formal chain tracking.

| from (finding/data) | edge (exploit) | to (capability) | status |
|---|---|---|---|
| leaked internal endpoint | IDOR | other user's data | ⏳ |
| leaked version | CVE / advisory precheck | known-N-day decision | ⏳ |

## Subagent Delegation (node → worker) — control tokens / prevent overlong sessions

> The DAG makes the split "main loop = orchestrator + judge, node = disposable worker" fall out naturally.
> Confine exploration noise (large responses, whole source files, fuzz output, payload attempts) inside the subagent's context;
> the main loop only sees the returned `status` + evidence paths → context doesn't bloat, and even if compaction cuts it, it can be rebuilt from the DAG.

- **When to delegate**: edge exploration that is **verbose and self-contained** (auditing one module, running one full exploit, fuzzing one param) → dispatch a subagent. **Trivial checks** the main loop does itself — the spawn cost exceeds the task.
- **What to delegate**: inject conventions by tier (see AGENTS.md "Subagent Convention Injection"; subagents do not inherit CLAUDE.md/AGENTS).
- **Lock down the return schema (this is the bottleneck, not the worker)**: splitting work off to a subagent does **not** automatically shrink the main session — what shrinks it is "the returned information being compressed." The worker's final message **returns structured JSON only**, never a raw transcript; the main loop consumes only a ~50-100 token summary. An unlocked return interface = dumping the worker's garbage back into the main loop, which is worse than not splitting at all.

  ```json
  {"task":"<one line>","new_findings":0,
   "findings":[{"path":"/x","type":"IDOR","severity":"high","evidence":"workspace/workshop/<t>/poc/x.txt","one_line":"..."}],
   "dead_ends":[{"item":".env","why":"404 (not SPA catch-all, compared)"}],
   "next_suggested":["test TRACE"],"carry_state":"needs X-Forwarded-Host spoof"}
  ```
  Enforce via the workflow's structured-output/schema mechanism, or paste the schema into an interactive subagent prompt ("final message = this JSON only"). Do NOT rely on the prompt instruction alone — pure-JSON compliance is format-following, not capability, and an eval found even the strongest model adds a preamble while cheaper models returned clean JSON. Enforce structure mechanically. PoC/evidence to `workspace/workshop/<target>/poc/`, return paths not inline.
- **Pick the model by task**: judgment / chain reasoning / **verification** = strongest model (**never downgrade**); source read / template-fill reporting = mid; result-classification / extraction / summary = cheap; CVE/version diff = no LLM (`grep`). Downgrade only bounded tasks a weak model can reliably finish (rework costs more — see AGENTS §6b2).
- **Judgment stays central**: the worker **gathers evidence + a tentative classification**, the main loop re-judges (severity / dead_ends re-judged; `404≠excluded`, SPA catch-all returns `200`; reproducibility / anti-exaggeration / dedup need a global view; never let a worker self-certify a finding).
- **Adaptive is not fan-out**: edges grow as you dig → the main loop dispatches subagents interactively; use a deterministic workflow only for a known batch (test these N endpoints).
- **The main session's own discipline**: keep only decisions in the conversation history, not intermediate reasoning (put reasoning in extended thinking); every 3-5 worker returns → snapshot into Carry-state/RECON_DB → compact the earlier details.
- **Cross-node nuance goes into Carry-state** (below); don't cram it into the 4-column table and don't leave it only in the worker context.

## Carry-state ledger (nuance + evidence paths that must persist across nodes)

> Record only things "the next node will need but are too long for the status column." Empty means there is no cross-node dependency.

- (append…)

## Automation

```bash
bash automation/dag_gaps.sh <target>
bash automation/dag_gaps.sh <target> --kind recon
bash automation/dag_gaps.sh <target> --kind validation
bash automation/dag_gaps.sh <target> --kind decision
bash automation/dag_gaps.sh <target> --kind pentest
bash automation/dag_gaps.sh <target> --kind chain
bash automation/dag_gaps.sh <target> --count
```
