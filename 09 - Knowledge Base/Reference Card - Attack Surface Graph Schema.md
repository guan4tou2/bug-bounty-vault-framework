---
fileClass: ReferenceCard
type: reference-card
title: Attack Surface Graph Schema
last_updated: 2026-07-08
tags: [reference-card, attack-surface, graph, schema, bb-referencecard]
source: internal
added: 2026-07-08
related:
  - Reference Card - bbflow Vault Data Contract
---

# Reference Card — Attack Surface Graph Schema

> Per-target attack surface is a **graph**, not a flat table. Canonical file:
> `<target-dir>/Attack Surface Graph - <target>.md` (next to `RECON_DB.md`).
> Machine source of truth = the single fenced ```yaml``` block below. Visual =
> `Attack Surface Graph - <target>.canvas`, rendered by a canvas renderer if you
> wire one up. Adapted from Z3r0 (MIT).

> **Seed contract vs optional runtime (C09).** This seed ships the **schema + the
> Markdown source-of-truth only**. Capability traversal, reachability / `dag-suggest`,
> and capability-state propagation are **optional runtime you supply** (e.g. a
> capability-graph engine / CGT tooling) — they are **not bundled** here. Do not
> assume the bare seed can traverse the graph or auto-derive reachable-but-untested
> nodes; a conforming adapter must report clearly (a `doctor`-style check) when that
> capability is absent rather than silently returning empty. The YAML contract below
> is the stable interface an adapter reads/writes.

## The yaml block

```yaml
target: <target>
updated: YYYY-MM-DD
nodes:            # element-level inventory (was the flat Surface Map table)
  - id: <stable-slug>          # unique within file
    type: endpoint|param|role|state|trust-boundary|integration|dependency|file-upload|business-flow|anomaly|service|domain|host|binary
    identifier: <url | param name | role | ...>
    origin: scope|discovered
    recon_source: gau|katana|subfinder|nuclei|manual|...
    disposition: untested|suspected|validated|covered|false_positive|blocked|deferred   # per-node coverage state (see Coverage tracking below) — optional; default untested
edges:
  - src: <node-id>
    dst: <node-id>
    rel: resolves_to|hosts|trusts|related|connects_to|exploits|pivots_to|leads_to
    note: <optional one-liner>
findings:
  - id: <FINDING-ID>           # links to the Finding note
    on_node: <node-id>         # attach to a node ...
    on_edge: [<src>, <dst>]    # ... and/or the edge it substantiates
    status: suspected|validated|false_positive
paths:
  - name: <attack path name>   # mirrors an Attack Chains/*.md narrative
    edges:
      - [<src>, <dst>]
      - [<src>, <dst>]
```

## Recon Dimensions (optional, anti-tunnel-vision)

The optional `recon_dimensions` block tracks which **categories of reconnaissance** have been performed. It is orthogonal to the vuln-agnostic *testing* dimensions in `bb-surface-mapping` — those ask "how could this break?", these ask "what information have I gathered, and from which channel?". The failure mode it prevents: many rounds of active HTTP probing exhaust the unauthenticated surface while a single passive-OSINT pass would have surfaced employee emails, token patterns, and dozens of historical subdomains that active probing never finds.

How the hunt loop uses it:
1. **Session open** — read `recon_dimensions` and surface every `pending` dimension as a replan candidate.
2. **Stall detection** — when the active-probing dimension produces 3+ consecutive attempts with no new finding, prefer an untried dimension over deeper probing in the same one.
3. **Version→CVE is event-driven** — whenever a node is added with a `version`, the `version_cve` dimension fires immediately.
4. **Completion** — mark `done` only when all mandatory items are `done`; `partial` = some done, others remain.

Item status: `pending | done | partial | skipped:<reason> | n/a`. The CORE floor (`passive_osint`, `subdomain_enum`, `live_host_port`, `url_content_discovery`) should be `done` / `skipped:<why>` / `n/a` before exploit-phase actions on a web target; a recon-completeness gate may hard-block until then (firmware / source-audit profiles are exempt — see `bb-firmware-audit` Phase 0b). `n/a` must carry a real reason; a target with a cloud component makes those dimensions `pending`, not `n/a`. Items and dimension keys are a **floor, not a ceiling** — a target may add its own (e.g. `regulatory_filings`, `supply_chain_deps`); the schema does not restrict the keys.

Dimension → executing skill (the floor says WHAT; these say HOW — no new recon skill is created):

| dimension | tier | executing skill |
|---|---|---|
| passive_osint | CORE | `bb-surface-mapping` |
| subdomain_enum | CORE | `web2-recon` |
| live_host_port | CORE | `web2-recon` |
| url_content_discovery | CORE | `web2-recon` |
| infra_layer | rec. | `osint-arsenal` (DNS/TLS/reverse-DNS) |
| tech_stack_deep | rec. | `osint-arsenal` + `js-sourcemap-miner` |
| cloud_assets | rec. | `osint-arsenal` + `bb-bucket-ownership` |
| asset_scope | rec. | `osint-arsenal` (WHOIS/RDAP/ASN) |
| employee_osint | rec. | `osint-arsenal` (identity-fabric) |

> The CORE four are the intersection that OSCP enumeration, OWASP-WSTG Information Gathering, reconftw, and HackTricks external-recon all put before exploitation.

## Finding lifecycle (suspected vs validated)

Findings follow a strict lifecycle. **Core principle: only a finding verified by a complete PoC that achieves the expected impact may enter a report.**

```
a suspicious sign → open finding (status: suspected)
  ├─ define expected_impact ("what this vuln SHOULD achieve")
  ├─ fill verification_plan ("how to verify")
  └─ fill verification_risk ("could verifying cause damage?")
      ▼
  write a complete PoC (reproducible steps/input/output; a script or precise manual steps — a screenshot alone is not enough;
  it must run against the authorized target or a proven-equivalent controlled environment, not just a harness)
      ▼
  execute, observe:
    reached expected_impact → validated + dynamic_verified
    partial                 → lower expected_impact and re-assess
    not reached             → false_positive, or stay suspected
    cannot test safely      → suspected + blocked:needs_auth
```

| status | meaning | evidence bar | report? |
|---|---|---|---|
| **suspected** | a sign, not yet proven exploitable | version match / static analysis / harness trigger / short observation | No |
| **validated** | expected impact achieved by a complete PoC on the authorized target or proven-equivalent env | a reproducible PoC procedure + the expected impact reached | Yes |
| **false_positive** | disproven on verification | a record of what was tried and why it failed | No (but keep the record) |

Common **fake-verification** traps — none of these is validation: a version matching a CVE (the vendor may have backported a patch); a standalone sanitizer/harness trigger (the harness is not the stock daemon — the code path may be unreachable); a short-term measurement anomaly (a 500-request RSS rise that falls back at 10k requests is jitter); "the request was sent" (sent ≠ impact); a response diff (may be normal behavior); a statically-found vulnerable pattern (the caller may block the path). Promotion criteria (hard): a reproducible PoC procedure, the `expected_impact` reached on the authorized/equivalent target (not a harness or a self-built env), the effect is the intended security impact (not a side effect), and the effect reproduces (a one-off does not count). If it falls short, stay `suspected` — an honest intermediate state for the next session to continue, never a downgraded report.

## Verification fields on findings

`verification_level` tracks **evidence strength**, orthogonal to `status` (lifecycle):

| Level | Meaning | `status` allowed | Report? |
|---|---|---|---|
| `version_match` | the CVE's affected range includes this version | `suspected` only | No |
| `static_confirmed` | vulnerable code path found in source/binary, or a standalone harness triggered | `suspected` only | No |
| `dynamic_verified` | a complete PoC achieves `expected_impact` on the authorized target or a proven-equivalent controlled env | `validated` | Yes |

```yaml
findings:
  - id: <FINDING-ID>
    status: suspected|validated|false_positive
    expected_impact: "<what the exploit SHOULD achieve>"       # required — defines success
    verification_level: version_match|static_confirmed|dynamic_verified
    verification_method: "<how verified — must show expected_impact achieved>"  # required when validated
    verification_risk: reads_only|state_query|writes_data|service_impact
    verification_plan: "<what test is needed>"                 # required when suspected
    evidence_ref: "<path to the evidence file>"                # required when validated
    poc_ref: "<path to the reproducible PoC procedure>"        # required when validated
```

- `status: validated` **requires** `verification_level: dynamic_verified` **and** a `poc_ref` to a reproducible procedure. Validated-with-only-static-evidence (or no PoC) is invalid.
- Promotion `version_match → static_confirmed → dynamic_verified` is append-only; never downgrade unless the evidence is disproven.
- **verification_risk gates authorization by real side effects, not HTTP method**: `reads_only` (no side effect, confirmed by semantics) runs under existing authorization; `state_query` (a POST whose semantics only query — watch for rate-limit/lockout); `writes_data` (creates/modifies — ask if existing authorization doesn't cover it); `service_impact` (possible DoS/resource exhaustion — **must** ask first and confirm a recovery plan).

## Capability tags (Provides / Requires)

Adapted from Ta-Lun Yen's capability-graph model. Each tag is `P:<domain>=<value>` (Provides) or `R:<domain>=<value>` (Requires).

| Domain | Values | Example |
|---|---|---|
| `auth` | anonymous, user, admin, root | `P:auth=admin` |
| `net` | external, internal, `<host:port>` | `R:net:target:3306` |
| `read` | config, db, fs, logs, secrets | `P:read=config` |
| `write` | fs, db, config | `R:write=fs` |
| `exec` | shell, sql, code | `P:exec=shell` |
| `uid` | `<numeric>` | `P:uid=0` |
| `cred` | `<service>` | `P:cred=mysql` |

- Tags are free-form — add domains as needed (`P:token=jwt`, `R:role=manager`).
- `capability_state` is the session-start pin and grows **monotonically** (capabilities accumulate, never retract). When a finding is validated, its `provides` tags are added with `source: <FINDING-ID>`.
- **Attack chain = graph traversal**: from `capability_state`, follow `provides` edges whose `requires` are satisfied until a target capability (e.g. `P:exec=shell`) is reached.
- A node whose `requires` are all satisfied by `capability_state` but whose disposition is `untested`/`blocked` carries a `⏳` DAG edge (reachable-but-untested). `python3 automation/surface_graph_lib.py dag-suggest "<graph>"` lists these read-only (a node needs an `identifier` to be seen). Habit: tag `disposition` after testing each node; add each new capability to `capability_state`, then re-run `dag-suggest` to see which attack surface just lit up.

**Which findings enter the graph — three classes:**

| Class | Definition | In graph? | Test |
|---|---|---|---|
| **capability-bearing** | verification gives the attacker a new capability | ✅ model each | has a non-empty `provides` |
| **inventory / recon** | info disclosure, version detection, discovery | ❌ not in the denominator | `vuln_class` matches an inventory pattern |
| **defense-in-depth (no capability)** | a real code defect whose existing mitigation grants **no** capability, so it is not an edge | ❌ not in the denominator | frontmatter `asg_exempt` + reason |

The third class (e.g. an OOB read the caller pre-checks, a bug on a compile-disabled path, an out-of-bounds read with no info-leak and no crash) is **still a valid, submittable finding** — forcing it into the capability graph just creates an orphan node with no out-edge. Mark it per-finding (never in bulk), stating the mechanism that denies the capability:

```yaml
asg_exempt: defense-in-depth
asg_exempt_reason: "<which pre-check / disabled path / missing primitive denies a capability>"
```

If a bypass of that mitigation is later found, remove the mark and model it — it is capability-bearing again.

**Tier classification** (from Ta-Lun Yen): T1 trivial (model finds directly — command injection, hardcoded creds); T2 guided (model needs steering — buffer overflow, auth bypass); T3 advanced (model struggles — type confusion, race conditions). A large share of IoT vulns are T1+T2, the LLM-addressable range.

## Edge categories (derived, never stored)

- **structural**: `resolves_to`, `hosts`, `trusts`, `related`, `connects_to`
- **offensive**: `exploits`, `pivots_to`, `leads_to`

`category(rel)` is a pure function — do not store it.

## Rules

- `nodes` stays **element-level** (one node per endpoint/param/role/trust-boundary/…), 1:1 with Discovered Paths, so the surface-map gate/audit keep working.
- A node counts as "real" only if `identifier` is set (not empty / not `—`). An empty graph ships `nodes: []`.
- Only Finding/path-touched **key assets** additionally get their own note; the rest live only here.
- `paths` hold structure; `Attack Chains/*.md` (+ `.excalidraw.md`) hold narrative/visual.

## Coverage tracking (disposition)

`disposition` turns the graph into a **shared coverage blackboard** — the record of what has already been tested on each element, so parallel/sequential sub-agents don't re-test covered ground and their results flow back into one place (distinct from `findings[].status`, which is per-finding confidence):

- `untested` (default) — not yet examined.
- `suspected` / `validated` / `false_positive` — verification verdict for a node-level weakness.
- `covered` — tested, nothing found; skip on re-visits.
- `blocked` — needs an account / VPS / other precondition before it can be tested.
- `deferred` — intentionally postponed.

**Method** (this is a methodology seed — the reference implementation below is one way to wire it):
- A hunting sub-agent reads dispositions before testing and **skips `covered` / `false_positive`** nodes; after testing it reports back a disposition delta.
- The **commander is the single writer** — it applies deltas to the graph (avoids concurrent-edit races on the YAML). Carry this in the sub-agent's prompt (see CLAUDE.md → Subagent Convention Injection).

**Reference implementation:** `automation/surface_graph_lib.py` — read-only queries (`count-nodes`, `discovery-coverage`, `validate-provenance`) plus `set-disposition <graph-file> <node-id> <disposition> [note]`, a surgical line edit that preserves the file's YAML comments/formatting and re-parses to confirm the write. Implement your own if you prefer; the schema, not the script, is the contract.
