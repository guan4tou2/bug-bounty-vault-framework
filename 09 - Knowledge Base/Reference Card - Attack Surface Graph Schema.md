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
