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
> `Attack Surface Graph - <target>.canvas`, rendered by
> `automation/render_surface_graph_canvas.py`. Adapted from Z3r0 (MIT).

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
