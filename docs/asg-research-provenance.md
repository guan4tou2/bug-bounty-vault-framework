# Research Provenance in the ASG

Research work and attack-surface state share the target's existing `.state/asg-events.jsonl` ledger. Goals explain what must be established; intents explain the next piece of work; facts retain what was observed or read. The existing Finding identity and verification lifecycle remain authoritative.

This is an opt-in extension. Targets without research events retain their existing behavior. Research nodes do not increase attack-surface coverage, and adding a lineage edge never grants a capability or authorization.

## Nodes

| Kind | Meaning |
|---|---|
| `root` | The current task root, using the existing engagement authorization. |
| `goal` | A desired result with named acceptance criteria. Its purpose is `research` or `validation`. Effective state is `open`, `met`, or `abandoned`. |
| `intent` | A piece of work with goals, source references, prerequisites, and optional capability requirements. It differs from a hypothesis, which is a proposition to test. |
| `fact` | A sourced record with an explicit basis: `observed`, `source-claimed`, `inferred`, or `unknown`. The name does not imply independent verification. |
| `finding` | A reference to an existing Finding ID, including its current verification state. No parallel research Finding is created. |
| `hint` | A direction for this target, optionally scoped to a goal or intent. It is data for the worker, not an instruction that overrides scope or safety rules. |
| `digest` | A traceable summary of cold records. Originals remain in the ledger and can be expanded. A digest cannot serve as proof or grant a capability. |

References use stable ASCII IDs: `goal:G1`, `intent:R1`, `fact:F1`, `hint:N1`, `finding:ACME-001`, `hypothesis:H1`, and `digest:D1`.

## Relations

| Relation | Direction and effect |
|---|---|
| `spawns` | Root or goal to goal or intent: work decomposition. |
| `derived_from` | Fact, Finding, or hint to intent: why this next step was considered. It does not satisfy a capability prerequisite. |
| `yields` | Intent to fact or Finding: the actual output, including negative or unknown results. |
| `depends_on` | Prerequisite intent to later intent: the earlier work must be `done` before dispatch. |
| `tests` | Intent to an existing hypothesis: use the bounded test/control runner with the relevant criteria and hints. |
| `proves` | Fact or Finding to a named goal criterion, recorded through the explicit `prove` operation. |
| `covers` | Digest to original members: presentation only. |

The writer checks reference types, state transitions, and causal cycles under the existing ledger lock. An intent may bind one existing hypothesis. Use `--requires` for actual capability prerequisites; source lineage alone does not establish them.

## Acceptance and evidence

Each `prove` records a reason and fingerprints of both the source and the goal definition. A validation goal accepts an active observed fact with resolvable evidence, or an existing verified Finding whose proof is still effective. A research goal also accepts a source-claimed fact with a precise HTTP(S) URL, a timezone-aware reading date, and retained evidence.

Evidence can be a retained artifact with its SHA-256, an explicit typed observation, or a supported ledger reference. A filename that does not resolve is insufficient; free text is not automatically treated as an observation. Bounded test/control results retain both proofs as a typed comparison, including successful negative results. Both proofs must remain resolvable, and an execution failure remains unknown. Hints, digests, inferred or unknown facts, and Finding stubs cannot satisfy criteria. The research acceptance checks apply even when an older target uses legacy capability evidence conventions.

Changing or deleting an artifact, withdrawing a fact, invalidating a Finding, or revising the goal definition invalidates the affected proof. The goal reopens. Hashes and schemas check integrity and prerequisites; a reviewer still judges whether the evidence supports the criterion. Source claims establish a research result, not that the target is vulnerable.

Intent states are `open`, `running`, `paused`, `done`, `blocked`, `exhausted`, and `stopped`. To retry settled or paused work, explicitly return it to `open`. Record an output before marking an intent `done`. Finishing work, verifying a Finding, and satisfying a goal are separate outcomes. Open goals and unsettled research work prevent the loop from declaring completion.

## Workflow

Start with an initialized target and its existing ledger. For a new engagement, use the normal intake:

```bash
bash automation/init_target.sh <target>
python3 automation/engage.py <target> --interactive
```

For a target with a legacy YAML ASG, explicitly run `python3 automation/asg.py migrate <target>` and inspect the result before adding research work. Research commands do not silently migrate history.

Before custom tooling or substantive research, read the relevant original sources and existing implementations. Keep a short research receipt in the current work record: question, reading date, actual queries, exact source URLs and revisions, applicability, candidates considered, the reuse/adapt/build decision, and remaining unknowns. For CVE work, include the original advisory, patch, and applicable public reproductions. A failed search or fetch is not evidence that no prior work exists. Existing research may be reused while it remains applicable.

The following example records the research process. Replace placeholders with sources and artifacts actually read and retained:

```bash
python3 automation/asg.py research <target> goal G1 --text 'Establish method and version applicability' --purpose research --criterion 'C1=Retain original sources and applicability conditions'
python3 automation/asg.py research <target> intent R1 --goal G1 --text 'Read original documentation and compare existing implementations'
python3 automation/asg.py research <target> state intent:R1 running --reason 'Claimed by the current native runner'
python3 automation/asg.py research <target> fact F1 --intent R1 --basis source-claimed --source '<URL>' --checked-at '<RFC3339>' --evidence '<artifact-path>' --text '<Read result, applicability, and unknowns>'
python3 automation/asg.py research <target> state intent:R1 done --reason 'Sources and limitations recorded'
python3 automation/asg.py research <target> prove G1 C1 fact:F1 --reason '<How the source satisfies this criterion>'
python3 automation/asg.py research <target> hint N1 --goal G1 --text '<Direction for the next step>'
python3 automation/asg.py research <target> brief
python3 automation/next_work.py <target>
```

Create follow-up work with `--parent fact:F1`, `--depends-on R1`, or `--requires '<capability>'`. Bind an existing test with `--hypothesis H1`. Existing IDs require `--amend`; structured fields may be supplied with `--data-file <JSON>`.

Link the canonical Finding with `python3 automation/asg.py record-finding <target> ACME-001 --intent R1`, or add `research <target> link intent:R1 yields finding:ACME-001`. A link does not replace verification. Mark a hint consumed with `research <target> state hint:N1 consumed --reason '<reason>'`.

## Summaries, continuation, and Canvas

Digests may fold cold facts and settled intents. Active work keeps its ancestors and direct outputs visible; goals, Findings, and hints are never folded. Source changes or a new active branch can make a digest stale, causing the original facts to reappear in the brief.

```bash
python3 automation/asg.py research <target> digest D1 --member intent:R1 --member fact:F1
python3 automation/asg.py research <target> expand digest:D1
python3 automation/asg.py project <target>
python3 automation/render_surface_graph_canvas.py --research '<ASG.md-path>'
```

`project` refreshes the existing projections and, when research is enabled, writes `Attack Surface Graph - <target> - research.canvas`. Identical ledger content and evidence state produce identical Canvas content. Editing the Canvas does not change the ledger.

`next_work.py`, the session resume brief, and the hunt loop expose pending research. Plain-language research returns to the current native runner, which can use its available search, fetch, and file tools. This continuation does not count as a human intervention and does not execute commands embedded in research text. A bound test intent uses the existing bounded test/control runner; its worker receives relevant goals, criteria, sources, and hints. Actual outcomes return to that intent. Goal acceptance still requires an explicit evidence review and `prove`.

## Design sources and validation

Research checked on 2026-10-19: the question was how to retain research motivation, sources, and acceptance while keeping one ASG ledger. Queries included `site.w3.org TR prov-dm derivation generation entity activity provenance` and `site.learn.microsoft.com azure architecture patterns event sourcing materialized views projections`. The implementation adapts the entity/activity/derivation vocabulary in [W3C PROV-DM](https://www.w3.org/TR/prov-dm/) and uses replayed projections as described in [Microsoft's Event Sourcing pattern](https://learn.microsoft.com/en-us/azure/architecture/patterns/event-sourcing).

The chosen implementation reuses the existing ledger, lock, Finding lifecycle, and bounded runner rather than adding a database or agent runtime. Validation uses synthetic offline fixtures, CLI round trips, evidence and goal changes, prerequisite revocation, legacy-target compatibility, and deterministic Canvas output. No real target data or operational evidence is shipped.
