# Event-driven reassessment

ASG research state and EFSM product state remain separate. Reassessment reviews a
changed research plan; it never creates authorization or verifies a Finding.
`automation/reassessment.py` exposes `request`, `collect`, `inventory`, `view`, and
checked `apply` decisions. All records use the existing ledger and writer lock.

## Triggers and bounded execution

The dispatcher collects obstruction/control failures, newly confirmed capabilities,
changed contexts, disputed hypotheses, changed pinned evidence, completed comparison
batches and explicit triggers. Autodrive requests review on queue exhaustion and
repeated rounds without evidence progress. Report/trace records request delivery
review on the next dispatcher pass; callers can request `pre_delivery` before drafting.
This is advisory review under existing delivery gates, not a new approval gate.

```sh
python3 automation/reassessment.py TARGET --reason pre_delivery
python3 automation/reassessment.py TARGET --reason no_information_gain --scope hypothesis:HYPOTHESIS_ID
python3 automation/work_dispatch.py TARGET --config PRIVATE_ROUTING.json
```

Inventory includes current/scoped hypotheses, capabilities, intents, obstruction
budgets, original evidence references, stale/conflicting evidence and untraversed
flow transitions. Traversal does not imply security coverage. A target-wide review
is explicit; a local obstruction uses its hypothesis scope.

Identical reason/scope/inventory versions are deduplicated, including completed
reviews. Changed pending inputs supersede old cards. Queue/no-information follow-up
reviews have a cooldown measured in meaningful ledger events. Each work has at most
one model call and no automatic retry; invalid output is retained as a failed receipt.
Deterministic triggers first record an inventory and defer to existing prerequisite
and evidence gates. Only ambiguous obstruction, conflict, no-information, exhausted
queue and delivery reviews request model judgment. This is not general state-space
search or automatic discovery of every missing role/entry point.

## Checked decisions

A configured `reassessment-analysis` worker receives a bounded, redacted inventory,
opaque evidence references and the current result contract. Data-processing policy
is checked before calling it. Return `operation: decide` with `payload.decisions`.
Each decision supplies `action`, `subject`, `reason`, `uncertainty`, `evidence_refs`
and optional `details`; citations use supplied IDs or `inventory`.

- `retain`: keep an existing hypothesis/intent or inventory.
- `prioritize`: order an existing hypothesis within its scheduler priority class,
  with integer `details.priority` from -2 to 2. Suggestions expire with their inputs.
- `propose`: create an exploration proposal with `details.question` and `requires`,
  citing a current original artifact; adoption and normal execution gates remain separate.
- `pause`, `resume`, `cancel`: change a canonical intent's plan state. Running work
  requires its original stop/effects acknowledgement and cannot be cancelled here.

The full decision batch is validated before mutation. Stale/altered cards, unknown
subjects, unsupported actions, invented evidence, authorization and verified-state
changes are rejected. Persist decisions, sources and uncertainty; do not request or
store a model's private reasoning transcript. Snapshot/handoff projections include
reassessment history; they are not writable sources of truth.

Validation uses synthetic fixtures and local subprocesses. Full-task token usage,
research quality, universal browser execution and live-target impact remain unmeasured.
