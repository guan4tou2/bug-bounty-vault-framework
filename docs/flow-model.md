# Conditional flows and evidence-backed traces

ASG retains research hypotheses, evidence and Finding state. The existing `delivery_record.flow` authority describes product actors, object ownership/relationships, identifier origin, states, entries and transitions. Case/trace events share that ledger; no graph database is required.

```sh
python3 automation/flow_model.py TARGET define --input FLOW.json
python3 automation/flow_model.py TARGET plan --flow-id FLOW --focus-transition TRANSITION
python3 automation/flow_model.py TARGET bind --case-id CASE --hyp-id HYPOTHESIS --invariant-ref INVARIANT
python3 automation/flow_model.py TARGET view
```

Targets need existing genesis and invariant records. Cases distinguish normal, skip/repeat, actor and entry boundaries. Actual steps pin separate pre/action/post artifacts, observed product state, actor/object/entry and identifier source. Reproduction needs its own TEST/CONTROL evidence and runner identity; it never sets Finding verification.

An optional transition `predicate` supports bounded `all`/`any` and typed field comparisons: `eq`/`ne`/`in` (equality and set), `gt`/`gte`/`lt`/`lte` (integer comparison for counter thresholds), and `exists` (variable presence). Missing variables return `unknown`; comparison operators on non-integer values return `unknown`. No expressions or arbitrary scripts are evaluated. A false product guard remains a possible negative security test, subject to existing authorization. Product expectations never overwrite observations or research conclusions.

`generate_cases` produces up to 20 case kinds per focus transition: 5 base (normal, skip, repeat, actor-boundary, entry-boundary), 7 sequence (multi-repeat-2/3/5, error-then-continue, resubmission, cancel-then-continue, back-and-modify), 4 structural input (input-empty/missing-field/type-mismatch/boundary-value), 5 business input (biz-quota-mismatch/time-contradiction/state-mismatch/role-object-mismatch/combo-invalid), and 1 concurrency (interleaved). Pass `include_extended=False` to restrict to the base 5.

Supporting modules (all pure, no I/O; **framework-only** — not present in vault):

- **`product_state.py`** — Tracks product variables with observed/inferred source provenance and producer-consumer lineage. `strict_variables()` excludes inferred values so guards return `unknown` without observation evidence.
- **`post_conditions.py`** — Event-triggered post-condition checks (RESTler Checker pattern): `after_error`, `after_revoke`, `after_delete`, `after_one_time_op`, `after_data_modify`, `after_cancel`. Each check spec ties back to an invariant ref.
- **`sequence_minimizer.py`** — Hypothesis-inspired minimal failure sequence reduction with 4 strategies (remove-single, reduce-repeat, simplify-input, prefix search). Callers implement `ResetAdapter` for isolated replay; `minimize_auto()` drives the full loop. Only accepts candidates that trigger the same invariant violation.
- **`trace_integration.py`** — Wires ProductState, PostConditions, and DependencyTracker into trace execution. `before_step` evaluates guards; `after_step` updates state and auto-triggers post-checks; `shared_data_analysis()` identifies multi-step read/write contention for race condition candidates.

Operational modules (all pure, no I/O; **framework-only** — not present in vault):

- **`state_reset.py`** — Initial state and reset contract. `ResetContract` defines expected initial values and forbidden fields; `RoundTracker` manages multi-round test sessions with per-round verification and cross-round `contamination_check()`.
- **`async_completion.py`** — Async completion judgment. `AsyncTracker` tracks operations through accepted → processing → completed/timed_out/failed; `premature_verdict_check()` prevents judging before an operation is terminal; `check_deadlines()` enforces bounded observation.
- **`result_classifier.py`** — Step result classification into 6 categories (tool_failure, environment_failure, blocked, expected, unknown, suspected_violation), each with a prescribed follow-up. `check_partial_effect()` detects error responses that still changed backend state.
- **`research_boundary.py`** — Research completion boundary. Tracks verified/untested/blocked/retired items, unexplained anomalies, and residual risks. `is_complete()` requires explicit accounting — an empty queue alone is not completion.

## Optional GraphWalker

The offline adapter targets upstream `graphwalker-rs` tag `v.1.0.4`, commit `be3810ea0577f44fe36b9c209d9db7cb70e0e8c8` (MIT). Build separately with `cargo build --locked --release -p graphwalker`; no binary is bundled.

```sh
python3 automation/flow_model.py TARGET plan --flow-id FLOW \
  --graphwalker-binary /PATH/TO/graphwalker --length 20 --seed 42
```

It runs model checking and bounded offline generation, validates returned identifiers and continuity, and records a revision-bound `flow_external_plan`. macOS invocations deny network with the OS sandbox; other platforms must supply their own isolation. Expected guard metadata never becomes executable engine code. Generated paths establish neither actual execution nor security coverage.

## Attack Flow export

```sh
python3 automation/attack_flow_export.py TARGET --output NEW_BUNDLE.json
python3 automation/attack_flow_export.py TARGET --include-pending --output NEW_PLAN.json
```

Requires/provides dependencies become actions, conditions and multi-prerequisite AND operators. Default export selects currently supported subjects; pending inclusion is explicit and labelled. Outputs retain proof-descriptor fingerprints, never raw private evidence. No ledger mutation or overwrite is performed.

Pinned Attack Flow 2.0.0 / STIX 2.1 schemas, extension objects, hashes, source commits and licenses live in `automation/schemas/attack-flow/`. Validation is offline. The upstream generic bundle dispatcher omits extension-definition and rejects the official extension through its core/SCO oneOf: this adapter retains the official envelope constraints and explicitly validates every supported object against its original official schema, then checks IDs and references.

## Owned browser fixture

`automation/labs/sharing_browser_lab.py` is an intentionally broken, synthetic loopback sharing application. `run_sharing_ui.cjs` optionally drives visible controls through a separately installed Playwright CLI wrapper. Source/replay sessions preserve distinct TEST/CONTROL traces and identifier origins. Keep all generated captures and ledgers outside this public seed. This is a test fixture, not a real target exploit or general GUI executor.

## Context precision modules

Two cross-cutting modules reduce model token usage while preserving research quality:

**ContextSelector** (`context_selector.py`, **vault-only**): shared entry point for both `hunt_worker` and `work_dispatch`. Selects data by work type (`hunt_comparison`, `report_review`, `candidate_analysis`, `dedup_check`), enforces required/optional field declarations, deduplicates evidence refs, trims snippets to budget, and auto-summarizes `flow_context` to judgment-relevant fields only. `deterministic_checks()` runs file-existence and version-match validation without model calls.

**ContextHygiene** (`context_hygiene.py`, **vault-only**): controls sensitive data flow across session boundaries. Write-side `MemoryFilter` with field whitelist and sensitive-pattern redaction. Three-stage read loading (routing → task selected → evidence access). `CanaryTracker` for synthetic-marker leak detection across cross-session flows. `sanitize_startup_output()` for startup script output staging.

**CredentialBacktest** (`credential_backtest.py`, **vault-only**): ASG-native credential re-exploitation loop. When `discovery_feedback()` detects new credential capabilities (`P:cred/token/key/secret`), generates backtest hypotheses against all known auth-gated endpoints. `spray_hypotheses()` runs in the templater replan cycle to cover the full credential×endpoint cross-product. `credential_spray_summary()` reports coverage metrics.

**Browser verification routing**: `LogicHypothesis.verification_mode` ("api"|"browser") controls dispatch path. `BROWSER_SURFACE_TEMPLATES` in `hyp_templates.py` auto-generates browser-mode hypotheses for redirect/CORS/XSS surfaces. `hunt_autodrive.py` defers browser hypotheses to `human_gate` for routing to web-hunter or OBU. `DriveReport.deferred_browser` tracks deferred hypothesis IDs.
