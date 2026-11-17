# Conditional flows and evidence-backed traces

ASG retains research hypotheses, evidence and Finding state. The existing `delivery_record.flow` authority describes product actors, object ownership/relationships, identifier origin, states, entries and transitions. Case/trace events share that ledger; no graph database is required.

```sh
python3 automation/flow_model.py TARGET define --input FLOW.json
python3 automation/flow_model.py TARGET plan --flow-id FLOW --focus-transition TRANSITION
python3 automation/flow_model.py TARGET bind --case-id CASE --hyp-id HYPOTHESIS --invariant-ref INVARIANT
python3 automation/flow_model.py TARGET view
```

Targets need existing genesis and invariant records. Cases distinguish normal, skip/repeat, actor and entry boundaries. Actual steps pin separate pre/action/post artifacts, observed product state, actor/object/entry and identifier source. Reproduction needs its own TEST/CONTROL evidence and runner identity; it never sets Finding verification.

An optional transition `predicate` supports bounded `all`/`any` and typed `eq`/`ne`/`in` field comparisons. Missing variables return `unknown`; no expressions or arbitrary scripts are evaluated. A false product guard remains a possible negative security test, subject to existing authorization. Product expectations never overwrite observations or research conclusions.

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
