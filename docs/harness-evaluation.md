# Harness evaluation

```sh
python3 automation/harness_eval.py
python3 automation/harness_eval.py --export-inputs
python3 automation/harness_eval.py --responses RESPONSES.json
```

Seven synthetic fixtures cover a positive signal, public-marker false positive, missing CONTROL, tool failure, expired evidence, possible duplicate root cause and malformed output. Default mode checks handcrafted references without calling a model. The malformed-output item is a deterministic parser control, not a request for a model to generate invalid output.

Exported inputs exclude expected assessments, reference answers and next-step oracle terms. Scoring checks supplied citations, exact observation/inference format, lexical discriminators and preserved uncertainty. It does not establish semantic correctness, real false-positive rate, improved discovery, or total task-token savings.

## Opt-in live comparison

```sh
python3 automation/harness_live_eval.py --output PRIVATE_OUTPUT_DIR \
  --baseline BASELINE_PROMPT --model CONFIGURED_MODEL \
  --processing-location CONFIGURED_LOCATION --policy-ref OPERATOR_POLICY_REF \
  --budget-usd 0.20 --timeout 120
```

Requires your own configured Claude CLI/authentication and explicit processing authorization. Only synthetic public inputs are sent. The runner has no tools/MCP, bounds each call, records cost/usage receipts when available, and pins prompts/configuration/fixtures. A writer lease prevents concurrent use of the output directory. Resume does not automatically repeat completed or failed attempts; changed configuration needs a new directory. A crash after provider completion but before saving its receipt needs manual reconciliation.

No account, credentials, runtime receipts, author-specific model scores or transcripts are shipped. Canonical candidate-role SHA-256 changes make prior analysis stale. Ranking/retrieval checks use small controlled corpora and are not representative benchmarks. Measure complete task cost, missed cases and invalid retries before removing additional core instructions.
