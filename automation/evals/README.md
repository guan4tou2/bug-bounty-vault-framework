# automation/evals — promptfoo skill evals (reference skeleton)

Optional. Two purposes — **regression** (a prompt edit doesn't break known-good
cases) and **model-tiering validation** (run the same prompt across model tiers,
compare pass-rate + cost → turn "can a cheaper model do this task?" from a guess
into a measured answer). This is the "measure" half of the closed loop applied to
your own skill prompts — not a tool for testing target LLMs.

## Scope rule (don't expand past it)

Only skills with an **input → checkable output** contract belong here:

| In | Out |
|---|---|
| CVSS scoring (desc → vector + score) | surface mapping / exploit chaining / scope-safety |
| classification (reply → label) | knowledge capture |
| structured-JSON return contracts | anything whose output is multi-step + has side effects |

Behavioral skills test poorly in an isolated API (no tooled runtime, low
fidelity); cover them with your gates + real-target runs. Expanding this suite to
every skill just creates maintenance debt.

## Run

Needs your own `ANTHROPIC_API_KEY` (promptfoo calls the API directly). promptfoo
is a node tool — use `npx`, no install:

```bash
cd automation/evals
export ANTHROPIC_API_KEY=...
npx promptfoo@latest eval
npx promptfoo@latest view     # matrix: pass-rate / cost / latency per model
```

## Reading the model-tiering result

Each row = a test, each column = a model tier. Compare **pass-rate per column**:
if a cheaper tier matches the strong tier on a task, downgrading is safe; if it
drops (e.g. miscomputed CVSS), keep that task on the stronger tier. promptfoo also
reports token/cost per model — the quality-vs-cost trade-off you can't get by
reading docs.

## Empirical note (worth knowing before you trust prompt instructions)

"Output ONLY JSON / ONLY X" is **format-following, not capability** — the strongest
models tend to add a preamble while cheaper ones return clean output. So for
structured returns, **enforce the structure mechanically** (a schema/validation
step), don't rely on the prompt instruction regardless of model strength.

## Notes

- `prompts/skill_runner.js` loads the real skill file (no drift).
- Replace the provider IDs with the models you actually use.
- Run artifacts/cache are gitignored; the config + prompts are kept.
