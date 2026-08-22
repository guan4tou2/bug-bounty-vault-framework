# Context Engineering

How to write the guidance layers in this repo (`CLAUDE.md`, skills, agents, tool descriptions) so they help rather than hurt. Read this before editing any of them.

Source of the frontier-model rules below: [The new rules of context engineering for Claude 5 generation models](https://claude.com/blog/the-new-rules-of-context-engineering-for-claude-5-generation-models).

## Calibrate to your model first (read this before the rules)

This framework is **model-agnostic** — you may drive it with a strong frontier model, a small/local model, or a non-Claude model. The single most important rule is that **how much to constrain depends on the model's capability**:

- **Strong frontier models** (e.g. Claude 5 generation): need **far fewer** constraints. Over-constraining suppresses their judgment. Anthropic removed 80%+ of Claude Code's system prompt with no loss in performance. Trust the model within clear parameters; hand it goals, not scripts.
- **Small / weaker / non-Claude models**: need **more** explicit scaffolding, not less — worked examples, step-by-step gates, tighter guardrails, and repeated safety reminders. Stripping constraints degrades them and raises the risk of skipped safety gates. Keep the scope-guard, GET-first, and stop-condition rules explicit for these models even when a stronger model would infer them.

So treat "remove constraints / trust judgment / drop examples" below as **capability-dependent**, not universal. When in doubt about the operator's model, keep the guardrails.

Some principles are universal regardless of model strength — progressive disclosure, no repetition, no derivable content, high-fidelity references. Those are marked **[universal]**.

## Six old → new shifts (strong-model calibration; soften for weaker models)

| Old approach | New approach (for capable models) |
|---|---|
| Rigid guardrails ("never write multi-paragraph docstrings") | Judgment-based guidance ("write code that reads like the surrounding code — match its comment density, naming, and idiom") |
| Many usage examples per tool | Design intent into the **parameters and interface** (enums, constraints imply usage). *Weaker models still benefit from examples — keep them.* |
| Front-load every rule | **Progressive disclosure**: load via a skill / deferred-loading tool only when needed **[universal]** |
| Repeat one instruction across system prompt, tool description, and skill | State it in exactly one place (tool guidance lives in the tool description) **[universal]** |
| Hand-copy knowledge into CLAUDE.md | Let auto-memory capture what is relevant — *where the harness supports it; otherwise keep a lean manual note* |
| Plain-markdown specs | High-fidelity references: real code, tests, rubrics, mockups **[universal]** |

## How to write each layer

**System prompt** — bind product/role context (what this agent is and what it operates on). Worth polishing for custom agents.

**CLAUDE.md** — lightweight **[universal]**. Put only **gotchas and non-obvious patterns**. Do not write what a session can reconstruct from the file tree (basic architecture, dependency lists, standard build commands); do write things like "there is one monolithic types file here" or "X looks safe but does Y". Point complex rules to a separate skill or reference file via links. Safety-critical prohibitions (scope guard, stop conditions) stay explicit — never trade those away for brevity, especially for weaker models.

**Skills** — a lightweight guide for "where to find information when needed", not a straitjacket. Split long skills into multiple files with layered loading. A good home for team opinions and hard-won experience. For weaker models, prefer skills with concrete step-by-step procedures over terse principles.

**Tool design** — document parameters fully; use enumeration / constraints to convey intent; put behavioral guidance in the tool description; route rarely-used tools through deferred loading **[universal]**.

**References** — prefer code, tests, and mockups over prose **[universal]**. Specs, mockups, and whole codebases can be handed in as references.

## Anti-patterns

- **Over-constraining a capable model** — system prompt / skill / user request contradict each other and suppress judgment. (Note: the opposite failure — under-scaffolding a weak model — is just as real.)
- **Repeated instructions** — the same rule restated across multiple context sources. **[universal]**
- **Up-front complexity** — loading everything regardless of relevance. **[universal]**
- **Manual memory burden** — forcing hand-copied learnings where auto-memory would capture them.
- **Static, thin references** — plain markdown where code or an interactive artifact would be clearer. **[universal]**

## Designing for interruption and failure (capability-dependent — keep the scaffolding explicit for weaker models)

Agent sessions get cut off, context gets reset between stages, and network/API calls fail in ways that look identical to "nothing was there." Three design principles guard against the resulting silent losses. A strong frontier model can often infer these; a weak model needs them spelled out as literal step ordering, not just stated as intent — so keep the worked examples below even when trimming other guidance.

### 1. Persist durable findings before running slow or flaky verification steps

Write what you've already discovered to durable storage (a Finding, RECON_DB.md, an operation-log row, a report table row) **before** starting the next, slower or less-reliable step that might time out or fail. An agent that persists-then-verifies survives an interruption with its findings intact; an agent that verifies-then-persists loses everything if the verification step is what runs out of time.

Worked example (already applied in `bb-retest-gate`): Phase 1 (direct PoC replay, fast) writes each finding's verdict to the report table and the regression-script library **immediately**, before Phase 2 (variant/bypass testing — slower, multi-payload, more failure-prone) starts on that finding. If Phase 2 times out on finding #7, findings #1-6's Phase 1 verdicts are already durable and the report is still usable.

**Anti-pattern:** running the full slow verification pass across every candidate first, and only writing results to the Finding/report at the very end — a mid-run interruption then discards everything, including the fast, already-confirmed results.

### 2. Make each pipeline stage self-contained — don't trust upstream handoff to survive

A downstream stage (a new session, a takeover, a later phase of the same pipeline) should never assume the upstream notes it depends on (HANDOFF.md, an in-progress block, a prior agent's summary) will always be present and intact. Context gets reset, truncated, or lost between stages. Every stage that depends on a handoff artifact needs an explicit **degraded-input path**: what to do when that artifact is missing, empty, or looks truncated, not just the happy path where it's there and well-formed.

Worked example (already applied in `bb-context-handoff`): the takeover process checks for a `BEGIN_INPROGRESS` block and branches on whether it exists — but a weak model implementing something similar should go one step further and also handle the case where the *whole file* is missing or corrupted (crash mid-write), not just "block absent." The fallback there: reconstruct minimal context from RECON_DB.md + `git log`, proceed as a normal (non-takeover) claim, and say so up front rather than blocking or guessing.

**Anti-pattern:** a skill/agent prompt that reads "load `<upstream-file>` and continue from where it left off" with no instruction for what to do if that file doesn't exist, is empty, or is half-written.

### 4. Distinguish "the approach is wrong" from "the tool/model/environment failed"

A failed tool call, an empty API response, a timeout, a dead/expired credential, or a weak model silently giving up can produce output that looks exactly like "I tried thoroughly and found nothing." Before concluding a technique doesn't work or a target is clean, explicitly check for the failure signature first (non-2xx transport error, 0-byte body, connection reset, auth-expired response, empty tool-call result) and route it to an *inconclusive* bucket — never merge it into the same bucket as a genuine, positive-evidence negative result.

Worked example (already applied in `regression-tester`): its outcome table has a dedicated `inconclusive — host down` / `inconclusive — rate-limited` classification, kept separate from `patched` (a real negative result requires the *original vulnerable signature* to be absent from a *successful* response — a timeout or 429 proves nothing either way).

**Anti-pattern:** a batch scan that treats "0 hits" and "50% of probes errored out" as the same "clean" result. Report the error rate alongside the finding count so a 0-hit result backed by 50% failed probes reads as *inconclusive*, not *clean*.

## Tooling note

`claude doctor` (CLI, Claude Code only) is an **installation** health check — it does not analyze prompt/skill redundancy. Trimming redundant guidance is a manual review: compare rules across files and remove duplicates, following the layer guidance above. This applies whatever model or harness you drive the framework with.
