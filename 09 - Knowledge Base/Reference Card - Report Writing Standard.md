---
fileClass: ReferenceCard
title: "Report Writing Standard"
type: reference
trigger: "writing a finding report / vendor form; 'is this ready to send'; deciding what to include; report feels long or defensive"
tags: [reporting, submission, methodology]
---

# Report Writing Standard

Discipline for writing a finding report the vendor/program actually wants. Each rule below
came from a real mistake. The machine checks are `check_report_quality.sh` (per-FORM),
`check_docx_package.py` (the shipped docx), and `check_submission_layout.py` (folder layout).

## Structure & wording

### Only the fields the form has
If the program gives an intake form, fill exactly its fields — do not invent extra
sections. An invented "methodology" or "re-test statement" block is a field the reviewer
did not ask for and did not budget attention for. Ratings/severity, if the form has no
field for them, go in the cover letter, not a new section.

### The evidence field holds evidence
A field named "request/response" or "proof" holds the **actual** request and response
(verbatim), not a prose summary of them. Earlier batches that did this read as evidence;
a summary reads as a claim.

### Don't promise files you don't attach
If a screenshot is embedded in the report, it is NOT a separate attachment — so don't
write "see attached file X" or name its filename. The reader will hunt for an attachment
that doesn't exist. (The filename is for your render tool to locate the image, not for the
reader.)

### A report answers three questions — delete the rest
Where is the bug · what does it cause · how to reproduce (and how to fix). Everything else
is reading overhead. Banned shapes:

| shape | example |
|---|---|
| score defense | "the reason we rate Confidentiality Low not High is that we only proved…" |
| methodology confession | "we do not infer impact from the vulnerability class, only from observed results" |
| polite meta | "duly noted", "stated hereby to avoid any misunderstanding during your review" |
| self-correction narrative | "we initially suspected X, testing disproved it" → just write the conclusion "supports GET only" |
| two-layer headings | "**(1) request sent as the server**<br>the request originates from…" → "(1) the request is sent by your server." |

Default to **no explanation** and an empty Notes field. Add a note only when the reader
cannot act without it, and write it as a plain statement, not a framing.

### "Re-test" is a word for after you submit
Running your own check again before submitting is **verification**, not a re-test. "Re-test"
means the vendor fixed it and you checked the fix. Using it wrong implies a second round
that didn't happen, and makes "you have patched this" unsupportable.

## Sentence-level rules (ASD-STE100 subset)

The rules above govern *what goes in the document*. These govern *how each sentence is
built*. They are a subset of ASD-STE100 (Simplified Technical English), the controlled
language written for aircraft maintenance manuals, where a misread sentence has a physical
cost. A finding report has the same property: the reader is often not the person who wrote
the code, and may not be a native speaker of the language you wrote in.

| Rule | What it means |
|---|---|
| One word, one meaning | Each noun and verb has exactly one reading. No rhetoric, no idiom, no subjective adjectives. |
| Active voice | "The program copies the value", not "the value is copied". Passive voice hides the actor, and the actor is the whole point of a security report. |
| Sentence length | Descriptive sentences: one clause, one idea. Instruction steps: shorter still. If you need a comma to join two actions, make it two sentences. |
| One idea per sentence | A sentence states one action or one concept. |
| Consistent terminology | One component, one word, for the whole document. No synonym variation — once you pick "buffer", never write "temporary store" for the same thing. |

> **Consistent terminology matters more than it looks.** A reader who is not a specialist
> reads three words for one component as three components. Synonym variation is a habit
> that good prose style actively teaches, and it is wrong here.

### Do not use metaphors

No "it is like", "think of it as", "this is essentially the equivalent of". To explain a
mechanism, state the mechanism: who, at what moment, made what decision. Do not switch to
a different scene to explain it.

### Code blocks are for commands

| Content | Form |
|---|---|
| A directly runnable command | fenced block, **one command per block** |
| Quoted source code from the target | fenced block with the language tag |
| Values to be copied verbatim (URLs, parameter strings) | fenced block, no language tag |
| **Everything else** — description, reproduce prose, notes, remediation | plain paragraphs and tables |

Wrapping a whole field in one big fenced block is a copy-paste habit from form-filling. It
makes the evidence and the prose look like the same kind of object, which is exactly the
distinction the report needs to keep.

### Partitioned application — the rule that keeps this from backfiring

**Do not apply the sentence rules to statements of uncertainty.**

ASD-STE100 was written for maintenance manuals, which assume the facts are settled. Half
the value of a security finding is its **calibrated uncertainty**. Compressing "most likely
unreachable; the residual uncertainty is the content of the factory environment block" into
a short declarative sentence produces "unreachable" — an inference rewritten as a fact.

| Apply the sentence rules | Do not apply them |
|---|---|
| Summary, mechanism, affected code, reproduce steps, remediation | Reachability assessment, evidence tiering, per-metric severity rationale, known gaps |

In the second column, keep the hedging words: *most likely*, *not confirmed*, *could not be
determined*, *this report does not claim*. A hedge is not padding; it is the evidence tier,
written in words.

> **This does not contradict "delete the rest" above.** That rule bans the *narrative of how
> you reached the conclusion* (score defense, self-correction story, methodology confession).
> This rule preserves the *hedge attached to the claim itself*. Ban the journey, keep the
> error bar.

## Conclusion vocabulary

State conclusions with **a number and an existing term**. Do not invent a word that sounds
professional.

The vocabulary already exists — reuse it instead of coining one. `automation/asg.py` defines
`FINDING_STATES` as the progression `hypothesis` → `tested` → `adversary-verified` →
`confirmed`, and a recorded verdict is one of `confirmed` / `refuted` / `inconclusive`.
Reports, finding files, and status updates use those words.

| Invented euphemism | Write instead |
|---|---|
| "negative convergence", "net result", "consolidation of findings" | "6 refuted after review, 2 severity reduced" |
| "overall posture is sound" | "this assessment found no issues above Medium" |

> **Euphemism is overclaiming in a lighter form, and it is the harder one to catch.**
> "Negative convergence" sounds like progress. It means "half of what we reported was
> wrong." The reader cannot parse the phrase but can parse the number.
>
### The impact ladder

Impact wording has its own ladder. Each rung is a different claim needing different
evidence, so using a higher word than you earned is an overclaim:

*reachable* → *accepted* → *statement produced* → *record created* → *executed* →
*data retrieved*

The two rules are a pair. The ladder stops the **strength of the impact** from skipping a
rung; the section above stops the **wording of the conclusion** from being packaged.

### The floor: register may change, evidence tier may not

Whatever register you write in, these stay literal:

| Must stay literal | Must not become |
|---|---|
| "This assessment **did not retrieve** any user data" | "data was not retained", "no further access was taken" |
| "This is an **architectural inference, not a direct proof**" | "impact is assessed as unlikely" |
| "**Not verified**" / "**not demonstrated**" | "initial indications suggest", "appears to be safe" |

Test: **raising or lowering the register may change the sentence shape; it may never change
a claim's evidence tier.** If a reader of the rewritten sentence can no longer tell
"verified" from "inferred", the rewrite broke it.

## What is worth submitting

**Submit** — there is actual exploitation evidence: a result was observed (data read that
isn't yours, a state change, code executed, a credential used downstream). The impact
sentence is backed by an observation, not by the vulnerability's name.

**Don't submit** (or record as a lead, not a report) — theoretical derivation or pure
information gathering: a version-to-CVE match with no PoC, an error message read as a
bypass you didn't achieve, something "public by design".

**Grey area (case by case):** information disclosure that is only an enabler for a bigger
chain — keep chaining; report it standalone only if it stands on its own.

> One root cause = one fix = one report. Before splitting into N reports, ask: "can the
> vendor close all of them by changing one place?" If yes, it's one report.

## Length

Lean. The vulnerability description is 2-3 sentences; impact is 1-3 one-sentence points;
reproduce is 2-4 steps; request/response is 1-2 pairs (a success plus a contrasting
failure). Reproduce steps and raw request/response are **not** length-capped — they should
be as long as they need to be. Everything else is.

## Before you send, ask

- Is every claim backed by an observation in the evidence (not by the bug's class)?
- Could the vendor reproduce it from the steps alone, with nothing from my head?
- Is there any invented section / unattached-file promise / explanatory padding?
- Did I verify the **shipped artifact** (the docx/pdf), not just its markdown source?
- Is all third-party PII redacted in text, and are embedded-image leaks handled?
