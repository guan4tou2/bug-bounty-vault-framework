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
