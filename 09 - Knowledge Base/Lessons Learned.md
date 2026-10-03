---
fileClass: KB
tags: [lessons, meta]
---

# Lessons Learned

Rolling log of what worked, what didn't, and what to do differently next time.

---

## Template

```markdown
### #NNN — Title (YYYY-MM-DD)

**Context:** What were you doing?
**What happened:** What went wrong or right?
**Lesson:** What will you do differently?
**Tags:** #lesson/recon, #lesson/reporting, #lesson/tooling, #lesson/triage
```

---

## Lessons

### #001 — A gate on the source file is not a gate on the artifact you ship (2026-10-03)

**Context:** Finalizing a submission package: report content lives in Markdown, but the
vendor receives a `.docx` generated from it. Several Markdown lint gates were all green.
**What happened:** Two separate defects shipped anyway, both in the Markdown→docx step
that no gate watched: (1) four `.docx` files were generated *before* a sentence was
deleted from the Markdown, so the deleted text was still inside the Word files; (2) a
field referenced an internal screenshot filename that was embedded, not attached, so the
reader would hunt for an attachment that does not exist. The Markdown was clean; the
shipped artifact was not.
**Lesson:** Gate the file you actually ship, not its source. Every transformation between
source and deliverable (templating, export, packaging) adds metadata and content of its
own and is unwatched by default. Add a check that reads the deliverable itself (here: a
gate that opens the `.docx` — staleness vs source mtime, stray filenames, embedded vs
attached, redaction residue).
**Tags:** #lesson/reporting, #lesson/tooling

### #002 — Proxy signals are not truth: status code / line count / memory / stale notes (2026-10-03)

**Context:** One session, several independent decisions each resting on a cheap proxy for
the real thing.
**What happened:** Four times the proxy was wrong. (1) Downloaded 43 "chunks", all HTTP
200, reported "43/43 downloaded" — all were the SPA fallback `index.html` (1373 bytes
each), zero real chunks. (2) `grep -c` counted 8 docx — 7 files plus one folder path
line. (3) Stated from memory that an archive was "packed before the fix" — extracting it
showed it was current. (4) A graph note labelled an endpoint an "IDOR oracle (leaks
order IDs)"; a single probe showed it was a write endpoint. Same shape every time: a
cheap proxy (status code / a count line / memory / an old note) stood in for actually
opening the content.
**Lesson:** Before concluding, ask: "am I trusting the content itself, or a signal that
stands for it?" If the latter and the conclusion matters (submission counts, coverage,
whether a finding holds), open the thing. Verify fetched files by content not status
code; count from structure not text lines; verify built artifacts by opening them, not
from memory or mtime; treat old notes as leads, re-test before citing.
**Tags:** #lesson/recon, #lesson/triage, #lesson/tooling
