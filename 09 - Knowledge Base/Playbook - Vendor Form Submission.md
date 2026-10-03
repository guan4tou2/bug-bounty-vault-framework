---
fileClass: Playbook
title: "Vendor Form Submission"
type: playbook
trigger: "turning verified findings into a vendor's intake form; preparing a submission batch; 'how do I package this for the vendor'"
tags: [reporting, submission, workflow]
---

# Playbook — Vendor Form Submission

End-to-end process for turning verified findings into a vendor's Word/PDF intake form and
shipping them, without the markdown and the shipped file drifting apart. The content
standard is `Reference Card - Report Writing Standard`; the tools and gates referenced
below live in `automation/`.

## Why this exists as a pipeline

The source of truth is the FORM markdown; the vendor receives a generated `.docx`. The
markdown→docx step is unwatched by the markdown gates, so defects ship through it (stale
docx, leaked filenames, un-redacted PII). This pipeline makes the deliverable, not just
its source, the thing that gets gated.

## Layout (conventions `check_submission_layout.py` enforces)

```
Submissions/
  Forms/
    FORM - <ID> - <title>.md   one per finding, the source of truth
    _form-template.docx        your vendor's Word form (fixed path, NOT inside a batch dir)
    <batch>-docx/              generated docx to send, one folder per batch
    <batch>-submitted/         renamed after sending; gates stop checking it
    <batch>.7z                 archive sits NEXT TO the folder it archives, not inside
    email-<batch>.md           the cover letter for that batch
    _withheld/                 docx decided not to send
  ../Evidence/                 all evidence files, this one place only
```

## Steps

1. **Write each FORM markdown** per `Reference Card - Report Writing Standard`: only the
   form's fields, verbatim request/response in the evidence field, lean, no invented
   sections. Screenshots are referenced in the image field as `` - `shot.png` — caption ``
   (the filename locates the image for the renderer; only the caption ships).

2. **Lint the markdown:** `bash automation/run_checks.sh report <target>` →
   `check_report_quality.sh`. Fix HARD issues before rendering.

3. **Render the docx:** `python3 automation/form_to_docx.py "Forms/FORM - *.md"
   --template Forms/_form-template.docx --out Forms/<batch>-docx`. The template is YOUR
   vendor form (there is no default). The renderer embeds screenshots, drops filenames
   from the body and from image metadata, and strips any media/thumbnail inherited from
   the template (so one finding's screenshot can't leak into another's report).

4. **Gate the shipped docx** (NOT just the markdown):
   `python3 automation/check_docx_package.py --target <target>` — catches a docx older
   than its source md, stray filenames in body or image metadata, unattached-file
   promises, explanatory padding, and a screenshot field with no image.

5. **Gate the layout:** `python3 automation/check_submission_layout.py <target>` —
   duplicate batches, archive in the wrong place, orphan evidence, a ready cover letter
   with no batch folder.

6. **Package & send:** archive `<batch>-docx/` to `<batch>.7z` (sitting beside it), attach
   it with the cover letter `email-<batch>.md`. (No email tool here — a human sends.)

7. **After sending, mark state in one command** (don't rely on memory):
   `bash automation/mark_submitted.sh <target> --batch <batch>-docx <ID> <ID> ...` —
   flips each FORM to `status: submitted` + `submitted_date`, renames the folder to
   `-submitted`, logs a ledger event. A FORM left at `ready` gets packaged again next batch.

8. **PII cleanup** per the program's ROE (e.g. a 24-hour deletion commitment): delete local
   un-redacted copies (screenshots, docx, archives), and redact the evidence text files
   that stay in the repo with `automation/redact_evidence.py` (then a second format scan
   for IDs the key-based pass missed). Reply to confirm if your ROE requires it.

## Adapting to your vendor form

- `_form-template.docx` is your vendor's actual Word form. `form_to_docx.py` clones its
  table formatting and fills `## sections` / `| label | value |` rows from the markdown.
- If your form's field names or language differ, set `BB_FORM_HEADERS` (header-row labels
  to skip), `BB_IMAGE_FIELD` (which field embeds images), and `--prefix` (output filename).
- `check_docx_package.py`'s phrase lists (padding, unattached-file promises, screenshot
  keyword) default to English and are overridable via `BB_DOCX_PADDING` /
  `BB_DOCX_PROMISES` / `BB_DOCX_SCREENSHOT_KW`.
