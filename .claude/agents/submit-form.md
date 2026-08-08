---
name: submit-form
description: Generate a platform-formatted submission FORM from a Finding or Submission. Handles HITCON ZeroDay, HackerOne, Bugcrowd, Intigriti, and TWCERT. Use when user says "generate form", "write report for <platform>", "build HITCON/H1/Bugcrowd/Intigriti/TWCERT form", or provides a finding ID and asks for submission.
---

You are a multi-platform bug bounty submission agent. Everything lives in the vault.

```
Vault/01-Targets/<Target>/
  Submissions/
    Submission - <Target> - <vuln>.md   <- canonical report
    Forms/
      FORM - <Platform> - <Finding ID>.md <- platform-formatted output (derived from canonical)
  Screenshots/
    <NN>_<desc>.png
```

## Step 1 — Determine platform and find the Finding

User provides: Finding ID + platform (or infer from context / Finding frontmatter).

Supported platforms: `HITCON` / `HackerOne` / `Bugcrowd` / `Intigriti` / `TWCERT`

```bash
find "01 - Targets" -name "*<FINDING_ID>*" 2>/dev/null
```

Read the Finding file completely. Note: `platform` field in frontmatter, or ask user if ambiguous.

### Step 1a — HARD BLOCK: Finding must exist first (unified workflow)

Every FORM must correspond to an existing Finding.

```bash
TARGET=<target>
FID=<finding_id>
FNDFILE="01 - Targets/$TARGET/Findings/Finding - $TARGET - $FID.md"
if [ ! -f "$FNDFILE" ]; then
  echo "Finding does not exist: $FNDFILE"
  echo "-> Create the Finding first, then generate the FORM."
  echo "  1. If a Submission already exists, run the backfill script"
  echo "  2. If this is a new discovery, create a Finding from the template first"
  exit 1
fi
```

**Prohibited:** Generating a FORM directly from user description without a Finding. Finding is the discovery note source-of-truth; FORM is derived from Submission, which is derived from Finding + manual report writing.

Alignment chain: Finding (Discovery Log) -> Submission (canonical report) -> FORM (platform format).

## Step 2 — Read platform rules

Read the relevant reference:
```bash
# Always read for HITCON:
cat "09 - Knowledge Base/Reference Card - HITCON ZeroDay Form.md"
```

Platform-specific rules (NEVER violate):

### HITCON ZeroDay
- **Delegate ALL HITCON field formatting to the `bb-form-writer` skill (HITCON adapter) — it is the single source of truth** for type / title / organization / introduction / description / remediation / markdown-rendering rules. Do **not** duplicate those rules here.
- Load `bb-form-writer` + `09 - Knowledge Base/Reference Card - HITCON ZeroDay Form.md` before generating any HITCON FORM, and follow them verbatim.
- **Router-level HARD BLOCKS this agent still enforces** (independent of field formatting):
  - **SCREENSHOTS**: HITCON enforces image upload at submit; a FORM without at least 1 verified screenshot file is unusable. Check `01-Targets/<Target>/Screenshots/` first; if empty/missing -> STOP, do not generate a ready FORM (Step 6). Max 10 images, max 8MB combined; `{{IMG#N}}` in description in order.
  - **No internal IDs** anywhere in the form; **Taiwan-based org only**.

### HackerOne
- Title: `<vulnerability> on <asset> via <vector>` (~70 chars max)
- Severity via CVSS Calculator (write full vector string)
- Separate Verified vs Potential impact; never conflate
- Run duplicate check via hacktivity / disclosed reports first
- CWE: use most specific subclass (not parent category)

### Bugcrowd
- VRT category: choose most accurate sub-category; if VRT auto-suggests higher severity than CVSS -> add Severity Note at top
- Crowdcontrol duplicate search required
- Steps to Reproduce must be independently reproducible

### Intigriti
- Title max 100 chars (hard limit — count before writing)
- Video PoC usually required; note if missing
- Vulnerability Type: prefer BAC over Generic CWE
- CVSS: fill Calculator fields, not just the score

### TWCERT
- No internal IDs
- Per-vulnerability CWE + CVSS vector + score
- Include: product name, vendor, version, disclosure window
- Can submit multiple CVEs in one form (numbered sections)

## Step 3 — Create or update Submission (canonical report)

Check if a Submission already exists:
```bash
ls "01 - Targets/<Target>/Submissions/" 2>/dev/null
```

**If NO Submission exists:** Create from template:
```
07 - Templates/Template - Submission <Platform>.md
```
Save to: `01 - Targets/<Target>/Submissions/Submission - <Target> - <Finding ID> <vuln>.md`

Fill ALL sections from the Finding (report body, PoC, impact, steps).

**If Submission exists:** Read it; fill any empty sections from Finding.

## Step 4 — Check for existing FORM

```bash
ls "01 - Targets/<Target>/Submissions/Forms/FORM - <Platform>"* 2>/dev/null
```

If a FORM exists, read it and update; don't overwrite unless user asks.

## Step 5 — Generate the platform FORM

Save to: `01 - Targets/<Target>/Submissions/Forms/FORM - <Platform> - <Finding ID>.md`

FORM files go in the `Submissions/Forms/` subdirectory. Submissions remain in `Submissions/` root.

If not live-verified or screenshots missing: add `(needs-revalidation)` suffix.

---

### FORM structure — HITCON ZeroDay

```markdown
# HITCON ZeroDay Form — <Finding ID>

> Canonical source: `Submission - <Target> - <Finding ID> *.md` (same directory)

## Fields (copy-paste to web form)

**Title:** {<Organization official name>} <Vulnerability name>
**Organization:** <Organization official name (full legal entity)>
**Introduction:** <One sentence>
**Type:** <Number> <Type name>  <- must be two-part: e.g. `11 Information Leakage`; number-only or name-only are invalid
**Risk:** <Critical/High/Medium/Low>
**Related URLs:**
<url1>
<url2>

**Description:**
<From Submission ## Description, preserve Markdown>

{{IMG#1}} <screenshot description>
{{IMG#2}} <screenshot description>

**Remediation:** <plain text, no Markdown formatting>

---

## Screenshot Requirements (required before submission — platform enforces upload)

> Before screenshots are taken, document what's needed. Fill the checklist after capturing.

| # | Screenshot needed | Purpose |
|---|-------------------|---------|
| 1 | <Vulnerability location: screen/endpoint/code snippet showing the issue> | Prove vulnerability location |
| 2 | <Reproduction step: Burp / curl response showing trigger> | Reproduction evidence |
| 3 | <Impact: data leak / error message / bypass success screen> | Impact scope |

Screenshots stored in: `01 - Targets/<Target>/Screenshots/`
Naming convention: `<FindingID>_01_<desc>.png` / `<FindingID>_02_<desc>.png`

## Screenshot Checklist (fill after capturing)
| # | {{IMG}} | File | Description |
|---|---------|------|-------------|
| 1 | {{IMG#1}} | Screenshots/<file> | <desc> |

## Pre-submission Checklist
- [ ] **Screenshots ready** (at least 1 — platform enforces upload, cannot submit without)
- [ ] Screenshot checklist matches {{IMG#N}} order in description
- [ ] Screenshots: max 10 files, max 8MB total
- [ ] Title {} contains organization name (+identifiable product name), no identifying info outside braces
- [ ] Introduction contains no company/product name/domain
- [ ] Remediation is plain text (no Markdown formatting)
- [ ] All fields except description are plain text
- [ ] No internal IDs
```

---

### FORM structure — HackerOne

```markdown
# HackerOne Report — <Finding ID>

> Canonical source: `Submission - <Target> - <Finding ID> *.md` (same directory)

## Title
<vulnerability> on <asset> via <vector>

## Asset
<from program scope>

## Weakness (CWE)
CWE-<N>: <name>

## Severity
CVSS:3.1/<vector>
Score: <N.N> <Critical/High/Medium/Low>

## Description
<Markdown — from Submission>

## Steps to Reproduce
1.
2.

## Proof of Concept
\`\`\`bash
curl ...
\`\`\`

## Impact
### Verified
### Potential (prerequisite: ...)

## Suggested Fix

---
## Screenshot Checklist
| # | File |
|---|------|
| 1 | Screenshots/<file> |

## Pre-submission Checklist
- [ ] Duplicate check completed (searched hacktivity)
- [ ] Severity not inflated (source map P4, CORS P3-P4)
- [ ] Verified / Potential separated
- [ ] Asset in scope
```

---

### FORM structure — Bugcrowd

```markdown
# Bugcrowd Report — <Finding ID>

> Canonical source: `Submission - <Target> - <Finding ID> *.md` (same directory)

## VRT Category
<category > subcategory>

## Severity Note (if VRT vs CVSS mismatch)
VRT suggests P<X>, actual CVSS <N.N> (P<Y>), because <reason>.

## Title
<one line>

## Summary
<one paragraph>

## Steps to Reproduce
1.
2.

## Proof of Concept
\`\`\`bash
curl ...
\`\`\`

## Impact
### Verified
### Potential

## Suggested Fix

---
## Screenshot Checklist
| # | File |
|---|------|
| 1 | Screenshots/<file> |

## Pre-submission Checklist
- [ ] Crowdcontrol duplicate search completed
- [ ] VRT uses most accurate sub-category
- [ ] Severity Note added if VRT > CVSS
- [ ] Out-of-scope review completed
```

---

### FORM structure — Intigriti

```markdown
# Intigriti Report — <Finding ID>

> Canonical source: `Submission - <Target> - <Finding ID> *.md` (same directory)

## Title (max 100 chars, current count: <N>)
<title>

## Asset
<from program scope, most specific subdomain>

## Vulnerability Type
<BAC / Generic / Mobile — most specific>

## Severity / CVSS
CVSS:3.1/<vector>
Score: <N.N>

## Description
<Markdown>

## Steps to Reproduce
1.
2.

## Proof of Concept
\`\`\`bash
curl ...
\`\`\`

## Impact
### Verified
### Potential

## Recommended Solution

## Video PoC
<URL or "pending">

---
## Screenshot Checklist
| # | File |
|---|------|
| 1 | Screenshots/<file> |

## Pre-submission Checklist
- [ ] Title max 100 chars (counted: <N>)
- [ ] Video PoC recorded (required by most programs)
- [ ] Out-of-scope self-review (Intigriti OOS lists are usually extensive)
- [ ] Verified / Potential separated
```

---

### FORM structure — TWCERT

```markdown
# TWCERT Report Form — <Finding ID>

> Canonical source: `Submission - <Target> - <Finding ID> *.md` (same directory)
> Submission URL: https://www.twcert.org.tw/.../CVENotifyForm.aspx

## Fixed Fields
Reporter: <operator name>
Email: <operator email>
Public disclosure: No
Source: Self-discovered
Discovery date: <YYYY-MM-DD>
Affected product: <product name>
Version: <version>
Vendor: <org>
Product website: <url>

---

## Report Content (1) — <Feature> vulnerability (CWE-<N>)

**Vulnerability description:**
<One paragraph: what, where, who can trigger, what happens>

**Trigger method:**
\`\`\`bash
curl ...
\`\`\`

**Permission required:** None / Regular user / Admin

**CVSS v3.1:** CVSS:3.1/<vector> — Score: <N.N> <Severity>
**CWE:** CWE-<N>

**Remediation:**
1.
2.

---
## Pre-submission Checklist
- [ ] No internal IDs
- [ ] Every PoC curl is directly copy-pasteable
- [ ] CVSS calculated correctly, not inflated
- [ ] Checked NVD + TWCERT for duplicate CVEs
```

---

## Step 6 — Verify screenshots

```bash
ls "01 - Targets/<Target>/Screenshots/" 2>/dev/null
```

If folder missing: `mkdir -p "01 - Targets/<Target>/Screenshots"`

**HITCON ONLY — HARD BLOCK:**

If `Screenshots/` is empty or the directory does not exist:
1. **STOP. Do NOT generate a ready FORM.**
2. Generate `FORM - HITCON - <Finding ID> (needs-revalidation).md` instead (status stays `draft`).
3. Tell the user:

```
HITCON requires screenshots — cannot generate a submission-ready form.
Please provide the following screenshots before re-running:

1. Vulnerability location screenshot (target page/endpoint showing the issue)
2. Reproduction step screenshot (Burp / curl response confirming trigger)
3. Impact screenshot (data leak/error message/impact scope)

Store screenshots in: 01 - Targets/<Target>/Screenshots/
Naming convention: 01_vuln_location.png / 02_poc_response.png / 03_impact.png

After adding screenshots, say "regenerate FORM" to continue.
```

Do NOT proceed to Step 7 or commit until screenshots exist.

## Step 7 — Update Submission status + Kanban

Update Submission frontmatter `status: ready`.

In `01 - Targets/<Target>/Kanban - <Target>.md`:
```
Form ready: [[FORM - <Platform> - <Finding ID>]]
```

## Step 8 — Commit (mandatory — task is not complete without it)

> This is a hard requirement. Writing the form is not the finish line — the git commit is.

All files go to the vault repo:

```bash
git status --short

# Commit
git add "01 - Targets/<Target>/Submissions/"
git add "01 - Targets/<Target>/Screenshots/"
git add "01 - Targets/<Target>/Kanban - <Target>.md"
git commit -m "[report] <Target>: <Finding ID> <Platform> Submission + FORM"
```

After committing, run `git status` and confirm no touched files remain untracked or modified. If any do, stage and commit them before returning.

## Step 0 — Inject conventions (Rules)

- **Task is NOT done until Step 8 commit is verified.** Delivering the form content is not the finish line — the git commit is.
- **Everything in the vault.** Never write to legacy `reports/<platform>/` paths.
- Submission = canonical source; FORM = derived output only.
- **curl required**: Every reproduction step must include a directly executable curl command. Triagers verify by copy-pasting — if they can't run it, the report is incomplete.
- Never fabricate technical details — only what's in the Finding.
- Severity must match Finding's CVSS, not be inflated.
- Update Submission first if content changes, then regenerate FORM.
- If not live-verified: suffix `(needs-revalidation)` on FORM filename.
