---
type: checklist
title: Checklist - Disclosed Findings Pre-Read Gate
tags: [checklist, bb-checklist, recon, competition, dedup, prior-disclosure]
status: verified
first_seen: 2026-06-04
last_updated: 2026-06-04
category: Checklist
precedents: >
  Hack The Tainan 競賽（2026-06-02）— agent had not read the disclosed vulnerability PDF
  before starting work; risked duplicating known findings. User correction was explicit.
  No existing KB item covers this competition-specific pre-work gate.
  'Checklist - Fresh Clone Acceptance' covers workspace hygiene only.
  'Checklist - Recon Floor' covers tool-based recon, not platform-disclosed findings.
---

# Checklist - Disclosed Findings Pre-Read Gate

## Purpose

Block hunting work when platform-disclosed or competition-published findings have not been read.

The failure mode: start poking a target, generate candidates, then discover post-triage that the
findings were already documented in a public disclosed-report PDF. This gate forces the read
**before** any Finding candidate is created, not after.

Trigger conditions (any one is sufficient):

- Any bug bounty competition (Hack The Tainan, <Platform> CTF-style competitions, government red-blue
  exercises, etc.)
- Any platform with a public disclosed/fixed report page (<Platform>, <Platform>, <Platform>)
- Any scope page that lists a "prior findings", "disclosed vulnerabilities", or "known issues"
  section

---

## Hard block rule

> **"Did not read disclosed reports" = do not proceed to hunting.**
>
> Manual browsing, tool recon, and Finding candidate creation are all blocked until §1–§4
> below are complete and checked into RECON_DB.

---

## §1. Locate the disclosed report list

Depending on platform type:

| Context | Where to find disclosed reports | Command / URL pattern |
|---|---|---|
| Hack The Tainan (and similar gov competitions) | Competition results page + official announcement PDF | WebFetch `<competition-official-site>/results` or organiser's Google Drive link |
| <Platform> | <Platform> published advisories | `https://zeroday.platform.org/vulnerability` (filter by target org name) |
| <Platform> program | Program's "Hacktivity" tab — filter "disclosed" | `https://<bb-platform>/<program>/hacktivity |
| <Platform> program | Program's "Disclosed Reports" section | `https://<bb-platform>/<program>/disclosed |
| <Platform> program | Hall of Fame + Public Reports tab | Program page → "Hall of Fame" → filter disclosed |
| Vendor advisory page | Vendor's security advisory or CVE list | WebFetch `<vendor-domain>/security` or NVD search `site:nvd.nist.gov <vendor>` |
| Competition PDF / ZIP | Downloaded from organiser before competition starts | `ls workspace/workshop/<target>/recon/disclosed/` |

If the platform has no public disclosed section, record `disclosed: none-available` in RECON_DB
and proceed — the gate is passed by explicit acknowledgment, not by skipping.

---

## §2. Download or fetch each disclosed report

For each disclosed item found in §1:

```bash
# WebFetch a <Platform> disclosed report
# (replace with actual report URL)
# No tool invocation needed — use WebFetch MCP tool with the report URL

# Download a competition PDF
curl -L "<pdf-url>" -o "workspace/workshop/<target>/recon/disclosed/<filename>.pdf"

# List what was saved
ls workspace/workshop/<target>/recon/disclosed/
```

Minimum required per disclosed report:

- [ ] URL or file path recorded
- [ ] File saved to `workspace/workshop/<target>/recon/disclosed/` (or confirmed WebFetch-read)
- [ ] Date of disclosure noted (to assess whether vendor patch is complete)

---

## §3. Extract and record: vuln type, affected endpoint, root cause

For each disclosed report read, extract these three fields and add a row to RECON_DB
`## 🔍 Known Findings` section:

```markdown
## 🔍 Known Findings (Disclosed / Prior)

| ID | Source | Vuln Type | Affected Endpoint / Component | Root Cause (one line) | Status |
|----|--------|-----------|-------------------------------|-----------------------|--------|
| KF-001 | <Platform> #12345 | 存取控制缺陷 | /api/admin/users | No auth check on list endpoint | Fixed 2025-11 |
| KF-002 | <Platform> #987654 | IDOR | /v2/orders/{id} | UUID not verified against session user | Resolved |
| KF-003 | Competition PDF p.4 | SQLi | /search?q= | Unsanitised string concat in ORM | Unknown |
```

Fields:
- **ID**: sequential `KF-NNN` (Known Finding)
- **Source**: platform + report ID or PDF page reference
- **Vuln Type**: use <Platform> canonical type name or plain English if non-<Platform> context
- **Affected Endpoint / Component**: be specific — `/path` or `ModuleName`, not just "web app"
- **Root Cause**: one sentence, root cause only — not impact, not attack steps
- **Status**: `Fixed` / `Resolved` / `Informative` / `Unknown` — with date if available

---

## §4. Completion gate — RECON_DB sign-off

Before opening any Finding candidate, confirm in RECON_DB:

```markdown
## ✅ Disclosed Report Gate

- Disclosed report read: YES / NO (reason if NO)
- Sources checked: [list platforms/URLs]
- KF entries added: N
- Gate passed at: YYYY-MM-DDTHH:MM+08:00
- Signed by: <session label or agent ID>
```

If `NO`: state explicit reason (e.g., `no public disclosed section exists for this program`).
A blank or missing gate entry = gate not passed.

### §4b. Evidence file(2026-06-04 加,automation-enforceable)

The RECON_DB sign-off is text — easy to forge / forget. Add a **physical evidence file** so automation can check:

```bash
# Path:
$WORKSHOP_ROOT/<target>/disclosed_pre_read.md
```

Required frontmatter + body:
```markdown
---
type: pre-read-evidence
target: <target>
read_at: 2026-06-04T09:00:00Z
sources:
  - target_page: 01 - Targets/<t>/Target - <t>.md
  - recon_db: $WORKSHOP_ROOT/<t>/RECON_DB.md
  - memory: $MEMORY_DIR/project_<t>_*.md
  - external_disclosed: <PDF URL / writeup URL / "N/A — no public disclosed section">
known_findings_count: <N>
status: pre_read_complete
---

## Already-Reported Summary
- <platform_id> | <hostname> | <vuln_class> | <root_cause>
...

## Withdrawn / Out-of-Scope
- ...

## Cross-Team / Other Researchers
- ...
```

**Verification(可由 skill / agent / audit 呼叫)**:
```bash
# Quick check: does the evidence file exist + is it complete?
bash automation/check_disclosed_preread.sh <target>
# Returns:
#   exit 0 + "✅ <target>: pre_read_complete (N findings recorded)"
#   exit 1 + "⛔ <target>: missing $WORKSHOP_ROOT/<t>/disclosed_pre_read.md"
```

`bb-surface-mapping` skill 在 Step 0 之前先 call 這個 check;失敗 → 不准進入後續 lifecycle gates。

---

## §5. Cross-check before each Finding candidate

Before creating any new Finding or Submission:

- [ ] Compare finding's (vuln type + affected endpoint) against every row in `## 🔍 Known Findings`
- [ ] If vuln type AND endpoint overlap with a KF entry: check root cause — same root cause = do **not** create a new Finding (use `bb-dedup-finding` skill)
- [ ] If root cause differs despite overlapping endpoint: document the delta in the Finding's Discovery Log before proceeding
- [ ] If status = `Fixed` in KF: verify whether the fix is complete before claiming the vuln is still present

```bash
# Quick grep against RECON_DB Known Findings section
grep -i "<endpoint-keyword>" "workspace/workshop/<target>/RECON_DB.md"
grep -i "<vuln-type-keyword>" "workspace/workshop/<target>/RECON_DB.md"
```

---

## §6. Competition-specific addenda

Additional steps required for competitions (e.g., Hack The Tainan, government red-blue drills):

- [ ] Download the **official competition scope PDF** before session start — competition organisers often publish a list of in-scope systems AND a list of already-known/awarded findings from prior rounds
- [ ] If prior-round results are published (e.g., "2024 awarded findings" list): treat every item as a KF entry in §3, even if no technical details are given — record vuln type + system name at minimum
- [ ] Confirm competition scoring rules: some competitions disqualify duplicate findings even if the root cause is slightly different (e.g., Hack The Tainan: same system = merged, not split)
- [ ] Record competition round and scoring rules at top of RECON_DB:

```markdown
## 🏆 Competition Context

- Competition: Hack The Tainan 2026
- Round: Red-blue exercise (06/01–06/15)
- Scoring rules: same system merges, different system prioritised, outdated-version-only invalid
- Prior round findings PDF: workspace/workshop/hack-the-tainan/recon/disclosed/2025_results.pdf
- Gate passed: YES — 2026-06-04T09:00+08:00
```

---

## Anti-patterns

- **Starting with tool recon before fetching the disclosed PDF** — tools find endpoints; disclosed reports tell you which endpoints are already known. Do the read first.
- **Treating "no disclosed section" as permission to skip** — explicitly record it. Missing the record is how this gate gets skipped silently.
- **Extracting only vuln type, skipping root cause** — two findings with the same vuln type but different root causes are not duplicates. Root cause is the dedup key.
- **Checking RECON_DB only at session start and not before each candidate** — new KF entries may be added mid-session (organiser updates, teammate disclosures). Re-check at candidate creation time.
- **Reading only the PDF summary page** — competition results PDFs often have a short summary and detailed appendix. The appendix contains endpoints and root causes. Read the full document.

---

## Related

- [[Checklist - Recon Floor]] — tool-based recon floor; this checklist is the prior-disclosure pre-work that runs before Recon Floor
- [[Checklist - Attack Surface Coverage]] — dimension-level surface map; run after both this gate and Recon Floor
- [[Reference Card - Bug Bounty Workflow 2026]] — full session lifecycle; this gate sits between scope-read and recon-tool-run
- [[Lessons Learned]] — 教訓 #121 (競賽策略: different system > same system), 教訓 #25 (Prior-disclosure check)
- `bb-dedup-finding` skill — root-cause dedup logic; invoked in §5
- AGENTS.md §0c — KB query timing (before research, during hunting, before report writing)
