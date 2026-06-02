---
fileClass: Recon
target: "[[]]"
session_date: <% tp.date.now("YYYY-MM-DD") %>
session_time_start: <% tp.date.now("HH:mm") %>
session_time_end: ""
hours_spent: 0
scope_focus: ""
tools_used: []
artefacts: []
findings_produced: []
attempts_produced: []
kb_capture_done: false
kb_capture_verified_at: ""
status: "wip | complete | interrupted"
tags: []
---

# Recon — {{TARGET}} — {{FOCUS}} — {{date}}

> **Discovery note**: Shares the discovery-note format with Finding/Attempt. Section headings use canonical English H2 (see AGENTS.md section 3b).

## Purpose

What are you looking for this session? State the scope, hypotheses, and success criteria.

## Scope

- Subdomains / endpoints / features in focus
- Account state (none / single / dual accounts)
- Constraints (e.g. no full nuclei scan, avoid prod writes)

## Tools & Config

| Tool | Why chosen | Configuration |
|------|-----------|---------------|
| | | |

---

## Activity Log

> Each activity entry should include an audit ref (`[audit:SESSION8@UTC_HH:MM:SS]`) to correlate with the Bash audit log.
> Retrieve session ref: `head -1 logs/claude_audit_$(date -u +%Y%m%d).log`

### `<HH:mm>` <activity>  `[source IP → target IP]`  `[audit:SESSION8@HH:MM:SS]`

**endpoint / host:**

**account / role:**

**command:**
```bash
```

**result summary:**

**interpretation / next step:**

### `<HH:mm>` ...

---

## Knowledge Capture Gate (what was learned this round)

> Write `N/A` if nothing to report — do not leave blank. Before ending the session, run:
> `bash automation/recon_kb_capture_gate.sh --verify <target> [recon_note_path]`

### Learned Items (required)

- New signals / new patterns confirmed for the first time this round:
- Dead-end paths and stop conditions (to avoid repeating mistakes next round):
- False positive filters / triage interpretation notes:
- Reusable commands / matchers / payloads:
```bash
```

### Hypothesis Log (required)

- hypothesis:
- test:
- result:
- next decision:

### Example Evidence (if applicable)

#### Successful Cases

- endpoint / host:
- account / role:
- exploit primitive:
- command:
```bash
```
- why it worked:

#### WAF / Defense Bypass Techniques

- defense observed:
- blocked payload:
- bypass payload / encoding / protocol trick:
- command:
```bash
```
- evidence:

### Vault Backfill

- Pattern / Playbook / Lessons Learned / Round Log update path (at least one):
- What reusable knowledge was added this session (1-2 lines):
- Related Finding / Attempt (including related_recon / related_pattern):

### Automation Backfill Decision (required)

- Is there a repeatable detection technique? (yes/no):
- Decision:
  - Backfill to automation: <hunter / Nuclei template / scanner profile / wiki / CHANGELOG path>
  - Or reason for not backfilling: <target-specific / not stable yet / false positive / one-off evidence / other>
- Wiki sanitization gate: <done / n/a> (if wiki updated, confirm target name, host/IP, token/cookie, raw log, screenshot, and PoC evidence have been removed)

### Completion Checklist (verified by automation gate)

- [ ] Learned Items filled (at least 2 entries; write N/A + reason if none)
- [ ] Hypothesis Log filled (hypothesis → test → result → next step)
- [ ] At least 1 Vault knowledge node updated (Pattern / Playbook / Lessons Learned / Round Log)
- [ ] Automation backfill decision filled (backfill path or reason for skipping)
- [ ] (optional) Successful cases documented
- [ ] (optional) WAF / defense bypasses documented

---

## Findings Produced

- [[Finding - <target> - ...]] (link to the formal Finding note)

## Attempts Produced

- [[Attempt - <target> - ...]]

## Open Leads (directions not yet converted to Finding/Attempt)

- Endpoint X: angle Y still untested
- Observed cookie Z — need to check spec

---

## Raw Artifact Links

- Tool output: [[../../../../workspace/workshop/<target>/...]]
- Screenshots: [[../../poc/...]]

---

## Related

- Target: [[]]
- Previous Recon Session: [[]]
- Referenced Pattern: [[]]
