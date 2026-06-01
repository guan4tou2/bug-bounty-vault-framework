---
fileClass: Target
target: "_example"
status: "recon"
channel: "private-program"
program_url: "https://example.com/security"
scope_type: "web"
created: "2026-01-01"
---

# Target - _example

> This is an example target page. Copy this directory structure when setting up a new target.

## Snapshot

| Field | Value |
|-------|-------|
| Channel | Private program |
| Scope | `*.example.com` |
| Status | Recon |
| Tech stack | TBD |
| Notes | Example target for reference |

## Findings Summary

```dataview
TABLE
  finding_id AS "ID",
  severity AS "Severity",
  status AS "Status"
FROM "01 - Targets/_example/Findings"
WHERE fileClass = "Finding"
SORT finding_id ASC
```

## Submission Status

```dataview
TABLE
  finding_id AS "ID",
  channel AS "Channel",
  status AS "Status"
FROM "01 - Targets/_example/Submissions"
WHERE fileClass = "Submission"
SORT status ASC
```

## Quick Links

- [[01 - Targets/_example/Findings/|Findings]]
- [[01 - Targets/_example/Submissions/|Submissions]]
- [[01 - Targets/_example/Recon/|Recon]]
- [[01 - Targets/_example/Attempts/|Attempts]]
- [[01 - Targets/_example/Attack Chains/|Attack Chains]]

## Session Notes

_Record session-level observations here. Detailed recon goes in the Recon/ subfolder._
