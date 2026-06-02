# Dashboard

> Live views over `01 - Targets/`. Requires the **Dataview** community plugin (see `docs/post-clone-checklist.md`). On a fresh clone these populate from the `_example` target.

## Active Targets

```dataview
TABLE
  status AS "Status",
  channel AS "Channel",
  scope_type AS "Scope"
FROM "01 - Targets"
WHERE fileClass = "Target" AND status != "closed"
SORT status ASC, file.name ASC
```

## Recent Findings (Last 7 Days)

```dataview
TABLE
  target AS "Target",
  severity AS "Severity",
  status AS "Status",
  verified_evidence AS "Evidence"
FROM "01 - Targets"
WHERE fileClass = "Finding" AND discovered_date >= date(today) - dur(7 days)
SORT discovered_date DESC
```

## Findings by Severity

```dataview
TABLE
  finding_id AS "ID",
  target AS "Target",
  status AS "Status",
  verified_evidence AS "Evidence"
FROM "01 - Targets"
WHERE fileClass = "Finding"
SORT severity ASC, finding_id ASC
```

## Open Findings Needing Action

```dataview
TABLE
  finding_id AS "ID",
  target AS "Target",
  severity AS "Severity",
  status AS "Status"
FROM "01 - Targets"
WHERE fileClass = "Finding" AND (status = "verified" OR status = "ready")
SORT severity ASC
```

## Submissions by Status

```dataview
TABLE
  target AS "Target",
  platform AS "Platform",
  status AS "Status",
  submitted_date AS "Submitted"
FROM "01 - Targets"
WHERE fileClass = "Submission"
SORT status ASC, submitted_date DESC
```

## Counts by Severity

```dataview
TABLE length(rows) AS "Count"
FROM "01 - Targets"
WHERE fileClass = "Finding"
GROUP BY severity AS "Severity"
SORT severity ASC
```
