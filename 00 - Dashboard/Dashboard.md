# Dashboard

## Active Targets

```dataview
TABLE
  status AS "Status",
  length(filter(file.inlinks, (l) => contains(meta(l).path, "Findings"))) AS "Findings"
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
WHERE fileClass = "Finding" AND created >= date(today) - dur(7 days)
SORT created DESC
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

## Findings by Severity

```dataview
TABLE
  finding_id AS "ID",
  target AS "Target",
  status AS "Status",
  verified_evidence AS "Evidence"
FROM "01 - Targets"
WHERE fileClass = "Finding"
SORT choice(severity, "Critical", 1, "High", 2, "Medium", 3, "Low", 4, "Informational", 5, 9) ASC
```

## Pipeline Overview

```dataview
LIST
FROM "01 - Targets"
WHERE fileClass = "Finding" AND status = "verified"
GROUP BY target
```
