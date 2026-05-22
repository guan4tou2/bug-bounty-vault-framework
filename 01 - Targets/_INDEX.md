# Target Index

This page lists all targets in the vault. Each target has its own directory under `01 - Targets/<target>/` containing findings, submissions, recon, and supporting materials.

To add a new target, run:

```bash
bash automation/init_target.sh <target>
```

---

## All Targets

```dataview
TABLE
  status AS "Status",
  length(filter(file.inlinks, (l) => contains(meta(l).path, "Findings"))) AS "Findings",
  length(filter(file.inlinks, (l) => contains(meta(l).path, "Submissions"))) AS "Submissions"
FROM "01 - Targets"
WHERE fileClass = "Target"
SORT status ASC, file.name ASC
```
