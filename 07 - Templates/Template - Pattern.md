---
fileClass: Pattern
pattern_name: ""
vuln_class: ""
severity_typical: "P1 | P2 | P3 | P4 | P5"
detection_method: ""
affected_targets: []
related_findings: []
bypass_table: false
last_updated: <% tp.date.now("YYYY-MM-DD") %>
tags: []
---

# Pattern — {{NAME}}

## Summary

Cross-target vulnerability Pattern: what it is, why it occurs, and typical manifestations.

## Detection Method

> How to find it: grep / nuclei template / Burp matcher / custom script

```bash
```

## Prerequisites

- Target must have...
- Target must not have...

## Bypass Table

| Defense | Bypass Method | Example |
|---------|--------------|---------|
| | | |

## Reusable Success Cases

| Target | Endpoint / Host | Account / Role | Primitive | Command |
|--------|-----------------|----------------|-----------|---------|
| | | | | |

## Typical PoC

```bash
```

## Impact

- Typical platform severity:
- Platform stance: (typical response from major programs, e.g. "large programs auto-N/A source maps")

## Affected Targets

```dataview
LIST
FROM "01 - Targets"
WHERE contains(file.outlinks, this.file.link) AND fileClass = "Finding"
SORT file.mtime DESC
```

## Related Findings

```dataview
TABLE target, severity, status
FROM "01 - Targets"
WHERE contains(related_pattern, this.file.link) AND fileClass = "Finding"
```

## Related Patterns

- [[]]

## Learning Sources

- [[]] — disclosed report / writeup / personal finding
