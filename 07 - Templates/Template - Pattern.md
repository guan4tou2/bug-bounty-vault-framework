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

## 簡述

跨 target 的漏洞模式：是什麼、為什麼會出現、典型樣態。

## 偵測方法

> 怎麼找：grep / nuclei template / Burp matcher / 自製腳本

```bash
```

## 必要條件

- 目標必須有...
- 目標必須沒有...

## Bypass 表

| 防禦 | Bypass 方法 | 範例 |
|------|------------|------|
| | | |

## 成功案例索引（可重用）

| Target | Endpoint / Host | Account / Role | Primitive | Command |
|--------|------------------|----------------|-----------|---------|
| | | | | |

## 典型 PoC

```bash
```

## 影響

- 平台典型 severity：
- 平台態度：（大廠的標準回應，e.g.「大廠 source map 必 N/A」）

## 影響的 Target

```dataview
LIST
FROM "01 - Targets"
WHERE contains(file.outlinks, this.file.link) AND fileClass = "Finding"
SORT file.mtime DESC
```

## 同類 Findings

```dataview
TABLE target, severity, status
FROM "01 - Targets"
WHERE contains(related_pattern, this.file.link) AND fileClass = "Finding"
```

## 相關 Pattern

- [[]]

## 學習來源

- [[]] — disclosed report / writeup / 自己的 finding
