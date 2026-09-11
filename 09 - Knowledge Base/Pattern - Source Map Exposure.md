---
type: pattern
title: "Pattern - Source Map Exposure"
vuln_class: Source Map / JS Asset Disclosure
tags: [pattern, source-map, info-disclosure, methodology, bb-pattern]
status: active
last_updated: 2026-04-05
---

# Pattern: Source Map Exposure

> This is a cross-target synthesis analysis page.

## What Is Worth Reporting

**Worth reporting:**
- **Directly exploitable vulnerabilities** discovered in source maps (XSS, SQLi, auth bypass)
- Hardcoded secrets + server-side differential response confirming validity (e.g., OAuth clientSecret)
- Internal API endpoints that chain into further attack paths

**Not worth reporting alone (at large companies):**
- Google OAuth Client ID (public identifier)
- New Relic browser key / Sentry DSN (browser-side, public by design)
- TypeScript path structure, version information

## Platform Attitudes

| Platform | Attitude | Basis |
|----------|----------|-------|
| Bugcrowd (large companies) | N/A | A major vendor case: triager explicitly said "not sensitive" |
| HackerOne (large companies) | Almost certainly Duplicate | Another vendor case: high collision rate on source map reports |
| Regional vulnerability disclosure platform | Accepts (if exploitable vulnerability found from source) | Local targets |

## Attack Chain Approach

```
Source map exposure
  -> Search for hardcoded secrets -> server-side differential confirmation
  -> Find internal API endpoints -> unauthorized operations
  -> Chain XSS / auth bypass -> report the complete chain
```

**Do not report source map exposure by itself**

## Search Commands

```bash
# Find sensitive strings
grep -r "secret\|password\|token\|api_key\|REACT_APP_" ./src/
grep -r "process\.env\." ./src/
grep -r "hardcoded\|clientSecret\|privateKey" ./src/

# Find internal API endpoints
grep -rE "(https?://[a-z0-9.-]+\.(internal|local|dev|staging))" ./src/
grep -rE '"(/api/v[0-9]+/[a-z/]+)"' ./src/
```

## Related

- [[Pattern - SourceMap Endpoint Family Disclosure]] -- Sub-pattern: focuses on the cascade impact of source maps revealing **entire API endpoint families** (framework comparison table + Python extraction snippet + vendor-shared key downgrade rules); this file is **case-review oriented** (which targets it appeared on), the sub-pattern is **methodology oriented** (how to extract + how to assess severity)
- [[Lessons Learned]] -- Source map submission lessons
- [[Pattern - Git Exposure]] -- Higher-ROI discovery path than source maps
- [[Tool - JS-Tap]] -- Upgrade impact after finding XSS in source maps
- [[Tool - Source Map Reverse Engineering]] -- Full reverse engineering guide (reverse-sourcemap / @sugarat/source-map-cli / attack flow / Vue-specific tricks)
- [[Resource - Client-Side Bugs]] -- JS analysis articles and tools
- [[Checklist - XSS Rat 2026]] -- JS file analysis chapter
