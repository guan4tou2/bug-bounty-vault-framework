---
fileClass: ReferenceCard
title: "Disclosed Report Sources"
type: reference
trigger: "find writeups, check report history, disclosed reports, pre-hunt research, has anyone reported this, how others wrote this vuln"
tags: [reference-card, recon, research, disclosed, writeup]
---

# Disclosed Report Sources

> Pre-hunt and mid-hunt reference for publicly disclosed reports. Sources in three tiers: local dataset (fastest), platform disclosures (freshest), technique writeups (deepest).

## 1. Local Dataset (offline, instant)

| Source | Location | Query | Records |
|---|---|---|---|
| **HexBrain H1 Reports** | `workshop/_platform-import-20261026/h1-reports/data.csv` | `bash automation/h1_lookup.sh <keyword>` | 15K+ |

```bash
bash automation/h1_lookup.sh shopify --top 10
bash automation/h1_lookup.sh '' --class ssrf --bounty-min 5000
bash automation/h1_lookup.sh gitlab --class rce
```

## 2. Platform Disclosures (online, freshest)

| Source | URL | Query Method | Use For |
|---|---|---|---|
| **HackerOne Hacktivity** | `hackerone.com/hacktivity` | Web UI filter + API `/v1/hackers/hacktivity` | Program history, latest disclosures |
| **Bugcrowd Disclosed** | `bugcrowd.com/disclosures` | Web UI search | Program history |
| **ProjectDiscovery Chaos** | `chaos.projectdiscovery.io` | JSON + API | Bug bounty program scope and subdomains |

## 3. Technique Writeup Aggregators (depth reference)

| Source | URL | Strength |
|---|---|---|
| **Pentester.Land Writeups** | `pentester.land/writeups` | Weekly curated, by vuln type; JSON mirror: `github.com/andreystepanov/pentesterland-writeups` |
| **Intigriti Bug Bytes** | `intigriti.com/researchers/blog/bug-bytes` | Weekly newsletter: tools + writeups + tutorials |
| **PortSwigger Research** | `portswigger.net/research` | Deepest technique coverage, new attack classes |
| **Assetnote Research** | `assetnote.io/resources/research` | Enterprise software deep-dive advisories (Confluence, Citrix, etc.) |
| **Awesome Bugbounty Writeups** | `github.com/devanshbatham/Awesome-Bugbounty-Writeups` | 578+ writeups in 18 categories, 6K stars |
| **Daily Bugbounty Writeups** | `github.com/securitycipher/daily-bugbounty-writeups` | Updated daily, active through 2026 |
| **Google Project Zero** | `projectzero.google` + `issues.chromium.org` | 90-day disclosure, browser/OS/firmware focus |

## 4. Per-Phase Usage

| Phase | Action | Source Priority |
|---|---|---|
| **Pre-target** | Check program disclosure history | H1 local CSV → HackerOne Hacktivity → Bugcrowd |
| **Surface mapping** | Check tech stack vulnerability history | PortSwigger → Assetnote → Awesome Writeups |
| **Post-finding** | Find depth writeups for same vuln class | Pentester.Land → Daily Writeups → Project Zero |
| **Pre-report** | Reference high-bounty report writing style | H1 local CSV (`--bounty-min 10000`) → Hacktivity |

## Related

- [[Reference Card - Report Quality Formula and Hunting Depth]] — High-bounty pattern quick reference
- `disclosed-report-researcher` agent — Pre-hunt research
- `bb-surface-mapping` skill — Attack surface mapping
- `bb-multi-search` skill — Mid-hunt parallel multi-source search
