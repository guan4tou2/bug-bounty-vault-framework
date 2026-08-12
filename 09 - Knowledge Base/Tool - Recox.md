---
type: tool
title: Tool - Recox (Browser-based Passive Recon)
tags: [tool, recon, subdomain-enum, passive, browser]
status: validated (with caveats - see Re-evaluation section)
last_updated: 2026-04-24
---

# Tool - Recox (Browser-based Passive Recon)

## TL;DR

**Recox** (https://recox.hackerz.space) by @zack0x01 is a browser-native recon aggregator that queries **HackerTarget / URLScan / crt.sh / JLDC / CertSpotter / RapidDNS / DNSRepo** in a single pass. 10 stars on GitHub (zack0x01/recox), MIT. Zero install.

**Empirical verdict**: it IS a complementary source worth running, despite initial skepticism about "same public APIs as subfinder". In an empirical test it surfaced **25 net-new live subdomains** across 4 under-enumerated apex domains that an Osmedeus+subfinder+CT pipeline had missed.

## When it's useful

- **Under-enumerated apex** where subfinder default sources don't fully cover. Specifically:
  - Small APAC vendors (JLDC + RapidDNS cover these better than Chaos / BinaryEdge)
  - Internal-naming conventions (`rd-gitlab`, `*-api`, `*-dev`) that CT logs don't capture
  - Staging / dev tiers that appear in HackerTarget passive DNS before they hit mainstream sources
- **Quick triage** on a new program -- 60 seconds per apex, mobile-friendly

## When it's NOT useful

- **Already-saturated apex** (e.g. if you already have 20+ subdomains via CT + CSP pivot, recox may return only a subset)
- **URL discovery** -- marketing claim of "53,030 vs waybackurls 10,184" compares multi-source aggregation to single-source. For URL enumeration, use `gau` / `waymore` (same aggregation, CLI)
- **Authenticated testing** -- it's passive-only
- **Wide-scope enterprise recon** -- for serious jobs, stick with `osmedeus bbflow-safe` on a VPS + `subfinder -all` with API keys

## Usage

**Web UI**: https://recox.hackerz.space -- paste domain, Scan, copy/export.

**Playwright automation** (for agent-driven use):

```python
# Via Playwright MCP (Claude Code):
# 1. browser_navigate https://recox.hackerz.space
# 2. browser_evaluate: dismiss promo-overlay (it intercepts pointer events)
#    () => { const o = document.getElementById('promo-overlay'); if (o) o.remove(); }
# 3. browser_evaluate: fill input + startScan()
#    () => { document.querySelector('#domain').value = 'TARGET'; startScan(); }
# 4. wait ~18-20s for all sources to complete
# 5. browser_evaluate: scrape table rows
#    () => { const subs = new Set();
#            document.querySelectorAll('td').forEach(el => {
#              const t = el.innerText?.trim().replace(/\s+/g,'');
#              if (t?.endsWith('APEX')) subs.add(t);
#            });
#            return Array.from(subs).sort(); }
```

Tip: the `startScan()` global function is exposed on `window`. Calling it directly bypasses the promo overlay issue.

## Source list (empirically verified)

Recox currently hits these passive sources:

| Source | Typical yield | Unique signal |
|--------|---------------|---------------|
| HackerTarget | high | well-known hostnames |
| URLScan.io | medium | recently-scanned URLs |
| crt.sh | high | CT log certificates |
| JLDC (anubisdb) | medium | historical passive DNS |
| CertSpotter | medium | CT log (redundant with crt.sh) |
| RapidDNS | medium-high | passive DNS + subdomain wildcards |
| DNSRepo | low-medium | additional DNS cache |

## Comparison to existing pipeline

| Tool | Sources covered | Missing vs recox |
|------|-----------------|------------------|
| `subfinder -all` (with API keys) | Chaos, BinaryEdge, VirusTotal, SecurityTrails, Shodan, etc. | may miss JLDC / RapidDNS / DNSRepo defaults |
| `crt.sh` direct | CT logs only | misses HackerTarget passive DNS |
| `assetfinder` | HackerTarget, crt.sh, Threatcrowd | misses JLDC / URLScan |
| Osmedeus bbflow-safe | subfinder + amass + assetfinder chain | varies by workflow config |

**Recommendation**: add recox as a Round 1 supplementary sweep on new programs. Budget: 2-3 minutes per apex.

## Integration with Osmedeus

Osmedeus workflow (`workflow/subdomain.yaml`) could integrate recox via a Chrome headless step, but:
- 60s / apex is not fast enough for batch
- browser automation adds fragility
- duplicates some sources already in subfinder-passive

**Better**: leave recox as a manual pass during triage, keep the Osmedeus pipeline clean.

## Source code

GitHub: https://github.com/zack0x01/recox -- MIT, pure HTML + JS, no backend. Safe to self-host if needed.

## Re-evaluation -- head-to-head vs subfinder -all

A head-to-head comparison was run against the same target apex. The result **does not contradict the earlier "+12 live" conclusion, but changes the recommendation**:

| Tool | subs found | time | Notes |
|------|-----------:|-----:|-------|
| recox.hackerz.space | 14 | ~30s manual | 11 passive sources |
| **`subfinder -all`** (local) | **21** | 45s | covers nearly all recox sources |
| crt.sh direct query | 15 | <1s | CT only |
| amass -passive (no API key) | 0 | 60s | requires API key config |

**subfinder exclusively found what recox missed**: 4 subdomains (dev/staging tiers). This means when local `subfinder -all` is properly enabled, **recox's marginal value approaches zero**. A previous recon round's "recox big win" was caused by the Osmedeus VPS default config not having `-all` enabled -- a comparison-condition bias, not an inherent recox advantage.

### Correction: actual source count is 11 (originally documented as 7)

After curling the HTML and parsing `fetch(` calls, the complete source list:
- `crt.sh` / `api.certspotter.com` (CT logs)
- `api.hackertarget.com` / `urlscan.io` / `otx.alienvault.com`
- `rapiddns.io` / `dnsrepo.noc.org` / `anubisdb.com`
- `web.archive.org` CDX (Wayback)
- `index.commoncrawl.org` (Common Crawl)
- JLDC (embedded in anubisdb path)

### Privacy warning (important addition)

Recox routes requests through 4 third-party CORS proxies:
- `corsproxy.io` / `cors.eu.org` / `thingproxy.freeboard.io` / `api.codetabs.com`

This means **every target domain you query will pass through these intermediaries' logs**. For bug bounty this is usually not critical, but if you are testing a VDP / internal engagement you should switch to a local CLI tool instead.

### Author background

Author `@zack0x01` explicitly labels this as a free companion tool for the commercial product **Sectiv AI**. README states: "It's not a replacement for a full CLI stack during a serious engagement -- it's a fast, zero-install companion." The repo was created on **2026-03-21** (~1 month before evaluation), 10 stars, 4 forks, no LICENSE file (README claims MIT but no actual license file committed).

### Final recommendation (updated)

| Scenario | Recommendation |
|----------|----------------|
| Daily recon pipeline | **Do not use** -- subfinder + bbot fully cover it |
| Phone / Chromebook / locked workstation quick lookup | OK -- only option |
| Teaching / demo visualization | OK -- clean UI |
| Privacy-sensitive target | **Avoid** -- CORS proxies log queries |
| VPS already running Osmedeus | **Do not use** -- duplicate sources |

**Overall rating: 3/10. Keep as an emergency mobile-query bookmark; do not integrate into daily pipeline.** The earlier "big win" conclusion stands for the specific test (genuinely +12 live subdomains at the time), but that was caused by subfinder not having `-all` enabled in the comparison -- not an inherent recox advantage.
