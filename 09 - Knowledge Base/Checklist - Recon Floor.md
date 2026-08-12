---
type: checklist
title: "Recon Floor"
tags: [checklist, recon, tool-coverage]
status: active
last_updated: 2026-06-26
---

# Checklist — Recon Floor (the minimum recon set that must run on every target)

Purpose: prevent the streetlight-effect failure mode where the hunter opens a target in a browser and starts poking endpoints WITHOUT running recon tools first. One training-range session proved this failure mode concretely: hundreds of tool calls, zero actual gau/subfinder/katana executions, despite a full subdomain-recon playbook being available. **Recon tools generate the Surface Map raw material — manual browsing alone does not.** Recon is always the most important step, and it's a precondition for everything downstream.

---

## Hard rule

If you haven't run the tools in §1 below, you have NOT done recon. Manual browsing + ad hoc page fetches is not recon. The output of these tools is what populates the Surface Map (see the surface-mapping methodology and the Exploratory Surface Mapping playbook).

---

## §1. Minimum recon set (mandatory — only once this has run does it count as "recon done")

| Stage | Tool | Why required | Command (canonical) |
|---|---|---|---|
| Subdomain enum | subfinder | passive subdomain discovery (CT logs, APIs) | `subfinder -d <domain> -all -recursive -o subs.txt` |
| Subdomain enum | chaos | ProjectDiscovery's curated dataset | `chaos -d <domain> -o subs_chaos.txt` |
| Live host probing | httpx | which subs are live, status, tech, title | `httpx -l subs.txt -title -tech-detect -status-code -o live.txt` |
| DNS resolution | dnsx | resolve to IP, find IP ranges | `dnsx -l subs.txt -resp -o resolved.txt` |
| URL discovery | gau | wayback + commoncrawl + AlienVault URLs | `gau --threads 5 <domain> > urls.txt` |
| URL discovery | waybackurls | belt-and-braces wayback fetcher | `cat live.txt \| waybackurls > wayback.txt` |
| Crawl + JS | katana | JS-aware crawl, JS endpoint extraction | `katana -list live.txt -d 3 -jc -o katana.txt` |
| JS analysis | xnLinkFinder | active fork of LinkFinder — endpoints + params from URL list/Burp XML/wayback | `xnLinkFinder -i js_urls.txt -sf <domain> -o endpoints.txt -op params.txt` |
| JS secrets | SecretFinder | 30+ regexes (AWS/Google/Slack/Stripe/etc.) | `python3 SecretFinder.py -i https://example.com/main.js -o cli` |
| Param discovery | x8 | active hidden-param verification (faster than paramspider + baseline diff) | `x8 -u urls.txt -w params_top1000.txt -o x8_out.txt` |
| Param discovery (passive) | paramspider | from wayback URLs (passive fallback) | `paramspider -d <domain> -o params.txt` |
| XSS recon | kxss | finds params reflected into HTML, pre-filters candidates for dalfox | `cat urls.txt \| grep '?' \| kxss > xss_seeds.txt` |
| Content discovery | feroxbuster | Rust recursive directory scanner, better default recursion than ffuf | `feroxbuster --stdin -w raft-medium.txt -x php,asp,bak < live.txt` |
| Known vuln | nuclei | pre-built CVE/exposure templates | `nuclei -l live.txt -severity medium,high,critical -o nuclei.txt` |
| Subdomain takeover | subzy (or nuclei takeover templates) | CNAME → dangling | `subzy run --targets subs.txt` |

**Recommended one-shot:** a recon orchestration command that runs the equivalent pipeline on a dedicated scanning host is preferable for long-running scans — don't run long scans on your local machine, since it hits rate limits and loses output if the session dies.

---

## §2. Per-target completion checklist (record checked status in your recon notes)

Before starting work on any target, confirm the following outputs exist in the target's recon workspace:

- [ ] subfinder + chaos → `subs.txt`
- [ ] httpx → `live.txt`
- [ ] dnsx → `resolved.txt`
- [ ] gau + waybackurls → `urls.txt`
- [ ] katana → `katana.txt`
- [ ] getJS + linkfinder → `js_endpoints.txt`
- [ ] paramspider → `params.txt`
- [ ] nuclei → `nuclei.txt`
- [ ] subzy → `takeover.txt`
- [ ] Surface Map populated from these outputs (not from manual browsing)

> If any item wasn't run, record the reason in the recon coverage notes (e.g., single-page SPA, scope = specific path only). Not running a tool ≠ forgetting it; it should be a deliberate decision.

---

## §3. When manual browsing is OK

After §1 completes — manual browsing is for *exploring* what the tools found, not *discovering* what's there.

Manual browsing's role:
- Confirm what the tools returned (validate live subdomains)
- Understand business logic (flows, roles, checkout, auth)
- Spot anomalies that tools can't flag (unusual UX, mixed auth patterns)

Manual = recon source = `manual` in the Surface Map. **A high `manual` ratio without tool outputs behind it is a signal that §1 wasn't actually run.**

---

## §4. Anti-patterns (things that keep going wrong)

- **Opening the target's URL in a browser and clicking around** — that's UX inspection, not recon. Tools first.
- **Dozens of sequential single-page fetches extracting endpoints from JS bundles** — that's manual katana/getJS, badly. Run the real tool.
- **Discussing what `gau` would find without actually running it** — this happened repeatedly for the same target in one session, with zero actual executions.
- **Skipping nuclei because "I'll find better stuff manually"** — nuclei finds the floor, you build the ceiling on top.
- **Running long recon pipelines locally instead of on a dedicated host** — long scans on localhost hit rate limits and lose output if the session dies.
- **Treating a single-URL fetch as a substitute for waybackurls/gau** — a single fetch retrieves one URL at a time; gau pulls tens of thousands of historical URLs in one pass.
- **Starting with vulnerability hunters before recon** — hunter tooling consumes endpoint candidates; if the candidate list is empty (no recon ran), hunters fire blind.

---

## §5. Tool ↔ Surface dimension mapping

Which tool feeds which Surface Map dimension (from the Exploratory Surface Mapping playbook + the Attack Surface Coverage checklist):

| Tool | Surface dimensions fed |
|---|---|
| subfinder / chaos | boundary (external asset discovery) |
| httpx | boundary, dependency (CDN/WAF/tech stack) |
| dnsx | boundary, integration (IP space, cloud provider) |
| gau / waybackurls | input/param (historical URL corpus), anomaly (deprecated paths) |
| katana | input/param (live crawl), business flow (JS route extraction) |
| getJS + linkfinder | integration (third-party JS), input/param (hidden API endpoints) |
| paramspider | input/param (parameter enumeration) |
| nuclei | anomaly (known CVE / exposure hits) |
| subzy | boundary (dangling CNAME / takeover candidates) |

---

## §6. Passive Enrichment (optional, high ROI — after §1, before httpx probing)

> **When to use**: the target is an established company (5-10+ years of history, public IP/ASN discoverable). For brand-new sites (≤30 days old) or targets fully behind a CDN with no history, most of these tools return zero hits — skip and move on (see the lesson on Cloudflare-fronted new domains being a passive-DNS dead end).

**Purpose**: find assets DNS enumeration can't see — historical origin IPs, hidden TLS hosts, exposed services, entire IP ranges not present in DNS. Output feeds directly into the boundary/integration dimensions of the Surface Map.

| Tool | Core use | How to get it |
|------|---------|------|
| **SecurityTrails** | historical DNS A records (origin IP before CDN onboarding / deleted subdomains) | free API key, 50 queries/month |
| **BGP.HE.NET / BGPView** | ASN CIDR ranges, find a company's full IP allocation | completely free, usable directly via curl |
| **ViewDNS IP History** | domain's historical IPs (a precondition for CDN-bypass) | completely free, manual or curl |
| **Censys** | TLS cert search (hidden hosts, unlisted SANs) | free account |
| **Shodan** | exposed service banners + CVE fingerprinting | free tier, CLI: `pip install shodan` |
| **URLScan.io** | network request timeline + screenshots | free API, no key needed |
| **AlienVault OTX** | prior-disclosure confirmation, find already-disclosed IOCs | completely free |

**Full command templates**: see the tool arsenal index, Passive Enrichment phase.

**Relationship to §1**: §6 does not replace §1. §1 = active DNS enumeration (finds subdomains that currently exist); §6 = passive history (finds IPs that existed in the past / were never in DNS). The two are complementary.

**Completion criteria**: passive enrichment is not a mandatory step and isn't part of the §2 checklist. But if it was run, record the execution status and hit count in your recon coverage notes.

---

## Related

- Recon Methodology playbook — full 6-phase methodology; this checklist is the floor
- Exploratory Surface Mapping playbook — what to do with the recon output
- Checklist - Attack Surface Coverage — dimension-level companion (what to think about after tools run)
- Tool arsenal index — canonical tool commands + one-shot pipeline, includes the full Passive Enrichment command set
- Lessons Learned log — streetlight effect, hunting craft, Cloudflare-fronted new-domain passive-DNS dead end

---

## Session-Mined Additions

- **crt.sh is a mandatory step:** `curl "https://crt.sh/?q=%.example.com&output=json" | jq '.[].name_value' | sort -u` → diff the output against known scope; subdomains in the difference need in-scope confirmation. Skipping crt.sh can cause a miss of GCS bucket / S3 subdomain takeover opportunities — a lesson learned from a past engagement.

## Session-Mined Additions (from automated-pipeline reverse-sync)

- **The platform's own assets CSV export is the authoritative scope source (it outranks queue seeds / slug-derived guesses):** before starting work on a program, pull the assets CSV export and check each asset's `eligible_for_submission` / `eligible_for_bounty` / `updated_at` fields. Uses: (a) filter out assets a queue seed incorrectly included as in-scope but which are actually out-of-scope (observed in practice — assets like a launch/cloud subdomain and an analytics subdomain that appeared in seed data but were actually out of scope for their respective programs), (b) pick up newly-added wildcard/API/dev assets, (c) serves as a reliable fallback when a program page is JS-heavy and hard to scrape directly. **Verify `eligible_for_submission` before probing — don't trust a queue seed's in-scope determination** (based on repeated observation across roughly 10 programs during an automated scanning run).
