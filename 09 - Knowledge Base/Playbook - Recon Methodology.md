---
type: playbook
title: "Bug Bounty Recon Methodology (Full Eight-Phase Pipeline)"
tags: [recon, methodology, subdomain, nuclei, javascript, fuzzing, automation]
status: draft
last_updated: 2026-08-12
category: recon
estimated_time: "several hours to multi-day, depending on target size"
---

# Playbook - Bug Bounty Recon Methodology (Full Eight-Phase Pipeline)

> **TL;DR**: A complete reconnaissance pipeline from passive OSINT through active vulnerability scanning. Each phase builds on the last — passive intelligence and pivoting feed DNS resolution and brute-forcing, which feeds infrastructure/port analysis, which feeds web probing, JS/content mining, and finally parameter fuzzing. Two later phases (historical/dead assets, continuous monitoring) turn one-off recon into a repeatable, compounding advantage.
>
> Source: adapted from a public methodology repository (github.com/Maniesh-Neupane/BugBounty-Recon-Methodology), reorganized here with additional phases. This is a methodology reference — treat every phase as something to adapt to the actual tools and rate limits available to you, not a script to run unattended end-to-end.

## Scope / When to use

Use this playbook at the start of any new web/API target, or whenever revisiting a target to refresh its attack-surface map. It is intentionally broad — not every phase applies to every engagement, and later phases (especially brute-forcing, port scanning, and fuzzing) must be checked against the program's scope and rate-limit rules before running.

## Phases

### Phase 1: Passive Intelligence & Scope Mapping

Goal: map the organization's global footprint, network boundaries, and historical data.

**1.1 ASN & network ranges**

```bash
# Get the ASN and convert to IP ranges
asnmap -d target.example.com | dnsx -silent > asn.txt

# Whois lookup for IP ranges
whois -h whois.radb.net -- '-i origin AS714' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq | mapcidr -silent | httpx > cidr_ips.txt

# Third-party IP extraction
curl -s "https://urlscan.io/api/v1/search/?q=domain:target.example.com&size=10000" | \
  jq -r '.results[]?.page?.ip//empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | tee urlscan_ips.txt

curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=target.example.com&apikey=KEY" | \
  jq -r '..|.ip_address?//empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | tee vt_ips.txt
```

**1.2 Passive subdomain collection (11 tools)**

```bash
# Mainstream tools
subfinder -d target.example.com -all -recursive -o sub1.txt
findomain -t target.example.com | tee sub2.txt
amass enum -passive -d target.example.com -norecursive -noalts -o sub3.txt
assetfinder --subs-only target.example.com > sub4.txt

# Additional tools
Subenum -d target.example.com | tee sub5.txt
Chaos -d target.example.com | tee sub6.txt          # ProjectDiscovery Chaos
github-subdomain -d target.example.com | tee sub7.txt
echo "target.example.com" | subdog | tee sub8.txt
tldfinder -d target.example.com | tee sub9.txt
bbot -t target.example.com -f subdomain-enum | tee sub10.txt
oneforall --target target.example.com --brute False run | tee sub11.txt

# Certificate Transparency
curl -s "https://crt.sh/?q=%25.target.example.com&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh_subs.txt

# SecurityTrails API
curl -s -H "APIKEY: <KEY>" \
  "https://api.securitytrails.com/v1/domain/target.example.com/subdomains" | \
  jq -r '.subdomains[] | "\(.).target.example.com"' > securitytrails.txt

# Rapid7 FDNS (full DNS snapshot, updated monthly)
# Download: https://opendata.rapid7.com/sonar.fdns_v2/
zcat 2025-01-01-1735689601-fdns_any.json.gz | \
  grep '"name":".*\.target\.example\.com"' | jq -r '.name' | sort -u > rapid7_subs.txt

# DNSDumpster (manual CSV export, or an unofficial API)
# https://dnsdumpster.com -> enter target.example.com -> export CSV

# Searchcode (find subdomains hardcoded in open-source code)
# https://searchcode.com/?q=target.example.com -> search the string

# One-shot crt.sh + status-code triage
cat << 'EOF' > /tmp/crtsh_triage.sh
#!/bin/bash
DOMAINS=$(curl -s "https://crt.sh/?q=%25.$1&output=json" | jq -r '.[]|.name_value' | sed 's/\*\.//g' | sort -u)
for DOMAIN in $DOMAINS; do
    curl -sL -o /dev/null -w "%{url_effective}: %{http_code}\n" https://$DOMAIN
done
EOF
bash /tmp/crtsh_triage.sh target.example.com | tee crtsh_status.txt
```

**1.3 Reverse / lateral pivoting (from one known asset to associated infrastructure)**

Sections 1.1/1.2 above are **forward enumeration** (target -> assets). This is the **reverse** direction: start from one known asset (an IP, a certificate, a page, a nameserver) and pivot outward to other assets under the same owner or infrastructure. This is how you find the real origin behind a CDN, surface related subsidiaries/acquisitions/shadow assets, and expand scope. These pivots are primarily passive/OSINT-based.

| Pivot | How to think about it |
|---|---|
| **Shared TLS certificate -> associated assets** | A certificate's SAN list, or another certificate sharing the same fingerprint, often spans multiple assets under the same owner. Don't rely on crt.sh alone — cross-reference with certspotter and other CT-log sources to avoid missing entries. |
| **IP / CDN /24 reverse lookup -> co-hosted assets** | Reverse-lookup an IP to find every domain hosted on the same machine; reverse-lookup a CDN's /24 block to sweep neighboring assets in one pass. |
| **Brand / page-title search on urlscan -> ecosystem and scale** | Searching a brand name or a `page.title` value on urlscan can surface other infrastructure using the same technique — this is a lateral search, not a target-to-IP lookup. |
| **ASN fingerprint -> operator clustering** | Treat the ASN as a "who's hosting this" clustering signal (e.g. a bulletproof-hosting ASN groups a set of related assets), not just a target-to-IP-range lookup. |
| **Direct origin connection to bypass a CDN catch-all** | Send `Host: target.example.com` with `curl -I` directly against a suspected origin IP to bypass a CDN's SPA/404 catch-all and reach the real backend. |
| **Nameserver reverse lookup -> confirm common operator** | Reverse-lookup a self-hosted or shared nameserver across domains to confirm they belong to the same operator. |

Useful passive tools: `curl https://ip.thc.org/<domain|IP>` (no-auth passive DNS), the urlscan API, certspotter.

**Note**: some of these lateral-pivot techniques are equally applicable to broader OSINT/infrastructure-mapping work outside bug bounty (e.g. investigating scam or impersonation infrastructure), but that use case has its own methodology and safety considerations and is out of scope for this playbook.

---

### Phase 2: DNS Resolution & Brute-Forcing

Goal: validate the collected data and find hidden assets through permutation.

**2.1 Merge & resolve**

```bash
# Merge all subdomain lists, dedupe
cat sub*.txt crtsh_subs.txt securitytrails.txt | anew allsubs.txt

# Resolve with puredns (use a reliable resolver list)
cat allsubs.txt | puredns resolve -r resolvers.txt -w resolved.txt

# Recursive scan on already-resolved subdomains
subfinder -dL resolved.txt -all -recursive -o subfinder_recursive.txt
```

**2.2 Brute-force & permutation**

```bash
# Dictionary brute-force
puredns bruteforce wordlist.txt target.example.com -r resolvers.txt -w brute_results.txt

# AlterX permutation scanning
cat resolved.txt | alterx | dnsx -silent | anew resolved.txt
```

**2.3 Active DNS techniques (zone transfer & DNSSEC walk)**

**DNS Zone Transfer (AXFR)** — a misconfigured nameserver can hand over the entire zone in one request.

```bash
# Look up NS servers first
dig NS target.example.com +short

# Attempt AXFR against each NS server
dig AXFR target.example.com @ns1.target.example.com
dig AXFR target.example.com @ns2.target.example.com

# Batch attempt across all NS records
for NS in $(dig NS target.example.com +short); do
    echo "=== $NS ==="; dig AXFR target.example.com @$NS
done

# IXFR (incremental)
dig IXFR=0 target.example.com @ns1.target.example.com
```

Prioritize by target type: government (`.gov`), education (`.edu`), and legacy ISP nameservers tend to have a higher misconfiguration rate.

**DNSSEC Zone Walk (NSEC records)** — works on zones that have not migrated to NSEC3.

```bash
# Install
brew install ldns          # macOS
apt install ldnsutils      # Linux

# Zone walk (automatically traverses the NSEC chain)
ldns-walk target.example.com

# Save results
ldns-walk target.example.com | awk '{print $1}' | sed 's/\.$//' | sort -u > nsec_walk.txt
```

Distinguish NSEC from NSEC3:

```bash
dig DNSKEY target.example.com | grep -i nsec3  # present -> NSEC3 (hash-protected, needs a rainbow table)
dig NSEC target.example.com                     # a response -> can walk directly
```

**Merge all DNS sources**

```bash
cat crtsh_subs.txt rapid7_subs.txt nsec_walk.txt brute_results.txt | sort -u | \
  puredns resolve -r resolvers.txt -w resolved_all.txt
```

---

### Phase 3: Infrastructure & Port Analysis

Goal: find services and misconfigured virtual hosts.

**3.1 Port scanning (Naabu + Nmap)**

```bash
# Full port scan (exclude 80/443 to speed up)
naabu -list resolved.txt -p - -exclude-ports 80,443 -o allports.txt

# Service detection
nmap -sV -sC -iL allports.txt -oN nmap_details.txt

# Naabu + Nmap combined
naabu -list resolved.txt -c 50 -nmap-cli 'nmap -sV -sC' -o naabu_full.txt

# Top 1000 ports (excluding common ones)
naabu -list subs.txt -top-ports 1000 -exclude-ports 80,443,21,22,25 -o top1000ports.txt
```

**3.2 VHost & subdomain fuzzing**

```bash
# VHost discovery
ffuf -H 'Host: FUZZ.target.example.com' -u 'http://target.example.com' -w subdomains.txt -fs [size]

# API subdomain fuzzing
ffuf -u https://FUZZ.api.target.example.com -w wordlist.txt
ffuf -u https://api.FUZZ.target.example.com -w wordlist.txt
```

---

### Phase 4: Web Probing & Vulnerability Scanning

**4.1 Web liveness detection (httpx)**

```bash
# Basic
cat subs.txt | httpx --random-agent --status-code --title --server -td -cl | tee liv.txt

# Full version (with tech detection + response body)
httpx -list allsubs.txt \
  -status-code -content-length -content-type \
  -line-count -title -body-preview \
  -server -tech-detect \
  -probe-all-ips -include-response \
  -follow-host-redirects -random-agent \
  -o httpx_full.txt
```

**4.2 Nuclei & subdomain takeover**

```bash
# CVEs + exposures + misconfigurations
cat live_web.txt | nuclei \
  -t cves/ -t exposures/ -t misconfiguration/ \
  -severity critical,high,medium \
  -o nuclei_results.txt

# Subdomain takeover
subzy run --targets resolved.txt
subzy run --targets subs.txt --concurrency 100 --hide_fails --verify_ssl
```

---

### Phase 5: Deep Content & JavaScript Analysis

Goal: mine secrets and sensitive files from JS and archived content.

**5.1 URL & file extraction**

```bash
# Historical URLs
waymore -i target.example.com -mode U -oU urls.txt
katana -u target.example.com -kf robotstxt,sitemapxml -o katana_urls.txt

# Find sensitive files
cat urls.txt | grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.zip|\.bak|\.config|\.yaml" \
  | tee sensitive_files.txt
```

**5.2 Deep JavaScript analysis**

```bash
# Find JS files
cat urls.txt | grep "\.js$" | httpx -mc 200 > js_files.txt
cat resolved.txt | getJS --complete | anew js_files.txt

# Extract endpoints from JS
cat js_files.txt | while read url; do
  curl -s $url | grep -aoP "(?<=(\"|\'|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))"
done | sort -u > endpoints.txt
```

---

### Phase 6: Input & Parameter Fuzzing

**6.1 Parameter discovery**

```bash
arjun -i live_web.txt -m GET -oT params.txt
```

**6.2 Automated vulnerability testing**

```bash
# LFI testing
cat live_web.txt | gf lfi | qsreplace "FUZZ" | while read url; do
  ffuf -u $url -w lfi_payloads.txt -mr "root:"
done

# XSS testing (automated chain)
cat urls.txt | gf xss | uro | Gxss -p Rxss | dalfox pipe

# Directory scanning
ffuf -u https://target.example.com/FUZZ -w fuzz_wordlist.txt -mc 200,302
ffuf -u https://target.example.com/FUZZ.php -w words.txt -mc 200,302
ffuf -u https://target.example.com/FUZZ.zip -w words.txt -mc 200,302
```

---

### Phase 7: Historical / Dead Assets (a first-class attack surface)

Core idea: "what resolves right now" is the wrong question. The right question is "**what has ever been announced**."

**7.1 Why historical assets have value**

| Type | Why it can still be exploitable |
|---|---|
| Expired CT-log certificate hostnames | an internal resolver may still answer for `*.corp` / `*.intranet` names |
| Wayback / archive.org URLs | deprecated endpoints often were never upgraded to the current auth model |
| Abandoned subdomain CNAMEs | a third-party service that was never unbound -> subdomain takeover (see [[Pattern - Subdomain Takeover]]) |
| Old API paths (`/v1/`, `/legacy/`) | usually have weaker ownership/authorization checks |
| Secrets in GitHub commit history | a token from before rotation may still be valid if the commit was never force-pushed away |

**7.2 Build a full hostname corpus (merge six sources)**

```bash
# (a) Passive subdomains (same as Phase 1.2)
# (b) CT logs
curl -s "https://crt.sh/?q=%25.target.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' >> corpus.txt
curl -s "https://api.certspotter.com/v1/issuances?domain=target.example.com&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' >> corpus.txt

# (c) Passive DNS (SecurityTrails / VirusTotal / Chaos)
chaos -d target.example.com -silent >> corpus.txt
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=target.example.com&apikey=KEY" | jq -r '.subdomains[]' >> corpus.txt

# (d) Hostnames seen in the Wayback archive
waymore -i target.example.com -mode U | grep -Eo 'https?://[^/]+' | sed 's|https\?://||' | sort -u >> corpus.txt

# (e) Hostnames hardcoded in JS / API responses
cat js_files.txt | while read u; do curl -s "$u" | grep -Eo '[a-z0-9.-]+\.target\.example\.com' ; done >> corpus.txt

# (f) HTTP redirect headers
cat resolved.txt | httpx -location -silent | grep -oP 'https?://\S+' >> corpus.txt

sort -u corpus.txt > corpus_uniq.txt
```

**7.3 Filter for NXDOMAIN (internal-only) entries**

```bash
# Keep only hostnames that public DNS cannot resolve
cat corpus_uniq.txt | dnsx -silent -resp -nc | awk '{print $1}' > resolved_now.txt
sort corpus_uniq.txt resolved_now.txt resolved_now.txt | uniq -u > nxdomain_corpus.txt

# Sanity check: these existed at some point but don't resolve now
wc -l nxdomain_corpus.txt
```

**7.4 Feed the NXDOMAIN list into any SSRF/proxy primitive**

Precondition: the target exposes at least one service that lets you control the upstream Host — a webhook, URL preview, image fetch, PDF render, HTML-to-PDF converter, or open redirect.

```bash
# Burp Intruder
# Find a webhook / URL-fetch endpoint
# Payload position: the host portion of the URL
# Payload set: nxdomain_corpus.txt
# Grep the response body for: "internal", "admin", "swagger", error messages

# Or with ffuf
ffuf -u "https://target.example.com/api/webhook?url=http://FUZZ/health" \
     -w nxdomain_corpus.txt \
     -mc 200,302,401,500 \
     -fs 0 \
     -of json -o ssrf_internal_hits.json
```

A non-empty body / a response length different from the baseline indicates an **internal service hit**.

**7.5 Key takeaways**

1. Recon is not a one-time activity: CT logs get new certificates daily — re-run the corpus build every time you revisit a target.
2. NXDOMAIN does not mean dead: internal split-horizon DNS may still answer for these hostnames from inside the network.
3. Any service that lets you control the upstream Host is a target for this technique.

---

### Phase 8: Continuous Monitoring

Core idea: turn "found it once" into "found it automatically, every day" — a systematic first-mover advantage.

**8.1 A minimal cron pipeline (subdomain-takeover monitoring)**

```bash
#!/bin/bash
# sub_monitor.sh
set -euo pipefail
WORK=/opt/bbh/work
mkdir -p "$WORK"
cd "$WORK"

# 1. Subdomains (per wildcard root domain)
> all_subs_today.txt
while read domain; do
  subfinder -silent -d "$domain" >> all_subs_today.txt
done < /opt/bbh/wildcard.txt

sort -u all_subs_today.txt > subs_today.txt

# 2. Diff to find new entries
comm -13 <(sort subs_yesterday.txt 2>/dev/null) subs_today.txt > new_subs.txt

# 3. Run takeover detection against all subdomains
subzy run --targets subs_today.txt --hide_fails > subzy_today.txt
nuclei -l subs_today.txt -t ~/nuclei-templates/http/takeovers/ -silent > nuclei_today.txt

# 4. Notify
if [[ -s new_subs.txt ]] || [[ -s nuclei_today.txt ]]; then
  cat new_subs.txt nuclei_today.txt | curl -s -F "chat_id=$TG_CHAT" -F "text=$(cat -)" "https://api.telegram.org/bot$TG_TOKEN/sendMessage"
fi

# 5. Roll over
mv subs_today.txt subs_yesterday.txt
```

```cron
# crontab -e
0 6 * * * /opt/bbh/sub_monitor.sh >> /var/log/bbh.log 2>&1
```

**8.2 What to monitor (ranked by value)**

| Target | Tool | Trigger condition |
|---|---|---|
| New subdomains | subfinder + diff | any `+1` |
| New takeover candidates | subzy / nuclei takeovers | fingerprint match |
| JS bundle hash change | `curl + sha256` comparison | hash changes -> re-run source-map mining |
| GitHub commits | `gh search code "target.example.com"` | new commit matching a secret pattern |
| Subdomain SSL nearing expiry | `openssl s_client + openssl x509 -enddate` | < 30 days -> possible takeover window |
| New endpoints (from Wayback) | `waymore` re-run weekly | new path appears |
| Bug-bounty program scope changes | platform API + diff | scope expansion |

---

## Decision Points

- **DNS layer before HTTP layer (DNS-first enumeration)**: resolving a domain name is far cheaper than a TCP+HTTP probe, so mistakes here cost almost nothing. Order of operations: `dnsx`/`massdns` across the full subdomain list first -> confirm liveness -> only then start HTTP probing. HTTP-first wastes multiples of the time budget on non-responsive hosts.
- **Read the target's security bulletins before digging**: changelogs, advisories, and CVE pages describing what was fixed often reveal attack surfaces that were previously neglected — look especially for feature modules that received a fix, version ranges with unusually large patch gaps (implying long-term neglect), and "security fix" changelog entries with no assigned CVE (often a quietly-patched issue). This belongs in the Phase 1 intelligence-gathering stage.
- **Complete tool inventory** (mapped to the phase each tool supports):

| Tool | Phase | Purpose | Install |
|---|---|---|---|
| subfinder | P1/P2 | subdomain enumeration | `brew install subfinder` |
| amass | P1 | subdomain enumeration | `brew install amass` |
| findomain | P1 | subdomain enumeration | `brew install findomain` |
| assetfinder | P1 | subdomain enumeration | `go install` |
| Chaos | P1 | ProjectDiscovery subdomain data | `go install` |
| bbot | P1 | fully automated recon | `pip install bbot` |
| asnmap | P1 | ASN -> IP range | `go install` |
| mapcidr | P1 | CIDR conversion | `go install` |
| puredns | P2 | DNS resolve + brute-force | `go install` |
| alterx | P2 | subdomain permutation | `go install` |
| dnsx | P2 | DNS queries | `go install` |
| naabu | P3 | port scanning | `go install` |
| nmap | P3 | service detection | `brew install nmap` |
| ffuf | P3/P6 | fuzzing | `brew install ffuf` |
| httpx | P4 | web liveness detection | `go install` |
| nuclei | P4 | vulnerability scanning | `brew install nuclei` |
| subzy | P4 | subdomain takeover | `go install` |
| waymore | P5 | historical URLs | `pip install waymore` |
| katana | P5 | URL crawling | `go install` |
| getJS | P5 | JS file discovery | `npm install -g` |
| arjun | P6 | parameter discovery | `pip install arjun` |
| gf | P6 | pattern filtering | `go install` |
| uro | P6 | URL deduplication | `pip install uro` |
| Gxss | P6 | XSS parameter filtering | `go install` |
| dalfox | P6 | XSS scanning | `brew install dalfox` |
| anew | all phases | incremental dedup | `go install` |

- **Recommended wordlist resources**: [SecLists](https://github.com/danielmiessler/SecLists) (the most comprehensive wordlist collection), [resolvers.txt](https://github.com/trickest/resolvers) (a reliable DNS resolver list), [fuzz_wordlist.txt](https://github.com/Bo0oM/fuzz.txt) (directory fuzzing).

## Expected Outputs

- A merged, deduplicated, resolved subdomain/hostname corpus, plus a separate NXDOMAIN (internal-only) subset.
- Live-host inventory with tech fingerprints (`httpx_full.txt` equivalent).
- Port/service scan results and any misconfigured VHosts found.
- Nuclei findings (CVE/exposure/misconfiguration) and subdomain-takeover candidates, triaged by severity.
- Extracted endpoint list from JS/archive mining, and any sensitive files discovered.
- Parameter list per live endpoint, ready for the input-fuzzing phase.
- (If continuous monitoring is set up) a running diff pipeline that surfaces new subdomains and takeover candidates automatically.

## Related

- [[Playbook - API Attack Surface]]
- [[Pattern - Subdomain Takeover]]
- [[Checklist - XSS Rat 2026]]
- [[Tool - Cloud and DNS Recon Toolkit]]
