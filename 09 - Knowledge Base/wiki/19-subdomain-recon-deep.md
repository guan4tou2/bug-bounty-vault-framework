---
type: wiki
category: recon
status: active
last-updated: 2026-04-21
---

# Subdomain Recon Deep Dive

> **Purpose:** For large targets (fintech/telecom/cloud), running subfinder alone typically misses 30-50%. This chains together "passive → active → permutation → third-party → ASN" into one pipeline.
> **End goal:** Before feeding all `*.target.com` into httpx, get the subdomain list to 95%+ coverage.

## 0. Overall Flow

```
[passive] → [active resolve] → [permutation] → [third-party API] → [ASN/CIDR]
       ↓                   ↓                       ↓                  ↓                 ↓
  subfinder           dnsx/puredns            alterx/dnsgen     securitytrails   asnmap
  amass               shuffledns              gotator           chaos            whoisxml
  github-sub                                                    virustotal        censys
  ctfr                                                          shodan
       ↓
 [merged + dedup] → httpx alive detection → flag new vs known
```

## 1. Passive

### subfinder (basic)

```bash
subfinder -d target.com -all -silent -o sub_subfinder.txt

# -all = enable all sources (slow but broad coverage)
# -silent = only output subdomains, for piping
# -recursive = recurse on found subdomains
```

**API key setup (important)**: `~/.config/subfinder/provider-config.yaml`

```yaml
binaryedge:
  - BINARYEDGE_KEY
censys:
  - CENSYS_ID:CENSYS_SECRET
chaos:
  - CHAOS_KEY
github:
  - GITHUB_PAT_1
  - GITHUB_PAT_2
passivetotal:
  - USER:KEY
securitytrails:
  - ST_KEY
shodan:
  - SHODAN_KEY
virustotal:
  - VT_KEY
zoomeye:
  - USER:KEY
```

Without keys, coverage is around 60%; with all keys configured, coverage can reach 85-90%.

### amass (complementary)

```bash
amass enum -passive -d target.com -o sub_amass.txt

# Enable more sources
amass enum -passive -d target.com -src -o sub_amass.txt

# Can also do intel
amass intel -org "Target Corp" -o intel.txt
amass intel -asn 16509 -o asn_intel.txt
```

Amass and subfinder results **overlap around 60%**, but each has unique sources — run both.

### assetfinder (fast fallback)

```bash
assetfinder --subs-only target.com > sub_assetfinder.txt

# Lightweight, finishes in under 5 seconds, good for filling gaps
```

### github-subdomains

```bash
# Find subdomains from public GitHub repos
go install github.com/gwen001/github-subdomains@latest

GITHUB_TOKEN=ghp_xxx github-subdomains -d target.com -o sub_github.txt
```

GitHub sources are especially good at finding **staging / dev / internal** hostnames (usually in `.env.example` or docker-compose files).

### chaos (from ProjectDiscovery)

```bash
# chaos-client = the subdomain DB continuously collected by Project Discovery
# https://chaos.projectdiscovery.io/ apply for a free key

chaos -d target.com -o sub_chaos.txt

# Download the entire program's historical data
chaos -dl "target_program" -o chaos_full.zip
```

### ctfr (Certificate Transparency logs)

```bash
# https://github.com/UnaPibaGeek/ctfr
python3 ctfr.py -d target.com -o sub_ctfr.txt
```

Or curl crt.sh directly:

```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > sub_crt.txt

# Note: crt.sh occasionally times out, retry
```

### Merging passive results

```bash
cat sub_*.txt | sort -u > passive_raw.txt
wc -l passive_raw.txt
```

## 2. Active Resolve (filter to what actually resolves via DNS)

Many subdomains found via passive sources are wildcard pollution or stale leftovers — need DNS verification.

### dnsx (single-pass verification)

```bash
# Basic: A record verification
dnsx -l passive_raw.txt -silent -o alive.txt

# Faster: custom resolvers (avoid local DNS getting rate-limited)
dnsx -l passive_raw.txt -silent -r resolvers.txt -o alive.txt

# Full records + CNAME extraction (find takeover candidates)
dnsx -l passive_raw.txt -silent -a -cname -resp -o alive_detail.txt
```

**resolvers.txt** (trusted list):

```
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
```

Or use ProjectDiscovery's:

```bash
wget https://raw.githubusercontent.com/projectdiscovery/dnsx/main/resolvers.txt
```

### puredns (mass brute-force + wildcard filtering)

puredns's strongest point is **automatically handling wildcard DNS responses**.

```bash
# Install
go install github.com/d3mondev/puredns/v2@latest

# Brute-force from a dictionary
puredns bruteforce ~/Tools/SecLists/Discovery/DNS/namelist.txt target.com \
  -r resolvers.txt \
  -w sub_brute.txt

# Verify the passive list (remove wildcards)
puredns resolve passive_raw.txt \
  -r resolvers.txt \
  -w sub_resolved.txt
```

### shuffledns (ProjectDiscovery's brute-force variant)

```bash
shuffledns -d target.com \
  -w ~/Tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -r resolvers.txt \
  -o sub_shuffle.txt
```

## 3. Permutation / Alteration

Generate variations of existing subdomains (dev/stg/api/old/new/suffix/prefix).

### alterx (ProjectDiscovery)

```bash
# Basic permutation
alterx -l resolved.txt -o permuted.txt

# Custom payload
alterx -l resolved.txt -p '{{word}}-{{suffix}}' -enrich -o permuted.txt

# With enrich (expand using a wordlist)
alterx -l resolved.txt -enrich | dnsx -silent -o permuted_alive.txt
```

### dnsgen

```bash
pip3 install dnsgen
dnsgen resolved.txt > permuted_dnsgen.txt
dnsx -l permuted_dnsgen.txt -silent -o dnsgen_alive.txt
```

### gotator (most fine-grained)

```bash
# https://github.com/Josue87/gotator
go install github.com/Josue87/gotator@latest

gotator -sub resolved.txt \
  -perm permutations.txt \
  -depth 2 \
  -numbers 10 \
  -mindup \
  -adv \
  > permuted_gotator.txt
```

**permutations.txt** common words:

```
dev
staging
stg
qa
test
uat
internal
private
admin
old
legacy
new
v1
v2
api
console
portal
panel
corp
mgmt
```

## 4. Third-Party APIs (gap-filling)

### SecurityTrails

```bash
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
  -H "APIKEY: YOUR_KEY" | jq -r '.subdomains[]' | \
  sed "s/$/.target.com/" > sub_st.txt
```

### VirusTotal

```bash
# Historical resolutions + subdomains
curl -s "https://www.virustotal.com/api/v3/domains/target.com/subdomains?limit=40" \
  -H "x-apikey: $VT_KEY" | jq -r '.data[].id' > sub_vt.txt
```

### Censys

```bash
# censys CLI
censys search "parsed.names: target.com" --index-type certificates | \
  jq -r '.parsed.names[]' | grep target.com > sub_censys.txt
```

### Shodan

```bash
# Find via cert
shodan search "ssl.cert.subject.cn:*.target.com" --fields hostnames | \
  tr ',' '\n' | grep target.com > sub_shodan.txt
```

## 5. ASN / CIDR Reverse Lookup (find assets that "forgot" DNS)

Some internal services only have an IP, no DNS. Find the org's ASN → scan the CIDR.

### asnmap (ProjectDiscovery)

```bash
# Org name → ASN
asnmap -org "Target Corp" -silent

# ASN → CIDR
asnmap -a AS16509 -silent

# Domain → ASN → CIDR
echo "target.com" | asnmap -silent
```

### whoisxmlapi reverse lookup

```bash
# IP → hostnames on the same ASN
curl -s "https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=$KEY&ip=1.2.3.4" | \
  jq -r '.result.records[].name'
```

### Combine with naabu / nmap to scan CIDR

```bash
# ASN → CIDR → naabu fast port scan
asnmap -a AS16509 -silent | naabu -silent -o open_ports.txt

# Only keep web ports
naabu -l cidr.txt -silent -p 80,443,8080,8443 -o web_ports.txt

# Run httpx against the open ports
httpx -l open_ports.txt -silent -title -tech-detect
```

## 6. Integrated Pipeline (all-in-one)

```bash
#!/bin/bash
# recon_deep.sh — deep subdomain enumeration
DOMAIN=$1
OUT=recon/$DOMAIN
mkdir -p $OUT

# 1. Passive
subfinder -d $DOMAIN -all -silent > $OUT/subfinder.txt &
amass enum -passive -d $DOMAIN -src -o $OUT/amass.txt &
assetfinder --subs-only $DOMAIN > $OUT/assetfinder.txt &
chaos -d $DOMAIN > $OUT/chaos.txt 2>/dev/null &
github-subdomains -d $DOMAIN -o $OUT/github.txt 2>/dev/null &
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
  jq -r '.[].name_value' | sed 's/\*\.//g' > $OUT/crt.txt &
wait

# 2. Merge + dedup
cat $OUT/*.txt 2>/dev/null | sort -u > $OUT/passive_raw.txt

# 3. Resolve + wildcard filter
puredns resolve $OUT/passive_raw.txt \
  -r resolvers.txt \
  -w $OUT/resolved.txt

# 4. Permutation
alterx -l $OUT/resolved.txt -enrich | \
  dnsx -silent -r resolvers.txt > $OUT/permuted.txt

# 5. Final
cat $OUT/resolved.txt $OUT/permuted.txt | sort -u > $OUT/all_subdomains.txt
wc -l $OUT/all_subdomains.txt

# 6. HTTPx alive check
httpx -l $OUT/all_subdomains.txt \
  -title -tech-detect -status-code -follow-redirects \
  -silent -o $OUT/live.txt
```

## 7. Advanced: Origins Masked by WAF/CDN

### Historical DNS (from before CDN protection)

```bash
# SecurityTrails history
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
  -H "APIKEY: $ST_KEY" | jq
# If you see an origin IP from before Cloudflare → keep it

# viewdns.info
curl -s "https://viewdns.info/iphistory/?domain=target.com"
```

### Shodan SSL reverse lookup

```bash
# Find IPs whose cert CN contains target.com
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,hostnames
# These IPs may be the origin (bypassing the WAF)
```

### CloudFlair

```bash
# https://github.com/christophetd/CloudFlair
pip3 install cloudflair
cloudflair target.com --censys-api-id $ID --censys-api-secret $SECRET
```

### Favicon hash

```bash
# 1. Compute favicon hash
curl -s https://target.com/favicon.ico | md5sum

# 2. Use Shodan to find IPs with the same hash
shodan search 'http.favicon.hash:-1234567890'
# Often finds the internal origin
```

## 8. Common Pitfalls

| Problem | Solution |
|------|------|
| Wildcard DNS returns garbage | Use puredns (auto-detects wildcards) |
| Your own DNS server gets rate limited | Use trusted resolvers + throttle with `-rate-limit 100` |
| Passive sources find many dead subdomains | Filter with dnsx before sending to httpx |
| HTTPS cert CN contains a wildcard (`*.target.com`) | Doesn't mean every subdomain exists — DNS verification is required |
| CDN returns 200 for every subdomain | Compare body hashes, filter out ones with the same hash |

## 9. bbflow Integration

```bash
# bbflow's default run does subfinder + httpx (10 minutes)
bbflow recon target.com

# For deeper digging, run the script manually and merge
./recon_deep.sh target.com

# Feed newly found subdomains back into bbflow
bbflow hunt --list recon/target.com/live.txt --name target --probe
```

## Related Files

- [22-tool-subfinder-httpx.md](22-tool-subfinder-httpx.md) — the basic version
- [40-checklist-new-target.md](40-checklist-new-target.md) § Phase 1
- Pentester Land Subdomain Enumeration Guide: https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html
