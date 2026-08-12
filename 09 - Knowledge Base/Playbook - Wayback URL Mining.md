---
type: playbook
title: "Wayback URL Mining"
tags: [playbook, recon, wayback-machine, url-mining, osint, bb-playbook]
category: recon
status: draft
last_updated: 2026-08-12
sources:
  - https://medium.com/@nitinsgavane/mining-wayback-urls-for-high-impact-vulnerability-discovery-dfa6ebbe63aa
---

# Playbook - Wayback URL Mining

> **TL;DR**: History on the internet never really disappears. Old endpoints, deprecated parameters, and legacy code sleep inside the Wayback Machine and Common Crawl, waiting to be rediscovered. This playbook collects historical URLs with waybackurls/gau, classifies them by vulnerability class using grep patterns and `gf`, verifies which are still alive with `httpx`, and then runs targeted deep tests (deprecated API auth, open redirect, IDOR, hidden parameters, JS secret mining, nuclei) against the survivors.

## Scope / When to use

Use this playbook whenever you start recon on a target and want to surface attack surface that no longer exists in the current site map but may still be reachable. The core insight: **past endpoints don't have present-day protections** —

- Old API endpoints may lack authentication that was added later.
- Old parameters may have looser input validation than the current version.
- Deprecated paths may not be covered by the current WAF ruleset.
- Historical debug/test endpoints may still be alive in production.

## Phases

### Phase 1: URL Collection

Use two tools together (they draw from different data sources):

```bash
TARGET="example.com"

# waybackurls: Wayback Machine specialist
echo $TARGET | waybackurls > wayback_urls.txt

# gau: multi-source (Wayback + Common Crawl + AlienVault OTX + URLScan)
# --subs: include all subdomains as well
gau --subs $TARGET > gau_urls.txt

# merge and deduplicate
cat wayback_urls.txt gau_urls.txt | sort -u > all_urls.txt
wc -l all_urls.txt  # confirm collection volume

# install
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/gf@latest          # pattern-based grep (see Phase 2b)
```

### Phase 2: Classification / Filtering (by vulnerability type)

```bash
# === Auth / OAuth / Session ===
grep -E "(oauth|callback|token|session|sso|saml|auth|login)" all_urls.txt \
  | grep -E "(\?|&)(code|token|state|redirect|next|return)" > auth_urls.txt

# === Open Redirect ===
grep -E "(\?|&)(redirect|url|next|return|goto|continue|dest|destination)=" all_urls.txt \
  > redirect_urls.txt

# === IDOR candidates (URLs with an ID parameter) ===
grep -E "(\?|&)(id|user_id|account_id|uid|uuid|object_id|item_id|order_id|file_id)=" all_urls.txt \
  > idor_urls.txt

# === Sensitive files / backups ===
grep -E "\.(bak|backup|old|temp|tmp|sql|db|log|config|conf|env|yaml|yml|json|xml)$" all_urls.txt \
  > sensitive_files.txt

# === Admin / Debug / Test endpoints ===
grep -E "/(admin|debug|test|staging|dev|internal|management|console|dashboard|panel)" all_urls.txt \
  > admin_urls.txt

# === API endpoints ===
grep -E "/(api/v[0-9]|api/[a-z]+|graphql|rest|rpc|endpoint|service)" all_urls.txt \
  > api_urls.txt

# === Parameter-rich URLs (higher testing value) ===
awk -F'?' 'NF>1{count=gsub(/&/,"&",$2); if(count>=3) print}' all_urls.txt \
  > rich_param_urls.txt
```

### Phase 2b: gf — Pattern-Based Grep (more precise filtering)

`gf` is a grep wrapper by tomnomnom with built-in regex patterns for common vulnerability classes:

```bash
# install gf patterns
mkdir -p ~/.config/gf
git clone https://github.com/tomnomnom/gf ~/.local/gf-src
cp ~/.local/gf-src/examples/*.json ~/.config/gf/

# usage (more accurate than manual grep)
cat all_urls.txt | gf sqli        > sqli_candidates.txt
cat all_urls.txt | gf xss         > xss_candidates.txt
cat all_urls.txt | gf idor        > idor_candidates.txt
cat all_urls.txt | gf ssrf        > ssrf_candidates.txt
cat all_urls.txt | gf redirect    > redirect_candidates.txt
cat all_urls.txt | gf rce         > rce_candidates.txt
cat all_urls.txt | gf lfi         > lfi_candidates.txt
cat all_urls.txt | gf debug-pages > debug_candidates.txt
cat all_urls.txt | gf s3-buckets  > s3_candidates.txt
```

### Phase 3: Liveness Verification

Only test endpoints that actually still respond:

```bash
# confirm which URLs are still alive
cat all_urls.txt | httpx -silent -status-code -mc 200,301,302,401,403 \
  > live_urls.txt

# interpreting response codes:
# 200 -> directly testable
# 302 -> redirect target may indicate an open redirect
# 401/403 -> possible auth bypass (try replaying the historical token)
cat live_urls.txt | grep " 200" | wc -l  # count of 200s
cat live_urls.txt | grep " 403" | wc -l  # 403 -> auth bypass candidates
```

### Phase 4: Deep Testing of High-Value URLs

#### 4a. Deprecated API auth testing

```bash
# find old API paths (/api/v1/ when the current version is /api/v2/)
grep -E "/api/v[0-9]/" live_urls.txt

# for each old API endpoint, test:
# 1. direct access with no token (auth may not have been added yet when it was deprecated)
# 2. access the old version with a current token (may bypass restrictions added in the new version)
```

#### 4b. Open Redirect

```bash
# test redirect parameters
while IFS= read -r url; do
  response=$(curl -sI -L "$url" --max-redirs 3 | grep "Location:")
  if echo "$response" | grep -v "example.com"; then
    echo "OPEN REDIRECT: $url -> $response"
  fi
done < redirect_urls.txt
```

#### 4c. IDOR via historical URLs

```bash
# ID parameters in historical URLs are often real user IDs
# grab an id value and try accessing another user's resource with your own token
grep "user_id=" idor_urls.txt | head -20
```

#### 4d. Hidden parameter discovery

```bash
# use Arjun to find hidden parameters on a currently-live endpoint
pip3 install arjun

# run parameter discovery against a live URL
arjun -u "https://api.example.com/user" --stable
```

#### 4e. Nuclei batch scan

```bash
# run nuclei templates against all live URLs
nuclei -l live_urls.txt \
  -t ~/.local/nuclei-templates/exposures/ \
  -t ~/.local/nuclei-templates/misconfiguration/ \
  -t ~/.local/nuclei-templates/cves/ \
  -severity medium,high,critical
```

### Phase 5: JS File Analysis

Historical JS files can still contain old API endpoints or secrets:

```bash
# extract JS files from the URL list
grep -E "\.js(\?|$)" all_urls.txt | sort -u > js_files.txt

# confirm liveness with httpx
cat js_files.txt | httpx -silent -mc 200 > live_js.txt

# extract endpoints and secrets from JS
# LinkFinder
python3 linkfinder.py -i live_js.txt -o cli 2>/dev/null | grep "http"

# SecretFinder
python3 SecretFinder.py -i $(cat live_js.txt | head -1) -o cli
```

## Decision Points

| Type | Wayback clue | Severity |
|------|--------------|----------|
| OAuth callback bypass | Old `redirect_uri` value | P1 |
| Unauthenticated deprecated API | `/api/v1/users` returns data | P2 |
| Backup database file | `database.sql.bak` | P1 |
| Admin panel | `/admin/old-dashboard` | P2-P1 |
| Config file | `/config/production.yml` | P2 |
| IDOR via real ID | `?user_id=12345` | P2 |

- 200 responses are directly testable; prioritize them first.
- 302 redirects are open-redirect candidates — check the `Location` header for off-domain targets.
- 401/403 responses are auth-bypass candidates — try replaying tokens/parameters captured from the historical URL.
- Parameter-rich URLs (3+ query parameters) and deprecated `/api/v1/`-style paths are worth manual deep-dive even before automated scanning.

## Expected Outputs

- `all_urls.txt` — deduplicated union of waybackurls + gau output.
- Classified candidate lists: `auth_urls.txt`, `redirect_urls.txt`, `idor_urls.txt`, `sensitive_files.txt`, `admin_urls.txt`, `api_urls.txt`, `rich_param_urls.txt`, plus `gf`-generated `*_candidates.txt` files.
- `live_urls.txt` — status-code-verified subset of `all_urls.txt` that is safe to test further.
- `live_js.txt` and any endpoints/secrets extracted from historical JS via LinkFinder/SecretFinder.
- Nuclei scan results against `live_urls.txt` for exposures/misconfigurations/CVEs.
- A short list of high-value candidates (open redirect, deprecated API auth gap, IDOR, exposed backup/config file) ready for manual verification and Finding write-up.

### One-shot integration script

```bash
#!/bin/bash
TARGET=$1
mkdir -p recon/$TARGET/wayback

# collect
echo $TARGET | waybackurls > recon/$TARGET/wayback/wayback.txt
gau $TARGET > recon/$TARGET/wayback/gau.txt
cat recon/$TARGET/wayback/*.txt | sort -u > recon/$TARGET/wayback/all.txt

# filter
grep -E "(\?|&)(redirect|url|next|return)=" recon/$TARGET/wayback/all.txt \
  > recon/$TARGET/wayback/redirects.txt
grep -E "(\?|&)(id|user_id|account_id|uid)=" recon/$TARGET/wayback/all.txt \
  > recon/$TARGET/wayback/idor.txt
grep -E "\.(bak|sql|env|config)$" recon/$TARGET/wayback/all.txt \
  > recon/$TARGET/wayback/sensitive.txt

# liveness check
cat recon/$TARGET/wayback/all.txt | httpx -silent -status-code \
  > recon/$TARGET/wayback/live.txt

echo "Done. $(wc -l < recon/$TARGET/wayback/live.txt) live URLs found."
```

### Tool installation

```bash
# waybackurls
go install github.com/tomnomnom/waybackurls@latest

# gau
go install github.com/lc/gau/v2/cmd/gau@latest

# httpx
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# arjun
pip3 install arjun

# nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

## Related

- [[Playbook - Recon Methodology]] — full recon workflow
- [[Pattern - IDOR Response Differential]] — testing method once IDOR candidates are identified
- [[Tool - Arsenal Index]] — full tool inventory
