---
type: pattern
title: Fastly Subdomain Takeover (Dangling CNAME to unclaimed CDN)
vuln_class: subdomain-takeover
last_updated: 2026-04-19
status: active
tags:
  - bb-pattern
---

# Pattern: Fastly Subdomain Takeover (Dangling CNAME → unclaimed CDN)

> When `*.example.com`'s DNS CNAME points at a Fastly edge node but **no Fastly service has claimed it**, anyone can register a free Fastly account, claim that hostname, and serve attacker-controlled content from the legitimate `*.example.com` subdomain.

## Core identification

1. **CNAME → Fastly edge**: `*.sni.global.fastly.net` / `*.fastly.net`
2. **HTTP request returns "unknown domain"**:
   ```
   HTTP/1.1 500 Domain Not Found
   <title>Fastly error: unknown domain X. Please check that this domain has been added to a service.</title>
   ```
3. **This error message is the unclaimed-confirmation signal**

## Scanning script

```bash
# Use the Google DNS API (avoids local cache) to batch-check CNAMEs
for sub in $(cat subdomains.txt); do
  cname=$(curl -s "https://dns.google/resolve?name=$sub&type=CNAME" \
    | jq -r '.Answer[]?.data')
  if [[ "$cname" == *fastly* ]]; then
    body=$(curl -s "http://$sub/")
    if echo "$body" | grep -q "Fastly error: unknown domain"; then
      echo "✅ UNCLAIMED: $sub → $cname"
    fi
  fi
done
```

## Verification PoC (non-destructive)

```bash
# Step 1: confirm the CNAME
curl -s "https://dns.google/resolve?name=target.example.com&type=CNAME" | jq -r '.Answer[].data'
# → n.sni.global.fastly.net

# Step 2: confirm Fastly hasn't claimed it
curl -si "http://target.example.com/" | grep "Fastly error: unknown domain"
# → Fastly error: unknown domain target.example.com
```

**Step 3 (actually claiming it):** ⚠️ **Consider claiming the hostname before reporting** — see the "claim before reporting" section below.

## Bugcrowd VRT severity

- **Subdomain Takeover → P2 Default**
- If the subdomain touches auth/token/api → P2 High
- If the subdomain is used for shared cookie scope → P1 candidate (impact-dependent)

## Real-world case study

### A staging/token subdomain of a large consumer brand

- CNAME: `n.sni.global.fastly.net`
- Response: `Fastly error: unknown domain <subdomain>`
- Naming implied it was token/staging auth infrastructure
- Scope status: borderline (not explicitly in-scope, but not explicitly OOS either)
- Submission strategy: submit with a scope note

Other unclaimed Fastly CNAMEs found on the same program but out of scope:
- a `tokens.*` subdomain
- an `api-staging.*` subdomain
- a `headertest.*` subdomain

## ⚠️ Claim before reporting (an important operational strategy)

> **Risk:** some programs, upon receiving a report, delete the dangling DNS CNAME during triage — so the triager can no longer reproduce it and replies "unable to reproduce / N/A". A more adversarial version of this: the company claims the hostname itself (S3/Fastly) and then says "already fixed, not a valid finding."

**Recommended sequence (Fastly):**
1. Confirm the CNAME points to `*.fastly.net` and the response is `Fastly error: unknown domain`
2. **Claim the hostname on a free Fastly account** (add the domain to your own Fastly service)
3. Upload a simple PoC HTML page (shows your finder ID and the date, no malicious behavior)
4. Screenshot proof that your content is served from `target.example.com`
5. **Only then submit the report**, with the screenshot as non-repudiable proof
6. After the report is accepted, you can delete your Fastly service or notify the company to take it over

**Same logic applies to S3 bucket takeover:**
1. Confirm the CNAME points to `*.s3.amazonaws.com` and returns `NoSuchBucket`
2. Create a bucket with the same name (first-come-first-served)
3. Upload a PoC file, enable static hosting
4. Screenshot confirming your content is served
5. Submit the report

**Notes:**
- PoC content should only contain the finder's ID and discovery date — no malicious code or phishing content
- A compliant, bug-bounty-context claim of an unclaimed resource fits within most programs' safe harbor (not unauthorized access)
- Whether to keep or immediately tear down the claim after submission depends on the program's safe harbor terms

## Remediation (for the report's remediation section)

1. **Immediate**: delete the dangling DNS CNAME record, or claim the hostname in the Fastly console and point it at a controlled origin
2. **Long term**: audit every `*.company.com` CNAME record and confirm the third-party CDN it points to (Fastly, CloudFront, Akamai, Heroku, Azure, GitHub Pages) has actually been claimed
3. **CI/CD stage**: check DNS/CDN consistency before deployment

## Other CDN variants

The same dangling-CNAME + unclaimed pattern exists across other providers:

| CDN | Identification signal |
|-----|---------|
| **AWS CloudFront** | `NoSuchBucket` or `The specified distribution could not be found` |
| **GitHub Pages** | `There isn't a GitHub Pages site here` |
| **Heroku** | `No such app` |
| **Azure Traffic Manager** | `404` on `*.azurewebsites.net` |
| **Netlify** | `Not Found - Request ID: ...` |
| **Pantheon** | `The gods are wise, but do not know of the site which you seek` |
| **Shopify** | `Only one step left!` |
| **Tumblr** | `Whatever you were looking for doesn't currently exist` |
| **WordPress.com** | `Do you want to register X?` |

## Tools

| Tool | URL | Purpose |
|------|-----|------|
| **subjack** | https://github.com/haccer/subjack | Automated subdomain-takeover scanning |
| **subzy** | https://github.com/PentestPad/subzy | Modern successor to subjack, supports more CDNs |
| **nuclei + takeover templates** | https://github.com/projectdiscovery/nuclei-templates/tree/main/http/takeovers | Integrates into a nuclei pipeline |
| **dnsx + httpx** | https://github.com/projectdiscovery/dnsx | Batch CNAME + HTTP checks |

## Continuous Monitoring Pipeline

> Automate takeover detection — run it daily at 06:00 and notify on any hit.

```bash
#!/bin/bash
# takeover_daily.sh
WORK=/opt/bbh
cd $WORK

# 1. Run subfinder against every wildcard root
> all_subs.txt
while read domain; do
  subfinder -silent -d "$domain" >> all_subs.txt
done < wildcard.txt
sort -u all_subs.txt > subs_today.txt

# 2. Find takeover candidates (subzy is fast but has weaker coverage)
subzy run --targets subs_today.txt --hide_fails > subzy.txt

# 3. Verify with nuclei takeover templates (low false-positive rate)
nuclei -l subs_today.txt -t ~/nuclei-templates/http/takeovers/ -silent > nuclei_take.txt

# 4. Diff against yesterday → notify only on new hits
comm -13 <(sort takeover_yesterday.txt 2>/dev/null) <(sort nuclei_take.txt) > new_takeovers.txt

# 5. Send a notification
[[ -s new_takeovers.txt ]] && curl -s -F "chat_id=$TG_CHAT" \
  -F "text=🚨 New takeover candidates:\n$(cat new_takeovers.txt)" \
  "https://api.telegram.org/bot$TG_TOKEN/sendMessage"

mv nuclei_take.txt takeover_yesterday.txt
```

```cron
0 6 * * * /opt/bbh/takeover_daily.sh >> /var/log/takeover.log 2>&1
```

**Triage sequence** (< 5 minutes from hit to decision):
1. `dig +short CNAME sub.target.com` → confirm it points to a third party
2. `curl -I https://sub.target.com` → grab a fingerprint
3. Register a free-tier app (Heroku etc.) and bind the domain
4. Upload a minimal PoC page (finder ID + date)
5. `curl -I` shows 200 + your content → screenshot
6. Submit the report

## Related

- can-i-take-over-xyz — full CDN takeover reference: https://github.com/EdOverflow/can-i-take-over-xyz
