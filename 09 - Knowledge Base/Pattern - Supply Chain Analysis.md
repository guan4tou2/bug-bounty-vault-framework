---
type: pattern
title: Supply Chain Analysis (Vendor / Development-Agency Pivoting)
vuln_class: supply-chain
last_updated: 2026-04-06
status: active
tags:
  - bb-pattern
---

# Pattern: Supply Chain Analysis (Development-Agency Pivoting)

> Finding a development agency/vendor = finding vulnerabilities in all of its clients. This multiplier effect is one of the highest-ROI attack paths in bug bounty.

## Signals that reveal the development agency behind a site

| Signal | Where to find it | Tool |
|------|------|------|
| `.git/config` remote URL | after a `.git` directory dump | `git config --get remote.origin.url` |
| Copyright / "powered by" / "designed by" strings | page source | `grep -r "copyright\|powered by\|designed by"` |
| Shared CSS/JS CDN paths | identical path across multiple client sites | manual comparison |
| Commit author email | `git log --format="%ae"` | `git log` |
| WHOIS registrant | domain lookup | `whois domain.com` |
| A public Gitea/GitLab instance run by the agency | the agency's own git server | browse directly |

## Real-world case studies (generalized)

### Case A — a regional web agency: a customer .git exposure → agency compromise → all clients

**Discovery process**:
```
A client's exposed .git directory → git log → an agency email address in the commit history
→ the agency's own primary site also had an exposed .git
→ discovered 4 client sites reachable from there: a CGI printenv leak, a phpinfo+admin
  panel, a leaked API secret, and a stored XSS
→ 3 downstream clients affected, one with externally-reachable MySQL credentials
```

**Impact**:
- Client 1: leaked mail-service API key + SMTP credentials
- Client 2: SMTP credentials + an exposed `.git`
- Client 3: exposed `.git` + external MySQL credentials + an outdated phpMyAdmin instance

**Key takeaway**: a single client's `.git` exposure led to compromising the entire agency's client base.

### Case B — a digital agency: backdoored SSO SDK

**Discovery process**:
```
A client's .git → .git/config → the agency's own Gitea instance
→ the Gitea instance had 7 public repos, including the agency's SSO SDK
→ the SDK had a hardcoded default app_key value ('default')
→ signature forgery: md5('DEFAULT' + timestamp)
→ every client integrating that SDK could have their SSO bypassed
```

**Scope**: the original client plus every other organization using the agency's SSO SDK.

### Case C — a hosting/dev vendor: RCE on the vendor's own infrastructure

**Discovery process**:
```
A client's .git → an API_DOMAIN reference → the vendor's own domain
→ the vendor's robots.txt → 4 sub-application paths
→ one sub-app's exposed .git → backend source code
→ hardcoded database credentials + an unauthenticated file-upload endpoint → RCE
→ resulting shell had ALL PRIVILEGES on ~28 client databases
```

**Impact**: full database privileges across ~28 downstream client sites; an unrelated third-party site (a university) was found hosted on the same IP, illustrating the blast radius of shared infrastructure.

## Multiplier-effect calculation

```
1 exposed .git on a client site
  ↓
the development agency's own Gitea / GitLab instance (often public)
  ↓
shared SDK / framework source code
  ↓
a common vulnerability pattern
  ↓
N clients × the same vulnerability

Number of reports = N (one submitted per affected client/organization)
```

## Supply-chain recon SOP

```bash
# Step 1: identify the development agency from a client's .git
git log --format="%ae %an" | sort -u
cat .git/config | grep url

# Step 2: find the agency's own git server
curl -s https://git.<agency-domain>  # Gitea
curl -s https://gitlab.<agency-domain>  # GitLab

# Step 3: enumerate the agency's public repos
# Gitea: GET /api/v1/repos/search?limit=50
curl -s "https://git.<agency-domain>/api/v1/repos/search?limit=50" | jq '.[].full_name'

# Step 4: find shared SDKs / common components
grep -r "require\|include\|import" --include="*.php" -l

# Step 5: enumerate all downstream clients
# crt.sh search on the agency's dev email address
curl -s "https://crt.sh/?q=dev@agency-domain.example&output=json" | jq -r '.[].common_name' | sort -u
```

## Reporting strategy

| Approach | Best for | Notes |
|------|---------|------|
| One report covering all clients | programs that reward chained attacks | emphasize the multiplier effect |
| A separate report per client | programs that score per-report | impact is clearer per submission |
| Report directly to the agency | when the agency has a security contact | fastest remediation path |
| National CERT | SDK-level vulnerabilities eligible for a CVE | requires a PoC |

## Related

- Pattern — Git Exposure: the starting point for this kind of analysis
