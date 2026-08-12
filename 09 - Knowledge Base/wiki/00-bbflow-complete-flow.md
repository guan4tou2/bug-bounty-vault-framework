---
type: wiki
category: flow
status: active
last-updated: 2026-04-21
---

# bbflow Complete Operating Flow

> From zero to submission, every step is actionable. `bbflow` is the CLI entry point for `$TOOLS_ROOT/bbflow.sh`, with zero LLM dependency.

## 0. Installation & Health Check

```bash
# First-time setup (from the BugBounty root directory)
cd "$VAULT_ROOT"
export PATH="$PWD/tools:$PATH"         # Make bbflow globally available
alias bbflow="$TOOLS_ROOT/bbflow.sh"

# Check dependencies
bbflow doctor
```

Expected output should include:
- `✓ nuclei / httpx / subfinder` — bundled under `$TOOLS_ROOT/`
- `✓ katana / gau / waybackurls / uro / gf` — need separate install
- `✓ dalfox / arjun / trufflehog / ffuf` — need separate install
- `✓ GAU_CONFIG → $TOOLS_ROOT/configs/gau.toml` — auto-mounted
- `✓ SecLists → ...` — wordlist path

### Filling gaps

```bash
# Go tools (subfinder/httpx/nuclei are bundled; the rest are below)
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/hakluke/hakscan@latest

# gf patterns (for crawl-chain classification)
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
# or git clone https://github.com/tomnomnom/gf then cp -r examples ~/.gf

# Python tools
pip3 install arjun paramspider uro --break-system-packages

# Homebrew
brew install dalfox ffuf feroxbuster rustscan nmap trufflehog
brew install gitleaks dnsx

# SecLists
git clone --depth=1 https://github.com/danielmiessler/SecLists.git ~/Tools/SecLists
```

### Syncing Nuclei templates

```bash
bbflow nuclei-update
# = nuclei -update-templates + clone topscoder/nuclei-wordfence-cve
```

## 1. Initialize a target

```bash
bbflow init example.com
# → creates a workshop/example.com/SCOPE.md template

# Fill in SCOPE.md manually (mandatory!)
vim workshop/example.com/SCOPE.md
```

**Required SCOPE.md fields:**
- Platform (HackerOne / Bugcrowd / HITCON / TWCERT / government program)
- In-scope assets (full list + wildcards)
- Out-of-scope rules (vuln classes + prohibited actions)
- Bounty range
- Submission rules

> ⚠️ **`bbflow recon` refuses to run if SCOPE.md is not filled in.** This is a mandatory scope-first rule.

## 2. Recon — passive subdomain enumeration + liveness detection

```bash
# Via BBOT (default) — fully passive, ~10 minutes
bbflow recon example.com

# Or via Osmedeus VPS (requires exporting OSMEDEUS_VPS first)
OSMEDEUS_VPS=user@1.2.3.4 bbflow recon example.com --osmedeus
```

Output:
- `workshop/example.com/bbot/subdomains.txt` — all discovered subdomains
- `workshop/example.com/bbot/live_hosts.txt` — URLs confirmed alive by httpx (`https://sub.example.com`)

### 2.5 Direct single-target hunt (skip recon)

```bash
# Hunt a single URL directly, without running recon
bbflow hunt https://target.example.com --only config-leak,weak-login

# Use an existing hostname list (e.g. manually collected from Shodan/Censys)
bbflow hunt --list hosts.txt --name my-program --probe --only cors,graphql
```

## 3. Hunt — run the hunters

### 3.1 Run everything (longest, covers everything)

```bash
bbflow hunt example.com
```

### 3.2 Pick by category (common combos)

```bash
# WAF-friendly low-noise four-pack (top pick for government sites)
bbflow hunt example.com --only config-leak,weak-login,backup-files,devops-unauth

# SPA frontend leaks (JS bundle / source map / window.envData)
bbflow hunt example.com --only envdata,sourcemap,js-secrets

# Google API key validation (requires a key found by another hunter first)
"$TOOLS_ROOT/hunters/hunt-google-api-key.sh" AIzaSy...XXX

# Full URL discovery + DAST
bbflow hunt example.com --only crawl-chain
DEPTH=5 bbflow hunt example.com --only crawl-chain  # deeper crawl

# Pure nuclei template scan
bbflow hunt example.com --only nuclei,nuclei-secrets,nuclei-panels,nuclei-wp
```

### 3.3 Hunter overview (26 total)

| Category | Hunter | Main Findings | ROI |
|------|--------|---------|-----|
| **Config / Info leak** | config-leak | .git/.env/actuator/swagger/WEB-INF | ⭐⭐⭐⭐⭐ |
| | backup-files | .zip/.sql/.tar.gz/Index-of | ⭐⭐⭐⭐ |
| | git-exposure | .git/config + credentials in history | ⭐⭐⭐⭐ |
| | envdata | window.envData AWS/Google key | ⭐⭐⭐⭐ |
| | sourcemap | .js.map sourcesContent | ⭐⭐⭐ |
| | js-secrets | hardcoded clientSecret/Bearer | ⭐⭐⭐ |
| | trufflehog | 100+ detectors over git history | ⭐⭐⭐ |
| **Authentication** | weak-login | vendor default creds | ⭐⭐⭐⭐⭐ |
| | userenum | validate_email differential | ⭐⭐ |
| | jwt | alg:none / weak HS256 | ⭐⭐⭐ |
| **DevOps / Infra** | devops-unauth | Harbor/ArgoCD/Jenkins with no auth | ⭐⭐⭐⭐ |
| | actuator-deep | /env /heapdump /jolokia | ⭐⭐⭐⭐ |
| | portscan | rustscan → nmap service | ⭐⭐ |
| **Auth Flow** | cors | 4-layer reflection + credentials | ⭐⭐⭐ |
| | graphql | introspection + IDOR | ⭐⭐⭐ |
| | open-redirect | redirect param + bypass variants | ⭐⭐ |
| | mcp-oauth | MCP OAuth scope discrepancies | ⭐⭐⭐ |
| | hybris-occ | SAP Hybris default OAuth | ⭐⭐⭐ |
| **Takeover** | takeover | CNAME → vendor fingerprint | ⭐⭐⭐ |
| | nxdomain | historical hostname superset | ⭐⭐ |
| **Google** | gkey | Maps/Vision/Translate unrestricted | ⭐⭐⭐ |
| **Fuzzing** | crawl-chain | 10-stage full chain | ⭐⭐⭐⭐ |
| | param-fuzz | katana+gau → nuclei DAST | ⭐⭐⭐ |
| | dalfox-xss | deep XSS | ⭐⭐ |
| | arjun-params | hidden param discovery | ⭐⭐ |
| | ffuf-dirs | directory fuzzing | ⭐⭐ |
| | nuclei-wp | Wordfence 1000+ WP CVEs | ⭐⭐ |

## 4. Report — generate a summary report

Hunting automatically produces:
```
workshop/example.com/HUNTERS_REPORT_YYYYMMDD_HHMM.md
```

This report consolidates every hunter's `🔴` hits and lists the corresponding raw output file paths.

Regenerate the report (if cleared or you want a refresh):
```bash
bbflow report example.com
```

## 5. Dedupe — cross-check against already-submitted reports

```bash
bbflow dedupe example.com
```

Compares against:
- `reports/<platform>/submitted/`
- `reports/<platform>/fixed/`
- `$WORKSHOP_ROOT/<target>/submitted/`
- `$WORKSHOP_ROOT/<target>/reports/`

Output:
- `NEW` — new finding (ready to prepare for submission)
- `DUP` — already submitted, don't resubmit

## 6. Status — check target progress

```bash
bbflow list                    # overview of all targets
bbflow status example.com      # details for a single target
bbflow scope example.com       # view SCOPE.md
```

## 7. Full workflow (example)

```bash
# Day 1: recon
bbflow init example.com
vim workshop/example.com/SCOPE.md          # fill in complete scope
bbflow recon example.com                   # 10 min

# Day 2: low-noise scan (for WAF-protected sites)
bbflow hunt example.com --only config-leak,weak-login,backup-files,devops-unauth,git-exposure

# Day 3: frontend leaks + Google key validation
bbflow hunt example.com --only envdata,sourcemap,js-secrets,trufflehog
# If an AIza* key is found, verify it manually
"$TOOLS_ROOT/hunters/hunt-google-api-key.sh" AIzaSy...

# Day 4: full fuzzing chain (requires explicit authorization / VDP permission)
DEPTH=5 bbflow hunt example.com --only crawl-chain

# Day 5: dedupe + review report
bbflow dedupe example.com
cat workshop/example.com/HUNTERS_REPORT_*.md | less

# Day 6: pick NEW findings and write reports
# See 09 - Knowledge Base/Skill - report-writing.md
```

## 8. Common env variables

| Variable | Purpose |
|------|------|
| `BBFLOW_WORKSPACE` | override the workshop/ path, defaults to `$PWD` |
| `GAU_CONFIG` | gau config file, defaults to `$TOOLS_ROOT/configs/gau.toml` |
| `NUCLEI_COMMUNITY` | nuclei templates path, defaults to `~/nuclei-templates` |
| `SECLISTS` | SecLists path (auto-detected) |
| `OSMEDEUS_VPS` | `user@ip` to run recon via VPS |
| `EXISTING_EMAIL` | used by userenum / gkey identity toolkit |
| `DALFOX_BLIND_URL` | dalfox blind XSS callback |
| `DALFOX_COOKIE` / `DALFOX_HEADERS` | authenticated XSS scan |
| `FFUF_COOKIE` / `FFUF_HEADER` | authenticated dir fuzzing |
| `ARJUN_HEADERS` / `ARJUN_COOKIES` | authenticated param discovery |
| `FAST=1` | fast mode for config-leak / crawl-chain / backup-files |
| `SAFE=1` | weak-login only runs vendors that can be judged from a single request |

## 9. Troubleshooting

| Symptom | Fix |
|------|------|
| `bbflow doctor` shows `bbot not found` | `pipx install bbot` or use `--osmedeus` |
| Nuclei templates are stale | `bbflow nuclei-update` |
| `httpx` blocked by WAF | slow down with `-rate-limit 5` or switch to curl/manual |
| `gau` finds nothing | check `~/.gau.toml` or `echo $GAU_CONFIG` |
| `arjun` too slow | switch to `--passive` or only run against the crawl-chain top-20 endpoints |
| Scan produces lots of false positives | every hunter supports `SAFE=1` / `FAST=1` — filter with those first |

## Related Documents

- [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md) — how to work around a WAF
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md) — government site low-hanging fruit
- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md) — what to do when nuclei finds nothing
- [40-checklist-new-target.md](40-checklist-new-target.md) — 24h checklist for a new target
