---
type: wiki
category: tool
tool: katana
status: active
last-updated: 2026-04-21
source: https://github.com/projectdiscovery/katana
---

# Tool: katana (active crawler)

> **Purpose:** A modern SPA-friendly crawler — it executes JS, extracts endpoints, and pulls params from forms. Deeper than hakrawler, faster than Burp Spider.

## Installation

```bash
# Official binary (recommended)
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Or via pdtm
pdtm -i katana

# Or Homebrew (older)
brew install katana
```

## Basic Usage

```bash
# Crawl a single target with depth=3
katana -u https://target.com -d 3 -silent

# List of alive targets
katana -list alive.txt -silent

# Output to a file
katana -u https://target.com -d 5 -silent -o endpoints.txt
```

## Must-Know Flags

| Flag | Purpose |
|------|------|
| `-d 5` | Crawl depth (5 levels deep) |
| `-jc` | **JavaScript crawling** — extract endpoints from JS (key flag) |
| `-js-crawl` | Same as `-jc` |
| `-headless` | Launch headless Chrome (Chrome must be installed) |
| `-aff` | Automatic form fill |
| `-fx` | Field extraction (also captures form inputs) |
| `-ef woff,css,png,svg,jpg,woff2,jpeg,gif` | Exclude extensions |
| `-em js,json,xml` | Only capture these extensions |
| `-cs "*.target.com"` | Crawl scope (restrict to a domain) |
| `-c 10` | Concurrency |
| `-rl 100` | Rate limit (100 req/s) |
| `-timeout 10` | Per-request timeout |
| `-ct 60` | Total crawl time limit |
| `-silent` | Only output results |
| `-o file.txt` | Output file |
| `-jsonl` | JSON lines format |
| `-kf robotstxt,sitemapxml` | Also fetch known files |

## Recommended Combinations

### General web app

```bash
katana -u https://target.com \
  -d 5 \
  -jc \
  -aff \
  -fx \
  -ef woff,css,png,svg,jpg,woff2,jpeg,gif,tiff,tif \
  -silent -o katana.txt
```

### SPA / JS-heavy site

```bash
katana -u https://target.com \
  -d 5 \
  -jc \
  -headless \
  -xhr \
  -aff \
  -silent -o katana_spa.txt
```

`-xhr` intercepts XHR requests → captures API endpoints.

### Government site (low noise)

```bash
katana -u https://target.gov.tw \
  -d 3 \
  -jc \
  -rl 10 \
  -c 3 \
  -timeout 15 \
  -silent -o katana.txt
```

### Multiple targets + scope restriction

```bash
katana -list subs.txt \
  -cs "*.target.com" \
  -d 3 \
  -jc \
  -silent -o katana_all.txt
```

### With auth token (authenticated state)

```bash
katana -u https://target.com \
  -d 5 -jc \
  -H "Authorization: Bearer xxx" \
  -H "Cookie: session=yyy" \
  -silent -o katana_auth.txt
```

## Combining with Other Tools

### katana → uro → gf

```bash
# 1. Crawl
katana -u https://target.com -d 5 -jc -silent -o katana.txt

# 2. Dedup
cat katana.txt | uro > endpoints.txt

# 3. Classify
gf xss < endpoints.txt > gf_xss.txt
gf sqli < endpoints.txt > gf_sqli.txt
```

### katana → dalfox

```bash
katana -u https://target.com -d 5 -jc -silent | \
  grep "=" | \
  dalfox pipe --silence
```

### katana + gau + waybackurls (full coverage)

```bash
# This is exactly what bbflow's crawl-chain hunter does
(
  katana -u https://target.com -d 5 -jc -silent
  echo target.com | gau --subs
  echo target.com | waybackurls
) | sort -u | uro > endpoints.txt
```

## Output Format

### Default (one URL per line)

```
https://target.com/
https://target.com/api/users
https://target.com/api/users/1
https://target.com/admin?action=list
```

### JSONL (`-jsonl`)

```json
{"timestamp":"...","request":{"method":"GET","endpoint":"https://target/admin"},"response":{"status_code":200}}
```

JSONL output can be filtered with `jq`:

```bash
katana -u https://target.com -jsonl -silent | \
  jq -r 'select(.response.status_code == 200) | .request.endpoint'
```

## bbflow Integration

katana is invoked by `hunt-crawl-chain.sh` in Stage 1:

```bash
tools/hunters/hunt-crawl-chain.sh https://target.com
```

Or via bbflow:

```bash
bbflow hunt target --only crawl-chain
```

Environment variables:

| Variable | Effect |
|------|------|
| `DEPTH` | `katana -d $DEPTH` (default 5) |
| `KATANA_EXTRA_ARGS` | Extra flags (rarely used) |

## Common Issues

### Q: headless mode hangs?
A: Confirm Chrome is installed + `which google-chrome` / `which chromium`. macOS: `brew install chromium`.

### Q: crawl times out midway?
A: Lower `-c` / `-rl` / add `-timeout 15`. Or use `-ct 300` to limit total time.

### Q: can't crawl API endpoints?
A: Add `-jc -headless -xhr`. If the SPA uses GraphQL, look directly for the `/graphql` endpoint.

### Q: crawled URLs outside of scope?
A: Restrict with `-cs "*.target.com"`.

## Performance Tuning

```bash
# High speed (your own machine, useful when CDN/CF is blocking)
katana -u target -d 5 -jc -c 50 -rl 500 -silent

# Low speed (for government / weak servers)
katana -u target -d 3 -jc -c 2 -rl 5 -timeout 20 -silent

# Only capture HTML + JS
katana -u target -d 5 -em html,js -silent
```

## Related Files

- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md)
- [21-tool-gau.md](21-tool-gau.md)
- [23-tool-arjun.md](23-tool-arjun.md)
- [25-tool-dalfox.md](25-tool-dalfox.md)
