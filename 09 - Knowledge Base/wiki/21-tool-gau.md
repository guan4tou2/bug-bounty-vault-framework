---
type: wiki
category: tool
tool: gau
status: active
last-updated: 2026-04-21
source: https://github.com/lc/gau
ref: https://medium.com/@felixmelvinchitechi/gau-for-recon-91f8b331293d
---

# Tool: gau (Get All URLs)

> **Purpose:** Extracts a target's historical URLs from **Wayback Machine / OTX / Common Crawl / URLScan**.
> Great for finding **removed endpoints**, **old parameters**, and **staging subdomains the vendor doesn't know about**.

## Installation

```bash
# Recommended: Go install
go install github.com/lc/gau/v2/cmd/gau@latest

# Homebrew
brew install gau
```

## Config (used by bbflow)

bbflow already has `tools/configs/gau.toml` set up:

```toml
# Concurrency and timeout
threads = 5
timeout = 45
retries = 2
verbose = false

# Subdomains — true will extract *.target.com
subdomains = true

# providers: don't rely on wayback alone, multiple sources give better coverage
providers = ["wayback", "otx", "commoncrawl", "urlscan"]

# Exclude meaningless extensions
blacklist = [
  "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico", "webp",
  "woff", "woff2", "ttf", "eot", "otf",
  "css", "scss",
  "mp3", "mp4", "avi", "mov",
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
]
```

Auto-loaded via: `GAU_CONFIG=$PWD/tools/configs/gau.toml` (bbflow exports this automatically).

## Basic Usage

```bash
# Simplest form
gau target.com

# Feed it a list
cat domains.txt | gau

# Restrict providers
gau --providers wayback,otx target.com

# Exclude extensions
gau --blacklist jpg,png,css target.com

# Extract subdomains too
gau --subs target.com

# Save to file
gau target.com --o gau.txt

# JSON output
gau --json target.com
```

## Must-Know Flags

| Flag | Purpose |
|------|------|
| `--subs` | Extract `*.target.com` |
| `--providers` | `wayback,otx,commoncrawl,urlscan` |
| `--blacklist` | Exclude extensions (comma-separated) |
| `--threads 10` | Concurrency |
| `--timeout 45` | Per-provider timeout |
| `--retries 2` | Retry on failure |
| `--mc 200,301` | Only keep specified HTTP status (requires a separate probe pass) |
| `--fc 404` | Exclude a status (same as above) |
| `--from 202101` | Start from a given month |
| `--to 202412` | End at a given month |
| `--json` | JSON output |
| `--o file.txt` | Output file |

## Recommended Combinations

### Full extraction (bbflow default)

```bash
GAU_CONFIG=$PWD/tools/configs/gau.toml \
  gau --subs target.com > gau.txt
```

### Only the last 2 years (fast)

```bash
gau --from 202301 --subs target.com > gau_recent.txt
```

### Only older data (retroactively find removed endpoints)

```bash
gau --to 202012 --subs target.com > gau_old.txt
```

### Batch over multiple targets

```bash
cat subs.txt | gau --threads 10 --providers wayback,otx > gau_batch.txt
```

## Post-Processing

### Filter URLs with query params (possible vulns)

```bash
gau target.com | grep "?" > params.txt
```

### Dedup + normalize

```bash
gau target.com | uro > endpoints.txt
```

uro will:
- Remove duplicates of the same endpoint with different values
- Remove static assets

### Extract emails / subdomains

```bash
# Extract emails
gau target.com | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+' | sort -u

# Extract subdomains (ones that appear in URLs but subfinder didn't find)
gau --subs target.com | awk -F/ '{print $3}' | sort -u
```

### gf classification

```bash
gau --subs target.com | uro | tee endpoints.txt | \
  gf xss > gf_xss.txt

# Other patterns
for p in xss sqli ssrf lfi redirect idor; do
  gf $p < endpoints.txt > gf_${p}.txt
done
```

### Probe alive status

```bash
gau --subs target.com | httpx -silent -status-code -mc 200,301,302,401 > alive_urls.txt
```

## Common Attack Surface Discoveries

### Discovery 1: Old API endpoints

```bash
gau target.com | grep "/api/v1" > old_api.txt
# v1 may have been replaced by v2 but not yet decommissioned → possibly missing auth checks
```

### Discovery 2: Removed but still-live admin panels

```bash
gau target.com | grep -iE "admin|login|manage|dashboard" | sort -u
# curl -I each one to check if it still returns 200
```

### Discovery 3: Forgotten test endpoints

```bash
gau target.com | grep -iE "test|debug|dev|beta"
```

### Discovery 4: Sensitive paths (past hits)

```bash
gau target.com | grep -iE "\.env|\.git|backup|config|\.sql"
```

## Performance and Limits

### Rate limits

- Wayback Machine: no explicit limit, but excessive use gets you temporarily suspended
- OTX: needs an API key (`export OTX_KEY=xxx`) for high speed
- Common Crawl: slow, but high volume
- URLScan: needs an API key (`export URLSCAN_KEY=xxx`)

### Output volume estimates

| Target type | gau volume |
|-------------|--------|
| Small site | 100-1000 URLs |
| Medium site | 1k-10k URLs |
| Large company | 10k-100k URLs |
| Large government site | 50k-500k URLs |

## bbflow Integration

```bash
# gau is invoked by Stage 2 of crawl-chain
bbflow hunt target --only crawl-chain
```

Standalone (without bbflow):

```bash
GAU_CONFIG=$PWD/tools/configs/gau.toml gau --subs target.com | uro > endpoints.txt
```

## Extension: waybackurls

For cases gau doesn't cover, use waybackurls (the tomnomnom classic):

```bash
go install github.com/tomnomnom/waybackurls@latest

echo target.com | waybackurls > wayback.txt

# Combining both gives the most complete coverage
(gau --subs target.com; echo target.com | waybackurls) | sort -u | uro
```

## Related Files

- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md)
- [20-tool-katana.md](20-tool-katana.md)
- [Reference tutorial (Medium)](https://medium.com/@felixmelvinchitechi/gau-for-recon-91f8b331293d)
