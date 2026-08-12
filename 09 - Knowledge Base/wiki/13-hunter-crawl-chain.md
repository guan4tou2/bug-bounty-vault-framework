---
type: wiki
category: hunter
hunter: crawl-chain
status: active
last-updated: 2026-04-21
---

# Hunter: `crawl-chain`

> **Purpose:** Run a full **10-stage information-gathering + passive/active DAST toolchain** against a target, solving the problem where nuclei's default templates miss deep surfaces that "need the right parameters / paths."
> **Pain point it solves:** nuclei's default templates only check known paths; if an endpoint needs a specific query parameter to trigger a vulnerability (e.g. `?file=`, `?redirect=`, `?id=`), the default templates simply miss it.

## Full toolchain flow

```
┌───────────────────────────────────────────────────────────────┐
│ Stage 1 Active crawl      katana  → endpoints from JS / crawl │
│ Stage 2 Historical URLs   gau     → wayback + otx + commoncrawl│
│ Stage 3 More history      waybackurls → legacy endpoints       │
│ Stage 4 Hidden params     paramspider → mine ?param=          │
│ Stage 5 JS crawler        hakrawler → fill in missed endpoints│
│ Stage 6 Dedupe/merge      uro     → URL normalize + dedupe     │
│ Stage 7 Pattern classify  gf      → xss / sqli / ssrf / lfi / ...│
│ Stage 8 Hidden param disc arjun   → params not caught elsewhere│
│ Stage 9 DAST scan         nuclei  → run each gf pattern once   │
│ Stage 10 XSS verification dalfox  → actually try XSS payloads │
└───────────────────────────────────────────────────────────────┘
```

## Usage

```bash
# Full scan (10 stages, 10-30 minutes)
tools/hunters/hunt-crawl-chain.sh https://target.com

# Deep scan (katana depth=8)
DEPTH=8 tools/hunters/hunt-crawl-chain.sh https://target.com

# Fast mode (skip arjun + dalfox, only run through Stage 9)
FAST=1 tools/hunters/hunt-crawl-chain.sh https://target.com

# Via bbflow
bbflow hunt target --only crawl-chain
```

### Output structure

```
./crawl_chain_out/https_target.com/
├── 01_katana.txt           # active crawl endpoints
├── 02_gau.txt              # historical URLs
├── 03_wayback.txt          # wayback backfill
├── 04_paramspider.txt      # ?param= endpoints
├── 05_hakrawler.txt        # JS crawler
├── 06_merged.txt           # uro deduped/merged
├── 07_gf_xss.txt           # suspected XSS
├── 07_gf_sqli.txt          # suspected SQLi
├── 07_gf_ssrf.txt          # suspected SSRF
├── 07_gf_lfi.txt           # suspected LFI
├── 07_gf_ssti.txt          # suspected SSTI
├── 07_gf_redirect.txt      # suspected open redirect
├── 07_gf_idor.txt          # suspected IDOR
├── 08_arjun.txt            # newly discovered hidden params
├── 09_nuclei_xss.txt       # nuclei DAST XSS results
├── 09_nuclei_sqli.txt
├── 09_nuclei_ssrf.txt
├── 09_nuclei_lfi.txt
├── 10_dalfox.txt           # dalfox XSS verification
└── summary.txt             # summary + hit count
```

## Stage-by-stage details

### Stage 1: katana (active crawl)

```bash
katana -u https://target.com \
  -d 5 \
  -jc \
  -aff \
  -fx \
  -ef woff,css,png,svg,jpg,woff2,jpeg,gif,tiff,tif \
  -silent -o 01_katana.txt
```

**Key flags:**
- `-d 5` — depth 5 (crawl 5 levels deep)
- `-jc` — JavaScript crawling (extract endpoints from JS)
- `-aff` — automatic form fill
- `-fx` — field extraction (also captures form inputs)
- `-ef` — exclude extensions

### Stage 2: gau (historical URLs)

```bash
gau --threads 5 --subs target.com > 02_gau.txt
```

**Config:** `tools/configs/gau.toml` already sets providers=wayback,otx,commoncrawl,urlscan

### Stage 3: waybackurls (backfill)

```bash
echo target.com | waybackurls > 03_wayback.txt
```

### Stage 4: paramspider (hidden params)

```bash
paramspider -d target.com -o 04_paramspider.txt
```

Output format: `https://target.com/page.php?id=FUZZ&name=FUZZ`

### Stage 5: hakrawler

```bash
echo https://target.com | hakrawler -d 3 > 05_hakrawler.txt
```

### Stage 6: uro (dedupe/merge)

```bash
cat 01_katana.txt 02_gau.txt 03_wayback.txt 04_paramspider.txt 05_hakrawler.txt \
  | sort -u | uro > 06_merged.txt
```

uro will:
- Remove duplicates that are the same endpoint with different param values
- Exclude static resources

### Stage 7: gf (pattern classification)

```bash
for pattern in xss sqli ssrf lfi ssti redirect idor; do
  gf $pattern < 06_merged.txt > 07_gf_${pattern}.txt
done
```

gf patterns need to be installed first:
```bash
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf-patterns
cp ~/.gf-patterns/*.json ~/.gf/
```

### Stage 8: arjun (hidden parameter discovery)

```bash
# Mine new params for each endpoint
arjun -i 06_merged.txt -oT 08_arjun.txt \
  --passive \
  --include-status 200,301,302,403
```

### Stage 9: nuclei DAST (per-pattern)

```bash
# XSS
nuclei -l 07_gf_xss.txt -tags xss -dast -silent -o 09_nuclei_xss.txt

# SQLi
nuclei -l 07_gf_sqli.txt -tags sqli -dast -silent -o 09_nuclei_sqli.txt

# SSRF
nuclei -l 07_gf_ssrf.txt -tags ssrf -dast -silent -o 09_nuclei_ssrf.txt

# LFI
nuclei -l 07_gf_lfi.txt -tags lfi,file -dast -silent -o 09_nuclei_lfi.txt
```

### Stage 10: dalfox (real XSS verification)

```bash
dalfox file 07_gf_xss.txt \
  --skip-bav \
  --skip-mining-all \
  --silence -o 10_dalfox.txt
```

dalfox actually sends the XSS payload and verifies execution using a headless browser.

## Environment variables

| Variable | Default | Description |
|------|------|------|
| `DEPTH` | 5 | katana crawl depth |
| `FAST` | 0 | 1 = skip arjun + dalfox |
| `THREADS` | 10 | crawler threads |
| `RATE` | 50 | nuclei rate limit |
| `TIMEOUT` | 10 | per-URL timeout |

## Common scenarios

### Scenario A: general government-site scan

```bash
DEPTH=3 FAST=1 bbflow hunt target.gov.tw --only crawl-chain
```

- DEPTH=3 to avoid noise
- FAST=1 skips dalfox (government WAFs tend to block it)

### Scenario B: SPA frontend source map exposure

```bash
# First extract URLs from the source map
bbflow hunt target --only sourcemap

# Then feed the extracted endpoints into nuclei
cat sourcemap_out/endpoints.txt >> crawl_chain_out/https_target.com/06_merged.txt
bbflow hunt target --only crawl-chain --skip-stages 1,2,3,4,5
```

### Scenario C: deep-diving after finding Swagger

```bash
# config-leak found /swagger-ui.html
curl -sk https://target.com/v2/api-docs > swagger.json

# Use katana + swagger to extract endpoints
katana -u https://target.com -swagger swagger.json -silent > endpoints.txt
```

## Notes

### Don't run the full pipeline on small programs

- A full 10-stage run fires ~5,000-20,000 requests
- Could get your IP banned on government projects / small vendors
- Recommend **DEPTH=3 + FAST=1** as the default

### A gf pattern match means "suspicious," not "confirmed"

- URLs in `07_gf_xss.txt` merely have a param like `?q=` / `?search=`
- **To actually confirm XSS you must run Stage 10 dalfox**
- Same for SQLi: gf just finds `?id=` `?user=`; you still need to run sqlmap or test manually

### arjun will dig up a lot of useless params

Filter with:
```bash
# Keep reflected-looking params (potential XSS)
grep -iE "q|search|keyword|callback|redirect|url|file|path" 08_arjun.txt
```

## Related documents

- [20-tool-katana.md](20-tool-katana.md)
- [21-tool-gau.md](21-tool-gau.md)
- [23-tool-arjun.md](23-tool-arjun.md)
- [24-tool-nuclei.md](24-tool-nuclei.md)
- [25-tool-dalfox.md](25-tool-dalfox.md)
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md)
