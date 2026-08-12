---
type: wiki
category: tool
tool: arjun
status: active
last-updated: 2026-04-21
source: https://github.com/s0md3v/Arjun
---

# Tool: arjun (hidden parameter discovery)

> **Purpose:** Discovers **hidden HTTP parameters** on known endpoints (like `?admin=true`, `?debug=1`, `?user_id=`).
> Many vulnerabilities hide in undocumented params — arjun is built to dig these out.

## Installation

```bash
# pip
pip3 install arjun

# Or from GitHub
git clone https://github.com/s0md3v/Arjun
cd Arjun && pip3 install -r requirements.txt
```

## Basic Usage

```bash
# Single endpoint
arjun -u https://target.com/api/user

# URL list
arjun -i urls.txt

# Output
arjun -u https://target.com/api/user -oT arjun.txt      # text
arjun -u https://target.com/api/user -oJ arjun.json     # json
```

## Must-Know Flags

| Flag | Purpose |
|------|------|
| `-u URL` | Single target |
| `-i file.txt` | URL list |
| `-m GET` | HTTP method (`GET`/`POST`/`JSON`/`XML`) |
| `-w wordlist.txt` | Custom parameter dictionary |
| `-t 10` | Concurrency |
| `-d 3` | Delay (seconds) |
| `-T 10` | Timeout |
| `-c 5` | Chunk size (test 5 params at a time) |
| `--headers 'Cookie: sess=xxx'` | Add header |
| `--passive` | Passive mode (extract params from JS/HTML) |
| `--include` | Only keep specific status codes |
| `--exclude` | Exclude status codes |
| `--stable` | Use stable diff (cleaner comparison) |
| `-oT file` | Text output |
| `-oJ file` | JSON output |

## Recommended Combinations

### Deep dive on a single endpoint

```bash
arjun -u "https://target.com/api/user" \
  -m GET \
  -t 25 \
  --stable \
  -oT arjun.txt
```

### Passive mode (no requests sent, extracted from response)

```bash
arjun -u "https://target.com/" --passive -oT arjun_passive.txt
```

### Run against an endpoints list produced by bbflow

```bash
# First use katana + gau to produce endpoints.txt
bbflow hunt target --only crawl-chain

# Dig params on each endpoint (only 200/301/302)
arjun -i crawl_chain_out/target/06_merged.txt \
  --include-status 200,301,302,403 \
  -t 25 \
  -oT arjun.txt
```

### Endpoint with a POST JSON body

```bash
arjun -u "https://target.com/api/login" \
  -m JSON \
  -t 10 \
  -oT arjun_json.txt
```

## Recommended Wordlists

arjun's built-in dictionary has ~25K params, already quite comprehensive. Supplement with:

```bash
# PortSwigger paramalist
wget https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/params.txt
arjun -u target -w params.txt

# SecLists
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt
```

## Common Findings

### Debug / admin parameters

```
arjun finds: ?debug=1, ?admin=true, ?test=1
→ Try sending this param and check the response difference
curl "https://target.com/page?debug=1" → may leak a stack trace
```

### Feature flags

```
?beta=1, ?preview=true, ?experimental=1
→ May enable undisclosed features
```

### Auth bypass

```
?auth=1, ?authenticated=true, ?user_id=1
→ May bypass an auth check
```

### IDOR

```
?user_id=, ?userId=, ?uid=, ?account_id=
→ Swap in another user's ID and check if you can see their data
```

### SSRF / Redirect

```
?url=, ?redirect=, ?target=, ?callback=, ?next=
→ Send http://oast.me and check if a request is made
```

### File / LFI

```
?file=, ?path=, ?name=, ?doc=, ?page=
→ Try ../../../etc/passwd
```

## Post-Processing

### Only keep reflected params (possible XSS)

```bash
# After arjun finds ?q, check whether it's reflected
found_params=$(arjun -u target --passive -oJ /dev/stdout 2>/dev/null | jq -r '.[0].parameters[]' 2>/dev/null)
for p in $found_params; do
  if curl -s "https://target/page?${p}=ARJUN_TEST_$(date +%s)" | grep -q "ARJUN_TEST"; then
    echo "[REFLECTED] $p"
  fi
done
```

### Run DAST (dalfox / nuclei) against discovered params

```bash
# Turn arjun-discovered params into URLs and feed into dalfox
while read -r endpoint params; do
  url="$endpoint?${params// /=test&}=test"
  echo "$url"
done < arjun.txt | dalfox pipe --silence
```

## bbflow Integration

### Via the `hunt-arjun-params` hunter

```bash
bbflow hunt target --only arjun-params
```

### Via Stage 8 of `hunt-crawl-chain`

```bash
bbflow hunt target --only crawl-chain
# Automatically runs arjun against the merged endpoints
```

## Performance Notes

### arjun sends a large volume of requests

- Each endpoint defaults to 25K params / chunks of 300 → roughly 83 requests
- 100 endpoints → 8300 requests
- For WAF-protected targets, recommended:
  - `-d 2` (2 second delay)
  - `-t 5` (lower concurrency)
  - `--include-status 200` (reduce meaningless requests)

### Recommended settings for government sites

```bash
arjun -i endpoints.txt \
  -d 3 \
  -t 3 \
  -T 15 \
  --include-status 200,301,302 \
  -oT arjun.txt
```

## Combining with Other Tools

```
arjun → finds ?redirect=
     → verify with hunt-open-redirect

arjun → finds ?file=
     → hunt-nuclei-deep CATEGORY=lfi

arjun → finds ?user_id=
     → manual IDOR testing
```

## Related Files

- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md) § Stage 8
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) § DAST
- [25-tool-dalfox.md](25-tool-dalfox.md)
