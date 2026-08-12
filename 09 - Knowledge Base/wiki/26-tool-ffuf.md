---
type: wiki
category: tool
tool: ffuf
status: active
last-updated: 2026-04-21
source: https://github.com/ffuf/ffuf
---

# Tool: ffuf (Web fuzzer)

> **Purpose:** Fast fuzzing of **paths / parameter names / parameter values / headers / Host / vhost**.
> Faster than gobuster, more flexible than feroxbuster.

## Installation

```bash
go install github.com/ffuf/ffuf/v2@latest
brew install ffuf
```

## Basic usage

```bash
# Directory fuzz
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Show only 200 / 301 results
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,403

# Parameter fuzz
ffuf -u 'https://target.com/?FUZZ=test' -w params.txt

# Parameter value fuzz
ffuf -u 'https://target.com/?id=FUZZ' -w nums.txt
```

## Essential flags

| Flag | Purpose |
|------|------|
| `-u URL` | URL containing `FUZZ` |
| `-w file` | Wordlist |
| `-w file:KEY` | Multiple wordlists with different keys |
| `-mc 200,301` | Match code |
| `-fc 404` | Filter code |
| `-ml 100` | Match line count (minimum) |
| `-ms 1000` | Match size |
| `-fs 1234` | Filter size |
| `-mr 'regex'` | Match regex |
| `-fr 'regex'` | Filter regex |
| `-ac` | Auto-calibrate (auto-filter SPA false 200s) |
| `-acc 'custom1,custom2'` | Auto-calibrate custom |
| `-t 40` | Threads |
| `-p 2` | Delay (seconds) |
| `-rate 100` | Rate limit (req/s) |
| `-e .php,.bak` | Extension fuzz |
| `-H 'Cookie: xxx'` | Add header |
| `-d 'a=FUZZ'` | POST data |
| `-X POST` | HTTP method |
| `-o out.json -of json` | JSON output |
| `-of html` | HTML output |
| `-replay-proxy http://127.0.0.1:8080` | Send hits to Burp |
| `-mode clusterbomb` | Multi-wordlist cartesian product (slow) |
| `-mode pitchfork` | Multi-wordlist one-to-one pairing |

## Recommended combinations

### Directory fuzz (classic)

```bash
# SecLists classic dictionary
WORDLIST=/usr/share/seclists/Discovery/Web-Content/common.txt

ffuf -u https://target.com/FUZZ \
  -w $WORDLIST \
  -mc 200,301,302,401,403 \
  -fs 0 \
  -ac \
  -t 50 \
  -o ffuf.json -of json
```

### Extension fuzz

```bash
# Try multiple extensions at once
ffuf -u https://target.com/FUZZ \
  -w words.txt \
  -e .php,.bak,.old,.zip,.json,.xml,.txt,.log \
  -mc 200,301 \
  -ac
```

### Subdirectory + extension (common for government targets)

```bash
# Build a dictionary: admin, backup, config, test, ...
cat > gov-paths.txt <<EOF
admin
administrator
backup
config
test
debug
internal
api
phpinfo
info
swagger
actuator
EOF

ffuf -u https://target.gov.tw/FUZZ \
  -w gov-paths.txt \
  -e .php,.aspx,.jsp,.html \
  -mc 200,301,401,403 \
  -ac \
  -t 10 \
  -p 1
```

### Parameter name fuzz (similar to arjun)

```bash
ffuf -u 'https://target.com/api?FUZZ=test' \
  -w params.txt \
  -fr 'Not Found' \
  -mc 200 \
  -mr 'test'
```

### vhost fuzz (find hidden subdomains)

```bash
ffuf -u https://target.com/ \
  -H "Host: FUZZ.target.com" \
  -w subs.txt \
  -fs 1234 \
  -mc 200,301
```

### Multiple wordlists (clusterbomb)

```bash
# Fuzz directory + file simultaneously
ffuf -u https://target.com/W1/W2 \
  -w dirs.txt:W1 \
  -w files.txt:W2 \
  -mc 200 \
  -ac \
  -mode clusterbomb
```

### POST fuzz (login brute force)

```bash
ffuf -u https://target.com/login \
  -X POST \
  -d 'user=admin&pass=FUZZ' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -w passwords.txt \
  -fr 'Invalid credentials' \
  -mc 200,302
```

## Recommended wordlists

| Purpose | Wordlist |
|------|---------|
| General directory | `SecLists/Discovery/Web-Content/common.txt` |
| Large dictionary | `SecLists/Discovery/Web-Content/raft-medium-directories.txt` |
| Hidden files | `SecLists/Discovery/Web-Content/raft-medium-files.txt` |
| API endpoints | `SecLists/Discovery/Web-Content/api/api-endpoints.txt` |
| Parameter names | `SecLists/Discovery/Web-Content/burp-parameter-names.txt` |
| Government sites (custom) | `tools/payloads/gov-paths.txt` (see wiki [02](02-gov-site-quick-wins.md)) |
| Backup filenames | `SecLists/Discovery/Web-Content/BackupFuzzy.fuzz.txt` |

### Quick install SecLists

```bash
# macOS
brew install seclists

# Linux
sudo apt install seclists
# or
git clone https://github.com/danielmiessler/SecLists ~/SecLists
```

## Post-processing

### Filter JSON results

```bash
# Only look at 200s
jq -r '.results[] | select(.status == 200) | .url' ffuf.json

# Find newly discovered interesting endpoints
jq -r '.results[] | select(.status == 200 and .length > 500) | "\(.status) \(.length) \(.url)"' ffuf.json
```

### Follow-up probing after discovery

```bash
# Feed ffuf's discovered endpoints into nuclei
jq -r '.results[].url' ffuf.json | nuclei -l - -silent
```

## WAF-friendly

```bash
# Lower parallelism + add delay
ffuf -u https://target/FUZZ -w words.txt \
  -t 3 \
  -p 2 \
  -rate 10 \
  -H "X-Forwarded-For: 127.0.0.1" \
  -timeout 15
```

## bbflow integration

bbflow has a `hunt-ffuf-dirs` hunter:

```bash
bbflow hunt target --only ffuf-dirs
```

Custom dictionary:

```bash
WORDLIST=/path/to/custom.txt bbflow hunt target --only ffuf-dirs
```

## Alternative tools

| Tool | Advantage | When to use |
|------|------|--------|
| **ffuf** | Most flexible (fuzz anywhere) | General purpose |
| feroxbuster | Good recursion (auto-descends) | Directory discovery |
| gobuster | Simple | Quick directory scan |
| wfuzz | Classic | Legacy workflows |
| dirsearch | Python, clean output | Report writing |

## Related files

- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md) §Government target payload dictionary
- [10-hunter-config-leak.md](10-hunter-config-leak.md) — A lower-noise alternative
