---
type: wiki
category: tool
tool: subfinder,httpx,amass
status: active
last-updated: 2026-04-21
---

# Tool: subfinder + httpx + amass (subdomain enumeration + alive probing)

> **Purpose:** The first step of any BB engagement — find all subdomains + confirm which are alive + fingerprint the tech stack.

## Installation

```bash
# subfinder (passive OSINT)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httpx (HTTP probe)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# amass (deeper, includes active bruteforce)
brew install amass
# or
go install github.com/owasp-amass/amass/v4/...@master
```

## subfinder — passive subdomain enumeration

```bash
# Simplest
subfinder -d target.com -silent

# Feed a list
subfinder -dL domains.txt -silent -o subs.txt

# Recursive (subdomains of subdomains)
subfinder -d target.com -recursive -silent

# All sources
subfinder -d target.com -all -silent

# Only specific sources (ones with API keys)
subfinder -d target.com -sources censys,shodan,virustotal -silent
```

### API key setup

```bash
# Add API keys to ~/.config/subfinder/provider-config.yaml
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/provider-config.yaml <<EOF
censys:
  - abc123:xyz789
shodan:
  - your_api_key
virustotal:
  - your_api_key
securitytrails:
  - your_api_key
github:
  - your_pat_token
chaos:
  - your_chaos_key
EOF
```

**Recommended free APIs:**
- **Chaos** (projectdiscovery): https://chaos.projectdiscovery.io
- **Censys** (research tier): https://search.censys.io
- **Shodan** (education tier): $5/lifetime
- **SecurityTrails**: 50 queries/month free
- **VirusTotal**: free

## httpx — alive probing + tech fingerprinting

```bash
# Basic alive check
subfinder -d target.com -silent | httpx -silent

# With status code + title + tech
subfinder -d target.com -silent | \
  httpx -silent -status-code -title -tech-detect -web-server

# Output format:
# https://api.target.com [200] [OK] [Cloudflare] [Nginx] [React]

# Read from a list
httpx -l subs.txt -silent -status-code -title -tech-detect > alive.txt

# Only keep specific statuses
httpx -l subs.txt -silent -mc 200,301,302,401,403

# Exclude a status
httpx -l subs.txt -silent -fc 404

# With screenshots (requires headless Chrome)
httpx -l subs.txt -silent -screenshot -srd screenshots/

# JSON output
httpx -l subs.txt -silent -json > alive.jsonl
```

### Must-Know Flags

| Flag | Purpose |
|------|------|
| `-status-code` `-sc` | Return HTTP code |
| `-title` | Capture HTML title |
| `-tech-detect` `-td` | Wappalyzer fingerprinting |
| `-web-server` `-server` | Server header |
| `-content-length` `-cl` | Content-Length |
| `-location` | Redirect location |
| `-response-time` `-rt` | Response time |
| `-mc 200,301` | Match code |
| `-fc 404,403` | Filter code |
| `-ml 500` | Match content length min |
| `-ms "keyword"` | Match string in response |
| `-fs "keyword"` | Filter string |
| `-o file.txt` | Output |
| `-json` | JSON output |
| `-screenshot` | Capture screenshot |
| `-follow-redirects` `-fr` | Follow redirects |
| `-threads 50` `-t 50` | Concurrency |
| `-rl 150` | Rate limit |
| `-timeout 10` | Per-request timeout |
| `-H "Header: value"` | Add header |
| `-ports 80,443,8080,8443,8888` | Scan multiple ports |

## amass — active + passive (deeper)

```bash
# Passive mode (similar to subfinder)
amass enum -passive -d target.com -silent > subs.txt

# Active mode (runs DNS bruteforce)
amass enum -active -d target.com -silent

# Deepest mode (combines passive + DNS + cert)
amass enum -active -brute -d target.com -silent

# Bruteforce with a custom wordlist
amass enum -active -brute -w /path/wordlist.txt -d target.com

# Continuous scan (records historical changes)
amass intel -addr 1.2.3.0/24
```

## Standard Workflow (what bbflow recon does)

```bash
# 1. Passive collection
(
  subfinder -d target.com -silent
  amass enum -passive -d target.com -silent
  curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | tr -d '"' | sort -u
  curl -s "https://chaos.projectdiscovery.io/api/v1/dns/target.com/subdomains" \
    -H "Authorization: $CHAOS_KEY" | jq -r '.subdomains[]' | sed "s/$/.target.com/"
) | sort -u > subs.txt

# 2. Alive probing
httpx -l subs.txt -silent -sc -title -td -server -o alive.txt

# 3. Classification
# Split into prod / staging / dev / test based on title / tech stack
grep -iE "staging|stg|dev|test|uat|beta|demo" alive.txt > non_prod.txt
grep -viE "staging|stg|dev|test|uat|beta|demo" alive.txt > prod.txt
```

## Advanced Techniques

### 1. Find a specific vendor's subdomains

```bash
# All SSL certs that contain "target"
curl -s "https://crt.sh/?q=target.com&output=json" | \
  jq -r '.[].common_name' | sort -u

# Use Shodan to find via cert
shodan search 'ssl.cert.subject.cn:"target.com"'
```

### 2. Find origin IPs (bypassing CDN)

```bash
# Check subdomains' A records → ones not pointing to a CDN are candidate origins
for sub in $(cat subs.txt); do
  ip=$(dig +short "$sub" | head -1)
  if [[ ! "$ip" =~ ^(104\.|172\.|173\.|198\.)  ]]; then
    echo "$sub → $ip (candidate origin)"
  fi
done
```

### 3. Port scanning (non-standard ports)

```bash
# Use httpx to scan multiple ports
httpx -l subs.txt -ports 80,443,8080,8443,8888,7001,9000,9090 -silent -sc

# More aggressive: rustscan
rustscan -a target.com --ulimit 5000 -- -sV
```

### 4. Detecting a WAF

```bash
httpx -l alive.txt -silent -td -server -H "X-Forwarded-For: 127.0.0.1" | \
  grep -iE "cloudflare|akamai|imperva|sucuri|safeline"
```

## bbflow Integration

```bash
# bbflow recon is essentially running subfinder + amass + crt.sh + httpx
bbflow recon target

# Output: workshop/target/recon/
# - subs.txt
# - alive.txt (includes tech stack)
# - non_prod.txt
```

## Notes

### Chaos requires a free API key registration

```bash
# https://chaos.projectdiscovery.io
export CHAOS_KEY="your_key"
```

bbflow will use it automatically.

### amass -brute sends a lot of DNS queries

- Fine for small targets
- For large targets, use a custom shorter wordlist with `-w`

### httpx does not follow redirects by default

- Add `-fr` to follow them
- But following redirects multiplies the request volume

## Related Files

- [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md) § Strategy 3: Finding non-prod
- [14-waf-bypass-commands.md](14-waf-bypass-commands.md)
- [00-bbflow-complete-flow.md](00-bbflow-complete-flow.md) § recon
