---
type: reference
category: playbook
tags: [playbook, recon, enumeration]
added: 2026-01-01
---

# Playbook — Recon

> External recon is about maximizing attack surface visibility before any interaction — stay passive, stay in scope, stay disciplined.

---

## Core Concepts

**Scope first, always.** Before any tool runs, verify which domains, IP ranges, and asset types the program explicitly permits. Out-of-scope actions can invalidate valid findings and get your account banned.

**GET-first principle.** During recon you should never trigger writes, account changes, or resource-intensive operations. All steps below are passive or read-only.

**Depth over breadth.** A thorough map of one subdomain beats shallow coverage of a hundred. Once the attack surface is charted, focus hunter energy on the highest-signal targets.

**Log as you go.** Every host, endpoint, and technology fingerprint belongs in `RECON_DB.md` the moment it is discovered. Undocumented findings are lost findings.

---

## Steps

1. **Scope confirmation**
   - Read the program's scope definition in full. Extract all in-scope domains, IP CIDRs, and excluded paths.
   - Create a scope allowlist file before running any tool:
     ```
     example.com
     *.example.com
     api.example.com
     ```
   - Note any wildcard exclusions (e.g., `*.corp.example.com` may be explicitly out-of-scope even under a wildcard allow).

2. **Subdomain enumeration**
   - Passive DNS resolution via certificate transparency logs:
     ```bash
     curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u
     ```
   - Active enumeration with subfinder (passive sources only):
     ```bash
     subfinder -d example.com -silent -o subs_raw.txt
     ```
   - Amass in passive mode:
     ```bash
     amass enum -passive -d example.com -o subs_amass.txt
     ```
   - Merge and deduplicate:
     ```bash
     sort -u subs_raw.txt subs_amass.txt > subs_all.txt
     ```

3. **Live host detection**
   - Probe HTTP/HTTPS with httpx to filter dead hosts:
     ```bash
     httpx -l subs_all.txt -silent -status-code -title -tech-detect -o live_hosts.txt
     ```
   - Resolve DNS for all subdomains to catch dangling CNAME candidates:
     ```bash
     dnsx -l subs_all.txt -silent -resp -o dns_resolved.txt
     ```

4. **Port and service scan**
   - Limit port scanning to explicitly in-scope IPs. Use a conservative rate to avoid unintended impact:
     ```bash
     nmap -sV -p 80,443,8080,8443,8888,3000,4443 --open -iL in_scope_ips.txt -oN portscan.txt
     ```
   - For web-only targets, restrict to standard HTTP ports to minimize noise.

5. **Content discovery**
   - Directory and path fuzzing with ffuf (scope-confirmed hosts only):
     ```bash
     ffuf -u https://example.com/FUZZ -w /path/to/wordlist.txt -mc 200,301,302,403 -o ffuf_results.json -of json
     ```
   - Crawl with katana to find linked endpoints:
     ```bash
     katana -u https://example.com -silent -depth 3 -o katana_urls.txt
     ```
   - Combine and deduplicate discovered paths before deeper inspection.

6. **JavaScript analysis for endpoints and secrets**
   - Download all JS bundles linked from the target:
     ```bash
     katana -u https://example.com -jc -silent | grep '\.js$' | sort -u > js_files.txt
     ```
   - Extract potential API endpoints and tokens with grep patterns:
     ```bash
     # API paths
     grep -hoE '"/[a-zA-Z0-9_/-]{3,50}"' js_files_combined.txt | sort -u
     # Secrets / keys (adjust pattern to target)
     grep -hoiE '(api[_-]?key|secret|token|password)["\s:=]+[A-Za-z0-9+/]{16,}' js_files_combined.txt
     ```
   - Use `trufflehog filesystem` or `gitleaks` on downloaded JS for secret patterns.

7. **Fingerprinting the tech stack**
   - httpx output from step 3 already includes Wappalyzer-style detection. Review the `tech` column.
   - Supplement with `whatweb` for server-side headers:
     ```bash
     whatweb -a 1 https://example.com
     ```
   - Check response headers manually for `X-Powered-By`, `Server`, `X-Generator`, and cookie names that reveal frameworks (e.g., `PHPSESSID`, `JSESSIONID`, `laravel_session`).
   - Cross-reference detected versions against public CVE/advisory databases before investing analysis time.

---

## Tools

| Tool | Purpose |
|------|---------|
| subfinder | Passive subdomain enumeration via public sources |
| amass | Subdomain enumeration with graph-based analysis |
| httpx | HTTP probing, status codes, tech fingerprinting |
| dnsx | Fast DNS resolution and CNAME chain walking |
| ffuf | Directory and endpoint fuzzing |
| katana | Web crawler for linked URLs and JS bundle discovery |
| nmap | Port and service version scanning |
| trufflehog | Secret scanning in JS / source files |
| gitleaks | Pattern-based secret detection |
| whatweb | Server-side technology fingerprinting via HTTP headers |
| jq | JSON parsing for crt.sh and API responses |

---

## Output → Vault

All recon output feeds two canonical documents:

**`RECON_DB.md`** (per-target, lives in `workspace/workshop/<target>/`)
- Add every discovered subdomain under `## Attack Surface`.
- Record each live host with status code, title, and detected tech.
- Log all non-trivial commands under `## Operation Log` with timestamp and result.
- Flag dangling CNAMEs, exposed admin panels, and version-disclosing headers as high-signal rows.

**Attack Surface table** (summary view, referenced in the target's main workspace file)
- Columns: `Host | Port | Tech Stack | Notable Paths | Status | Priority`
- Keep this table short — only hosts worth investigating further.
- Mark out-of-scope rows explicitly rather than deleting them, so future sessions don't re-scan them.

**Hand-off discipline:** Before closing a recon session, run:
```bash
bash automation/session_end_checklist.sh <target>
```
This verifies RECON_DB is updated and no uncommitted findings are pending.

---

## Related

- [[Checklist - Pre-Submission Validation]]
- [[Pattern - IDOR]]
- [[Lessons Learned]]
