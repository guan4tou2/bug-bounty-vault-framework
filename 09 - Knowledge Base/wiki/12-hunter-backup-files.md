---
type: wiki
category: hunter
hunter: backup-files
status: active
last-updated: 2026-04-21
---

# Hunter: `backup-files`

> **Purpose:** For sites behind a WAF, low-noise detection of **backup files, database dumps, and archives** in the site root / subdirectories.
> **How it works:** 41 static candidates + hostname-derived dynamic candidates (e.g. `target.zip`, `target.tar.gz`), each verified with just 1 HEAD + a partial GET checking magic bytes.

## Why it's worth using

- One of the most common P2-P3 quick wins on government/legacy systems (`backup.zip`, `db.sql`, `www.tar.gz`)
- **HEAD first**: in most cases HEAD confirms size + content-type first, without an actual download
- **Magic byte verification**: an HTTP 200 alone doesn't count — it actually pulls the first 8 bytes and compares against ZIP / gzip / SQLite / tar signatures
- **Directory listing** detection included (`/backup/`, `/uploads/` with `Index of` enabled)

## Usage

```bash
# Basic
tools/hunters/hunt-backup-files.sh https://target.gov.tw

# With candidate keywords (recommended: pass the target's English name + abbreviation / agency English acronym)
tools/hunters/hunt-backup-files.sh https://target.gov.tw TargetName abbr

# Via bbflow
bbflow hunt target --only backup-files
```

### Output

```
./backup_files_out/https_target.gov.tw.txt
```

```
[12:34:56] === Backup files hunt: https://target.gov.tw ===
🔴 [P1-CRIT] /backup.zip [200] size=348291842 type=application/zip magic=PK\x03\x04
🔴 [P1-CRIT] /db.sql [200] size=128492 magic=SQL dump
🟠 [P2-HIGH] /www.tar.gz [200] size=84728341 magic=1f8b
🟡 [P3-MED]  /backup/ [200] Index-of directory listing
```

## Candidate list coverage

### Archives (sorted by hit rate)

| Filename | Notes |
|------|------|
| `/backup.zip` `/backup.tar.gz` `/backup.tar` `/backup.rar` `/backup.7z` | Most common hits |
| `/www.zip` `/www.tar.gz` `/www.rar` `/www.7z` | Common on Apache |
| `/web.zip` `/wwwroot.zip` `/website.zip` `/site.zip` | IIS / mixed stacks |
| `/admin.zip` `/src.zip` `/app.zip` `/code.zip` | |
| `/bak.zip` `/bak.tar.gz` `/old.zip` `/oldsite.zip` | |
| `/{hostname}.zip` `/{hostname}.tar.gz` | dynamically derived |
| `/{domain-no-tld}.zip` | e.g. `target` without `.gov.tw` |
| `/{abbr}.zip` | custom parameter |

### Database dumps

```
/db.sql, /dump.sql, /database.sql, /data.sql
/mysql.sql, /backup.sql, /old.sql
/db.zip, /db.tar.gz, /dump.zip, /database.zip
/sql.sql, /sql.zip
```

### Single-file backups (still kept under FAST=1 for high-confidence ones)

```
/config.php.bak       /config.php.old       /config.php~
/database.php.bak     /settings.py.bak
/.env.bak             /.env.backup
/web.config.bak       /wp-config.php.bak    /wp-config.php.old
/index.php.bak        /index.html.bak
```

### Directory listing checks

```
/backup/  /backups/  /bak/  /db/  /dbs/
/upload/  /uploads/  /files/  /download/  /downloads/
/old/  /temp/  /tmp/  /archive/  /archives/  /log/  /logs/
```

## Verification logic (the core of this hunter)

The internal flow of `check()`:

```bash
# 1. HEAD first to check Content-Type / Content-Length
HEADERS=$(curl -sIk --max-time 6 "$HOST/$PATH")

# 2. If 200 and Content-Length > 1024 → range GET the first 8 bytes
MAGIC=$(curl -sk --max-time 6 -r 0-7 "$HOST/$PATH" | xxd -p)

# 3. Compare magic bytes
case "$MAGIC" in
  504b0304*)         echo "ZIP archive" ;;
  1f8b08*)           echo "gzip" ;;
  377abcaf*)         echo "7z" ;;
  526172211a*)       echo "RAR" ;;
  53514c697465*)     echo "SQLite" ;;
  2d2d2044756d70*)   echo "SQL dump" ;;
esac
```

> **Key point**: even when HEAD returns 200, many SPAs will return index.html. Magic byte comparison is the only reliable confirmation method.

## Interpreting alongside content-length

| Content-Length | Usually means |
|----------------|--------|
| < 1KB | false positive (SPA returns index.html) |
| 1KB - 10KB | a small config file / empty archive |
| 10KB - 100MB | a real backup |
| > 100MB | a full-site backup (extremely common on government projects) |

> **Download tip**: don't waste bandwidth downloading the entire large file; use `curl -r 0-10485760` to grab the first 10MB to inspect content (`unzip -l`, `tar -tzf`).

## Government-project candidate wordlist

In `tools/payloads/gov-backup.txt` (passed via the `-w` parameter):

```
ministry.zip
mof.zip
moea.zip
moj.zip
exam.zip
old-site.zip
archive-2020.zip
archive-2021.zip
archive-2022.zip
data-2024.zip
final.zip
final-backup.zip
release.zip
publish.zip
```

## Extending: add custom candidates

Edit `hunt-backup-files.sh` and add to the `CANDIDATES` array:

```bash
CANDIDATES+=(
  "/your-custom.zip"
  "/project-name.tar.gz"
  "/company-internal.sql"
)
```

## Relationship to other hunters

```
backup-files → finds /backup.zip → extract → git-exposure scans .git/
backup-files → finds /db.sql    → grep -iE "password|secret|token|key"
backup-files → finds /backup/   → enters directory listing → grabs subfiles
config-leak  → finds .env       → backup-files tries .env.bak / .env.backup
```

## Download and analysis flow (after finding backup.zip)

```bash
# 1. Download (use -C to resume if the connection is unstable)
curl -sk -C - -O "https://target.gov.tw/backup.zip"

# 2. Inspect the listing (without extracting)
unzip -l backup.zip | head -50

# 3. Extract only the valuable files
unzip backup.zip -d ./dump "*.env" "*.sql" "wp-config.php" "application.yml"

# 4. grep for sensitive content
grep -rEi "password|secret|api[_-]?key|token|mysql|aws" ./dump/

# 5. If it's a DB dump, quickly check the schema
head -500 ./dump/database.sql | grep -E "CREATE TABLE|INSERT INTO"
```

## Report writing

**Report focus:**
- Attach `curl -sI` output proving the file exists + its size (don't actually fully download it)
- Attach the first few magic bytes in hex (e.g. `50 4b 03 04` for ZIP)
- List the sensitive filenames found after extraction (without disclosing contents)
- For DB dumps, list the table structure (without disclosing data)

Example:

```markdown
## Vulnerability Summary
https://target.gov.tw/backup.zip can be downloaded anonymously; the file is 348MB and contains the full site source code + a DB dump.

## Reproduction Steps
```bash
# 1. HEAD to confirm it's downloadable
curl -sI https://target.gov.tw/backup.zip
# HTTP/1.1 200 OK
# Content-Type: application/zip
# Content-Length: 348291842

# 2. Range GET the first 8 bytes to confirm magic bytes
curl -sk -r 0-7 https://target.gov.tw/backup.zip | xxd
# 00000000: 504b 0304 1400 0000  PK......

# 3. Grab the first 10MB to check the structure
curl -sk -r 0-10485760 -O https://target.gov.tw/backup.zip
unzip -l backup.zip | head -50
# (lists: application.yml / database.sql / src/ / uploads/)
```

## Impact
- Full site source code leaked (src/)
- DB schema leaked (database.sql, first 10MB shows CREATE TABLE for 142 tables)
- May contain hardcoded credentials (application.yml confirmed to contain DB_PASSWORD)

## Severity
P2-HIGH (if DB connectivity is verified → P1-CRIT)
```

## Related documents

- [03-xray-rules-reference.md](03-xray-rules-reference.md) §"Backup / Dump"
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md) §#5
- [10-hunter-config-leak.md](10-hunter-config-leak.md)
- [28-tool-git-dumper.md](28-tool-git-dumper.md)
