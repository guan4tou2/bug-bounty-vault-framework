---
type: pattern
title: Pattern - Unix Socket Permissions
vuln_class: insecure-file-permissions
tags: [bb-pattern]
status: active
last_updated: 2026-06-03
---

# Pattern: Unix Socket Permissions

> World-accessible Unix domain sockets are an under-checked local attack surface — always enumerate socket permissions, who can connect, and what commands the socket accepts before concluding "local only = low severity."

## Why This Is a Real Vulnerability, Not Noise

A Unix domain socket is not a TCP socket: it has no TLS, no auth header, no firewall. If a socket is created as `srwxrwxrwx` (0777), any low-privilege local process (a browser renderer, a malicious npm package, another account on a shared server) can connect and send commands directly. Severity is determined by what commands the socket accepts — not by "local only."

**Stop-loss judgment**: if the socket requires a specific binary protocol that cannot be reverse-engineered, or the attacker cannot get any meaningful response, downgrade to theoretical. But once the protocol has been reverse-engineered, impact can escalate quickly to High.

---

## Illustrative Case: A Desktop Peripheral Management Agent

**Target**: a consumer peripheral vendor's desktop companion app (macOS + Windows, current release at time of assessment)
**Severity**: High (CVSS 7.8, AV:L/AC:L/PR:L/UI:N)

The vendor's background agent process created a Unix socket:

```
/tmp/<vendor>_agent-{MD5(username)}
```

- **Permissions**: `srwxrwxrwx` (0777) — connectable by any local user
- **Path**: suffixed with MD5(username), which an attacker can compute
- **Protocol**: fully reverse-engineered (JSON over a custom framing layer)
- **Routes**: 300+ IPC routes, including firmware flashing, key remapping, and device unpairing

The equivalent Windows Named Pipe (`\\.\pipe\<vendor>_agent-{MD5(username)}`) had an ACL of **RW Everyone** — the same vulnerability class on the Windows side.

**Race condition (CWE-362)**: on startup, the agent did not check whether the socket already existed (no atomic `unlink` + `bind`). An attacker could kill the agent, pre-create a fake socket at the same path, and the restarted agent would fail to reclaim it — the desktop UI would blindly reconnect to the attacker's socket, producing a full IPC MITM.

---

## Detection Signals

| Signal | Tool | Meaning |
|------|------|------|
| `srwxrwxrwx` or `0777` socket | `ls -la /tmp/*.sock` / `lsof -U` | World-writable — any local process can connect |
| `/tmp/<predictable_name>` socket | `lsof -U \| grep tmp` | Predictable path → possible race condition |
| `srw-rw-rw-` (0666) socket | `ls -la` | World-writable (no exec bit, still connectable) |
| Named pipe ACL `RW Everyone` | `accesschk.exe -w \\\\.\\pipe\\*` | Windows equivalent of the same vulnerability |
| Socket held by a privileged service | `lsof -U \| grep -i root` | If the command set is rich enough, possible LPE |
| Socket path contains a guessable hash | `ls /tmp/` | MD5/CRC/username hash = computable |

---

## Grep / Test Methodology

### Step 1: Enumerate All Unix Sockets

```bash
# macOS — list all UNIX sockets (with owner + path)
lsof -U 2>/dev/null | awk 'NR>1 {print $1, $3, $NF}' | sort -u

# Linux
find /tmp /var/run /run -type s 2>/dev/null | xargs ls -la 2>/dev/null

# More complete (includes /proc)
ss -xl 2>/dev/null | grep -v "^Netid"

# World-writable only
find /tmp /var/run /run -type s -perm /o+w 2>/dev/null
```

### Step 2: Confirm Socket Permissions

```bash
SOCKET_PATH="/tmp/target-app-socket"

# Check perms
ls -la "${SOCKET_PATH}"
# srwxrwxrwx = 0777, world-writable
# srw-rw-rw- = 0666, world-writable (no exec)
# srw-rw---- = 0660, group-writable (check your group membership)
# srw------- = 0600, owner-only (safe)

# Check owner
stat -f "%u %g %p %N" "${SOCKET_PATH}" 2>/dev/null || stat -c "%u %g %a %n" "${SOCKET_PATH}"
```

### Step 3: Test Connection + Initial Probing

```bash
SOCKET_PATH="/tmp/target-app-socket"

# Minimal test: can we connect?
python3 -c "
import socket, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect('${SOCKET_PATH}')
    data = s.recv(256)
    print(f'Connected. Banner ({len(data)} bytes): {data[:64].hex()}')
except Exception as e:
    print(f'Failed: {e}')
finally:
    s.close()
"

# socat interactive test (good for text protocols)
echo -ne '{"action":"list"}\n' | socat - UNIX-CONNECT:"${SOCKET_PATH}"

# socat MITM proxy — intercept app <-> agent traffic
# confirm the target socket path first, then:
socat -v UNIX-LISTEN:"${SOCKET_PATH}.mitm",mode=777,fork UNIX-CONNECT:"${SOCKET_PATH}"
# then point the target app at ${SOCKET_PATH}.mitm
```

### Step 4: Windows Named Pipe Enumeration

```powershell
# List all named pipes
Get-ChildItem \\.\pipe\ | Select-Object Name

# Check ACL (requires Sysinternals accesschk)
accesschk.exe -w \\.\pipe\* 2>$null | Select-String "Everyone|Users|Authenticated"

# PowerShell connection test
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "target-pipe-name", [System.IO.Pipes.PipeDirection]::InOut)
$pipe.Connect(3000)   # 3 sec timeout
$reader = New-Object System.IO.StreamReader($pipe)
Write-Host "Connected. Reading..."
Start-Sleep -Milliseconds 500
$pipe.Close()
```

### Step 5: Race Condition Test

```bash
SOCKET_PATH="/tmp/target-app-socket"

# 1. Check whether the agent unlinks the old socket on startup
# First manually create a fake socket
python3 -c "
import socket, os
fake = '${SOCKET_PATH}'
if os.path.exists(fake): os.unlink(fake)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(fake)
s.listen(1)
os.chmod(fake, 0o777)
print('Fake socket created, waiting...')
conn, addr = s.accept()
print('Connection received from agent or client')
data = conn.recv(256)
print(f'Received: {data.hex()}')
"

# 2. In a separate terminal, restart the target agent
# 3. If the fake socket receives a connection → the agent did not unlink+rebind → race condition confirmed
```

### Step 6: Command Set Discovery (once the protocol is known)

```bash
# If the protocol is JSON, try common command words
for cmd in list info status ping version help routes; do
  echo "=== $cmd ==="
  echo "{\"action\":\"${cmd}\"}" | socat - UNIX-CONNECT:"${SOCKET_PATH}" 2>/dev/null | head -3
done

# If it's HTTP-over-socket (like Docker)
curl --unix-socket "${SOCKET_PATH}" http://localhost/version
curl --unix-socket "${SOCKET_PATH}" http://localhost/containers/json
```

---

## Variants / Chain

### LPE Chain (if the socket belongs to a privileged service)

```
world-writable socket → privileged daemon (e.g. SYSTEM / root) accepts commands
  → commands can trigger file write / exec → LPE
  → in the illustrative case: an updater pipe (RW Everyone, runs as SYSTEM) — protocol not fully reverse-engineered, unconfirmed
```

### IPC MITM Chain (race condition)

```
kill agent → pre-create fake socket → agent restarts (no reclaim)
  → client reconnects to attacker's socket
  → attacker proxies to the real agent (transparent MITM)
  → intercepts all commands + injects malicious SET commands
  → fully verified in the illustrative case
```

### Supply Chain Pre-Positioning

```
world-writable IPC → modify the update-server URL
  + modify the firmware DFU pipeline host
  + trigger an update check
  + if DNS hijack of the vendor's update domain is possible
  → malicious firmware delivery (theoretical, requires DNS hijack)
```

### Key Injection (verified in the illustrative case)

```
world-writable IPC → SET /v2/assignment → arbitrary key remapping
  → e.g. middle-click mapped to Cmd+Q (quit foreground app)
  → succeeds even while the device is marked INACTIVE (pre-set)
  → triggers when the user plugs the device in
```

---

## Three Root-Cause CWEs (reusable template)

| CWE | Description | Example from the illustrative case |
|-----|------|--------------|
| CWE-732 | Incorrect Permission Assignment for Critical Resource | socket 0777 / pipe RW Everyone |
| CWE-330 | Use of Insufficiently Random Values | MD5(username) used as the socket suffix |
| CWE-362 | Concurrent Execution Using Shared Resource Without Proper Locking | agent does not unlink + rebind |

---

## Severity Guide

| Condition | Severity | Note |
|------|----------|------|
| World-writable socket + privileged daemon + effective command set → LPE | P1 Critical | Local privilege escalation |
| World-writable socket + device control / firmware flashing / verified key injection | P2 High | CVSS 7.x, matches the illustrative case |
| World-writable socket + race condition MITM + fully reverse-engineered protocol | P2 High | Strong PoC = high confidence |
| World-writable socket + information disclosure only (user ID / version) | P3 Medium | No modification capability |
| World-writable socket + protocol cannot be reverse-engineered (binary, no response) | P4-P5 Low | Theoretical; must be flagged as unconfirmed |
| Group-writable socket (0660) + attacker is in the group | P2-P3 | Depends on group membership and command set |

**Anti-overclaim reminder**: in the illustrative case, an updater pipe running as SYSTEM accepted a connection but broke the pipe after a write — the protocol was not reverse-engineered, so that branch was labeled "partially confirmed, needs further research" rather than written up as a confirmed LPE.

---

## Remediation Template (ready to paste into a report)

1. Create the socket with owner-only permissions: `chmod 0700` after `bind()`
2. Use a cryptographically random value for the socket name (e.g., `/tmp/<app>-$(openssl rand -hex 16)`)
3. Implement peer authentication using `getpeereid()` (macOS/BSDs) or `SO_PEERCRED` (Linux) to verify only the intended client UID can send commands
4. On startup, atomically `unlink()` and rebind the socket, or fail with an error if a socket already exists at the expected path (preventing race-condition hijacking)
5. Windows: restrict the Named Pipe DACL to specific SIDs (e.g., `NT AUTHORITY\INTERACTIVE` or the specific app user SID) rather than `Everyone`

---

## Cross-Reference

- [[Pattern - Electron Preload Injection Chain]] — related: an Electron UI is often a socket client, so injection there can trigger IPC
- [[Lessons Learned]] — "always check Unix socket permissions"
