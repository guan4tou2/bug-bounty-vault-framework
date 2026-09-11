---
type: pattern
title: Pattern - Electron contextIsolation Per-Window Variance
tags: [pattern, cwe-693, electron, contextIsolation, browserwindow, meet, jitsi, bb-pattern]
status: verified
first_seen: 2026-05-18
last_updated: 2026-05-18
severity: P2 High (if secondary window loads attacker-controlled content)
precedents: a desktop messenger whose "meet" window used contextIsolation:false while the main window had it ON
---

# Pattern - Electron contextIsolation Per-Window Variance

## TL;DR

An Electron app may have strong security settings on its main BrowserWindow but create **secondary windows** (meet, preview, OAuth, etc.) with weaker settings. If the secondary window loads attacker-influenced content, the missing `contextIsolation` gives renderer JS direct access to Node.js / IPC bridge.

## Root cause

Electron apps create multiple `BrowserWindow` instances. Each has independent `webPreferences`:

```javascript
// Main window — secure
mainWindow = new BrowserWindow({
  webPreferences: {
    contextIsolation: true,    // ON
    sandbox: true,             // ON
    nodeIntegration: false,
    preload: path.join(__dirname, 'preload.js')
  }
});

// Meet/preview window — INSECURE
meetWindow = new BrowserWindow({
  webPreferences: {
    contextIsolation: false,   // OFF — attacker JS can reach preload globals
    sandbox: false,            // OFF
    nodeIntegration: false,
    preload: path.join(__dirname, 'preload.js')  // same preload = same bridge
  }
});
```

The preload script exposes `window.electron` or similar IPC bridge to BOTH windows. But only the Meet window lets arbitrary web content access it.

## Detection

```bash
# In deobfuscated/extracted main.js or ASAR:
grep -n "contextIsolation\|new BrowserWindow\|webPreferences" main.js

# Look for multiple BrowserWindow constructors with DIFFERENT settings
# Common pattern: one has contextIsolation:true, another doesn't set it (defaults vary by Electron version)
```

**Key check:** Does the insecure window load URLs influenced by external input? (Meet links, OAuth callbacks, deep links, preview URLs)

## Exploitation flow

```
Attacker sends Meet/preview URL
  -> Electron opens secondary window (contextIsolation:false)
  -> Window loads attacker-controlled domain (e.g., custom Jitsi server)
  -> Attacker's external_api.js runs in renderer
  -> window.electron (preload bridge) is directly accessible
  -> IPC calls: saveBase64toFile, shell.openExternal, etc.
  -> File write + execution = RCE
```

## Real-world: [Case A] (Messaging App)

- **Main window:** `contextIsolation: true`, `preload` bridge properly isolated
- **Meet window:** `contextIsolation: false`, `sandbox: false` — loads Jitsi Meet URL
- **Attack:** Send victim a Meet invite with attacker-controlled Jitsi server domain
- **Result:** Attacker's JS accesses `window.electron.saveBase64toFile()` -> write payload -> execute -> RCE

## Where to look for secondary windows

| Window type | Why it might be weaker | Example |
|-------------|----------------------|---------|
| Video/Meet | Loads external Jitsi/Zoom SDK with specific requirements | [Case A] Meet window |
| OAuth/SSO popup | Opens external auth URL | Login windows |
| Link preview | Renders external page content | Chat previews |
| File viewer | Opens documents/PDFs | Inline viewers |
| About/Help | May load external changelog/docs | Help windows |

## Severity assessment

| Condition | Severity |
|-----------|----------|
| Secondary window loads attacker-controlled URL + preload bridge exposed | **P1-P2** (RCE chain) |
| Secondary window loads fixed URL but has XSS + preload bridge exposed | **P2** |
| Secondary window lacks contextIsolation but no preload bridge | **P3-P4** (limited impact) |

## Remediation

1. Apply `contextIsolation: true` + `sandbox: true` to ALL BrowserWindow instances
2. Use separate preload scripts: main window gets full bridge, secondary windows get minimal/no bridge
3. Validate URLs before opening in secondary windows (allowlist domains)

## Session-Mined Additions (2026-06-04)

- **PDF viewer webview exception**: Rocket.Chat Desktop's `will-navigate` handler has an exception branch for the PDF viewer webview; navigation in a non-PDF webview can bypass the handler. During an audit you must confirm the `will-navigate` coverage of every webview.

## Session-Mined Additions (2026-08-04)

- **Preload directly loads external script variant** ([Case A] meetPreload.js): the preload parses the domain from the `--meet-url=` argument and directly builds `<script src="https://DOMAIN/external_api.js">`, with **zero allowlist validation**. Attacker controls the domain → the script runs in the parent page context (contextIsolation:false) → full RCE.
  - Note: the script loads in the **parent page** (not an iframe) → it can directly access the preload-exposed `require('electron')` / the app's custom IPC wrapper object (wrapping `ipcRenderer`)
  - More severe than "window.electron bridge is accessible": the attacker's JS is already in the Node.js context when it loads, with no need to bypass contextBridge
  - **Audit keywords**: grep `createElement('script')` / `document.createElement("script")` + confirm whether the src origin is user/attacker-controlled
- **Lesson (see lessons)**: inconsistent identifiers in obfuscated code cause false negatives — deobfuscate before testing, otherwise conclusions are invalid
