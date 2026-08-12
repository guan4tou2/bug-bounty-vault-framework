---
type: pattern
title: Pattern - Electron Custom Scheme Handler Injection
tags: [pattern, cwe-79, cwe-88, cwe-20, electron, protocol-handler, scheme-xss, ipc-trust, bb-pattern]
status: verified
vuln_class: rce
severity_range: P1-P2
seen_in: []
last_updated: 2026-04-25
precedents: CVE-2018-1000136 (Electron contextIsolation default), CVE-2020-15174 (Electron IPC), CVE-2023-29059 (3CX)
---

# Pattern - Electron Custom Scheme Handler Injection

## TL;DR

Electron apps commonly register a custom URL scheme via `app.setAsDefaultProtocolClient("yourproto", ...)` and dispatch incoming URIs through `app.on("second-instance")` / `app.on("open-url")` to a case-switch handler (commonly named something like `handleProtocol()` or `onSchemeRequest()`, sometimes minified to a short internal name).

**The trap**: developers usually only add protection to the "obviously dangerous" case (e.g. raw `executeJavaScript(eventData)`), while other cases build a JS string via concatenation and pass it to `executeJavaScript(...)` — **every case is an independent injection point**.

## Root-cause ingredients

### Ingredient 1 — scheme registration + dispatcher

```javascript
app.setAsDefaultProtocolClient("acmeapp");

app.on("second-instance", (event, argv) => {
  const url = argv.find(a => a.startsWith("acmeapp://"));
  if (!url) return;
  dispatch(url);
});

function dispatch(url) {
  const u = new URL(url);
  const action = u.searchParams.get("action");
  handleProtocol(action, u.searchParams);   // case dispatch
}
```

### Ingredient 2 — case-switch with mixed sinks

```javascript
function handleProtocol(action, params) {
  switch (action) {
    case "answerCall":
    case "hangupCall":
      // 1. RAW EXECUTION — the case developers are most likely to notice
      mainWindow.webContents.executeJavaScript(params.get("eventData"));
      break;

    case "initMessageList":
      // 2. STRING CONCAT — looks "safe" but channelType is unquoted and id's
      //    single-quote escaping is insufficient
      const ct = params.get("channelType");
      const id = params.get("id");
      mainWindow.webContents.executeJavaScript(
        `messengerMain.initMessageList(${ct},'${id}','${id}')`
      );
      break;

    case "executeDesktopJsEvent":
      // 3. TEMPLATE LITERAL — URL parameter embedded directly in a template string
      const ed = params.get("eventData");
      mainWindow.webContents.executeJavaScript(
        `desktopNotifyEventHandler.executeDesktopJsEvent(${ed});`
      );
      break;

    case "openCallLog":
      // SAFE — pure static string, no external input
      mainWindow.webContents.executeJavaScript("openCallLog();");
      break;
  }
}
```

### Ingredient 3 — notification handler is a hidden sink of the same class (macOS)

The `onclick` handler of `new Notification(...)` frequently calls `webContents.executeJavaScript(serverData)` directly. **This path bypasses the protocol handler entirely**:

```javascript
function showIMNotice(noticeJsonStr) {
  const n = JSON.parse(noticeJsonStr);
  const notif = new Notification({ title: n.Title, body: n.Body });
  notif.on("click", () => {
    // Injection point: n.channelType / n.id come from the server, unsanitized
    const s = `messengerMain.openMessage(${n.channelType}, '${n.id}')`;
    mainWindow.webContents.executeJavaScript(s);   // Direct execution on macOS
  });
  notif.show();
}
```

On macOS this path is **more reliable than the protocol handler** (it isn't affected by macOS's scheme-handler security prompt), and can be triggered by any IM notification (vs. the protocol handler, which requires the user to click a link).

## Detection methodology

1. **Find scheme registration**: grep `setAsDefaultProtocolClient`
2. **Find the dispatcher**: grep `second-instance`, `open-url`, `will-navigate`
3. **Trace into the dispatcher function and enumerate every case** — don't stop at the first sink
4. **Inside each case, look for**:
   - `executeJavaScript(<x>)` — direct execution
   - `webContents.send(<x>, ...)` — IPC dispatch
   - JS built via string concatenation (`"...${x}..."`, `"..." + x + "..."`)
   - `JSON.parse` → `eval` / `Function` constructor
5. **Find Notification handlers**: grep `Notification`, `notif.on("click"`, `new Notification`
6. **Annotate every sink**: input source (URL params / server JSON / IPC arg) + sanitization status

## Variants

### Variant A — raw executeJavaScript

Most common and easiest to spot. Developers usually try to block this one, but often fail.

### Variant B — string concat in a JS template

Developers mistakenly assume that "the JS function called via `messengerMain.foo(${x})` will do its own sanitization." **Wrong**: the string concatenation is handed directly to `executeJavaScript`, parsed first by V8 — any closing paren, backtick, or quote can break out.

### Variant C — template literal injection

`` `func(${x})` `` looks more benign than plain concatenation because "a template literal" sounds safer. In reality, `executeJavaScript` sees exactly the same raw JS source string.

### Variant D — notification click → executeJavaScript (important on macOS)

Server-controlled notification JSON injects channelType/id → notification click fires → direct execution in the main-process context, bypassing the protocol handler dialog entirely.

## Real-world examples

| Vendor / App | Variant | Sink | Note |
|--------------|---------|------|------|
| Acme Messenger (Electron desktop IM, case study) | A | `executeJavaScript(eventData)` raw | Live-confirmed 1-click chain |
| Acme Messenger | B | `messengerMain.initMessageList(${ct},'${id}','${id}')` | `channelType` unquoted |
| Acme Messenger | C | `` `desktopNotifyEventHandler.executeDesktopJsEvent(${r});` `` | Template injection |
| Acme Messenger | D | `showIMNotice` macOS notification click → executeJavaScript | Server-controlled, AC:H MITM |
| 3CX (CVE-2023-29059) | — | DLL sideload via signed installer | Scheme handler triggers supply-chain compromise |

## Defense

```javascript
// Vulnerable
case "initMessageList":
  webContents.executeJavaScript(`messengerMain.initMessageList(${ct},'${id}')`);

// Safe
case "initMessageList":
  // 1. Call a pre-registered renderer function via IPC instead of building JS strings
  webContents.send("scheme:initMessageList", { ct, id });
  // 2. Or expose a controlled API to the renderer via ipcRenderer
```

```javascript
// Vulnerable notification handler
notif.on("click", () => {
  webContents.executeJavaScript(`openMessage(${n.channelType}, '${n.id}')`);
});

// Safe
notif.on("click", () => {
  // 1. Validate the server JSON first
  if (typeof n.channelType !== "number") return;
  if (!/^[a-zA-Z0-9_-]+$/.test(n.id)) return;
  // 2. Use IPC, not executeJavaScript
  webContents.send("notif:openMessage", { ct: n.channelType, id: n.id });
});
```

## Filing & severity

- **A single-case injection** = CWE-88 (Improper Neutralization of Argument Delimiters) + CWE-79 (Cross-site Scripting in a privileged context)
- **Standalone CVSS**: typically 6.0–7.5 (requires 1-click opening of the scheme)
- **Chained with preload exposure** (an unvalidated `openWindow`-style IPC handler) → 1-click desktop takeover → 8.5–9.6
- **Chained with `shell.openExternal(UNC)`** → 1-click UI:R RCE → 9.6
- **macOS notification path (Variant D)** + AC:H MITM → 8.0–8.5 (lower barrier than the protocol-handler dialog)

## Chains

- Custom scheme injection → preload exposure → `openWindow(attackerURL)` → contextBridge takeover: see [[Pattern - Electron Preload Injection Chain]]
- Custom scheme injection → `shell.openExternal(UNC)` → Windows RCE + NTLM theft: see [[Pattern - Electron Preload Injection Chain]] (shell.openExternal UNC RCE section)
- Notification handler injection (macOS path) → executeJavaScript → same downstream chains

## Related

- [[Pattern - Electron Preload Injection Chain]]
- [[Pattern - Electron Preload Origin-Agnostic Injection]]
- [[Pattern - Electron Framework CVE Inheritance]]
