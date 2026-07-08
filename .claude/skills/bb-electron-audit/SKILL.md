---
name: bb-electron-audit
description: Use when auditing an Electron / desktop app statically — asar extraction, shell.openExternal, preload / contextBridge, contextIsolation, custom scheme handler, IPC senderFrame. This is the ELECTRON-SPECIFIC audit PROCEDURE (10-min grading → 3-tier defense classification → delivery-chain gate), distinct from generic bb-exploit-chain / bb-attack-chain-review. Triggers: Electron / asar / shell.openExternal / preload / contextIsolation / desktop app static audit.
---

# Bug Bounty — Electron Static Audit (desktop-app-specific procedure)

The **single entry point** for Electron audit methodology: a repeatable, gated procedure that takes one Electron app from unpacking to a reportable finding. This is **not** the generic chaining skill — use `bb-exploit-chain` (the 6-question gate) / `bb-attack-chain-review` for cross-system chaining. This skill only owns the mechanical flow of "one Electron app, from unpack to report-ready verdict."

**Core principle: a sink existing is not the same as it being exploitable.** Every finding must trace the full delivery chain of an attacker-controlled URL from the attacker's hand to the sink; a filter at any intermediate layer kills it.

## When to trigger

- You have a `.app` / installer / `app.asar` / desktop IM / Slack-like client to audit statically
- A grep hits `shell.openExternal` / `contextBridge` / `protocol.handle` / `ipcMain`
- "Audit this Electron app", "extract the asar", "does this desktop app have RCE?"

## Lifecycle position (run the upstream gates first)

```
bb-version-cve-precheck  (the Electron framework CVE and the bundled Chromium CVE are
                          two separate version windows — check both, they diverge)
        ▼
bb-surface-mapping       (vuln-agnostic mapping; a desktop app's surface = IPC channels
                          + scheme handlers + the BrowserWindow inventory)
        ▼
[THIS skill: per-app static audit procedure]   ← starts at asar extraction
        ▼
Delivery Chain Gate (3 layers) → bb-evidence-readiness → bb-attack-chain-review → Finding
```

## Step 0 — Confirm it's Electron + unpack (≤2 min)

`app.asar` present, `package.json` lists electron, a bundled Chromium is present (`locales/`, `LICENSE.electron.txt`), binary ~100-200 MB. If none of these hold → not Electron → stop.

```bash
npx asar extract app.asar /tmp/<app>_extracted   # encrypted asar can't be extracted → stop the static path
```

Before deep analysis, confirm the version's known CVEs/advisories are not already patched for the sink you're about to chase (this is what `bb-version-cve-precheck` is for).

## Step 1 — 10-minute asar triage (decide whether it's worth going deep)

**This is a STOP gate.** Goal: ≤10 min/app to decide "go deep vs skip", so the budget goes to apps that actually have material. Run the **full** grep dictionary below — an API rename will make a stale grep miss everything, so run every line:

```bash
APP=/tmp/<app>_extracted
grep -rn "openExternal\|shell\.openPath\|shell\.showItemInFolder" "$APP" --include="*.js"           # primary sink
grep -rn "protocol\.handle\|registerFileProtocol\|registerStreamProtocol\|registerStringProtocol\|interceptFileProtocol\|setAsDefaultProtocolClient\|registerSchemesAsPrivileged" "$APP" --include="*.js"  # custom scheme entry (old + new API)
grep -rn "ipcMain\.on\|ipcMain\.handle" "$APP" --include="*.js"                                       # IPC entry points
grep -rn "event\.senderFrame\|event\.sender\.getURL" "$APP" --include="*.js"                          # origin-validation census
grep -rn "new BrowserWindow\|webPreferences\|contextIsolation\|nodeIntegration\|sandbox\|preload" "$APP" --include="*.js"  # per-window config variance
```

**🛑 Not worth going deep — if any of these hold, record a negative (`bb-attempt-recorder`) and move to the next app:**
1. No `preload.js` **and** `contextIsolation: true` — no attacker-controllable bridge injection point.
2. No `shell.openExternal` **and** no custom scheme handler — no sink. (0 grep hits is a strong signal that this build lacks the pattern — don't force it.)
3. asar encrypted / binary-only, no JS layer — can't audit statically.

## Step 2 — 3-tier defense classification (read the code around each sink, grade it)

This is the discrimination backbone of the whole audit. Read the URL handling around each `shell.openExternal` call site:

| Tier | Signature | Verdict |
|---|---|---|
| **Allowlist (deny-by-default)** | `ALLOWED_PROTOCOLS=["https:","http:","mailto:"]` / `if(!url.startsWith("http"))return` | ✅ **SAFE → SKIP**. The only reliable defense. |
| **Blocklist (deny list)** | `BLOCKED_PROTOCOLS=[...]` | ⚠️ **Find the gap**: walk the dangerous-protocol list against it (`search-ms:`, `smb:`, `ftp:`, `\\UNC` are almost always missed) → a gap = FINDING. |
| **Zero validation** | `url` flows straight into `shell.openExternal(url)` | 🔥 **FINDING**. `nodeIntegration:true` → Critical, `contextIsolation:false` → High modifier. |

**Don't look only at the sink call site** — validation often lives in a wrapper (`openExternalUrl` / `openLink`), or is bypassed by a skip-validation flag some clients ship. An allowlist must also cover **every** call site: popup windows, webviews, `new-window` fallthrough, `setWindowOpenHandler`.

**Sweep the other (non-openExternal) sinks in the same asar in one pass:**
- A custom scheme handler's **case dispatch is a set of injection points, not one** — find one action, enumerate them all.
- An `ipcMain` handler with **no `senderFrame.url` check** means the whole-app attack surface equals its weakest renderer (a systemic origin-trust failure, CWE-346).
- An IPC handler that does `new BrowserWindow` and unconditionally attaches a `preload` with no URL/sender check = 1-click takeover; `sandbox:true` is the only real fix — contextIsolation / webSecurity / setWindowOpenHandler do not save you here.
- A `preload` that **doesn't distinguish origin** means an HTTP/attacker URL also receives the same contextBridge → a 0-click MITM primitive.
- `contextIsolation` is **per-window**: a safe main window does not mean a safe child/secondary window — compare each BrowserWindow's `webPreferences`.

## Step 3 — Delivery Chain Gate (3 layers; all must PASS before opening a Finding)

Once a sink has a hole you **cannot** open a Finding directly. All three layers must PASS; any BLOCK = record a negative:

```
Layer 1 (Input)   Can an attacker inject a non-http scheme URL at some entry?
                  (chat message / IPC / notification / custom-scheme eventData)
Layer 2 (Transit) Does the intermediate layer (server sanitizer / IPC bridge / renderer
                  linkifier) preserve the original scheme unfiltered?  ← the most common
                  false-positive layer
Layer 3 (Sink)    Does the scheme actually reach shell.openExternal with no second filter
                  (scheme allowlist / UNC reject)?
Exploitable = L1 × L2 × L3
```

Known Layer-2 blockers to check for: a chat/server sanitizer that converts a dangerous scheme (e.g. `search-ms:`) into plain text neutralizes the payload — that's a hard BLOCK. Known bypasses: a scheme missing from the blocklist (e.g. `ftp:`), a window `disposition` value that routes around a `will-navigate` handler, a skip-validation flag, a missing `senderFrame` check.

## Batch audit — one pattern across all apps (highest ROI)

With multiple Electron targets, **do not** deep-dive one at a time. Batch it:

1. Run Step 0 → 1 → 2 (extract → grep dictionary → 3-tier grading) on each app, **10-20 min/app**.
2. Only apps landing in "zero validation / blocklist with a gap" advance to Step 3 (deep + dynamic verification).
3. Produce reports from one template, swapping app name / version / code path.
4. **Same vendor / shared framework = guilt by association**: if one app's `api/shell.js` has no validation, immediately check the same vendor's other Electron apps sharing that framework. Start at `<asar_extracted>/api/shell.js`. A different architecture (e.g. a Blazor→SignalR→IPC hybrid adds a hop) doesn't mean the bug is absent — the call path is just longer.
5. Check the framework / Chromium / Node dependency CVEs **separately** — an Electron app inherits vulnerabilities from each layer independently.

**DevTools shortcut**: launch the main process with `--inspect` → connect via `chrome://inspect` → call the IPC handler straight from the console to verify Layer 3, without installing the full app.

## Framing (anti-exaggeration before submitting — mandatory)

- ✅ `shell.openExternal(UNC)` confirmed live → "1-click NTLMv2 theft + 1-click RCE via UNC path, requires a Windows security dialog (UI:R)".
- ❌ Do not write "0-click RCE" / bare "Remote Code Execution" / "full system takeover".
- On a fully-patched Windows 11, a 0-dialog `.exe` execution has **not** been demonstrated; `search-ms:` + SMB is the 0-dialog primitive (NTLM capture only, not code exec).
- CVSS 9.6 Critical is still reachable even with UI:R — honest framing does not cost you the score.

## Grading & handoff

3 layers all PASS → `bb-evidence-readiness` (Grade A dynamic / Grade B static; a `verified_evidence: static` write-up is acceptable for advisory-style submission, but a P1 to a bounty platform should be dynamically confirmed first) → `bb-attack-chain-review` (scheme-XSS → IPC openWindow → UNC is a multi-hop chain) → Finding → Submission.

Any layer BLOCK / Step 1 kill → `bb-attempt-recorder` (record the negative). A new blocker / bypass / dangerous protocol → `bb-knowledge-capture` (promote it as a reusable lesson).

## Cross-references

- `bb-version-cve-precheck` (upstream gate — check the Electron **and** Chromium version windows separately)
- `bb-surface-mapping` (the desktop app's surface = IPC channels + scheme handlers + BrowserWindow inventory)
- `bb-exploit-chain` / `bb-attack-chain-review` (generic chaining — this skill is Electron-specific and does not replace them)
- `bb-evidence-readiness` / `bb-submission-readiness` (before writing the Finding/Submission)
- `bb-dedup-finding` (same vendor / shared framework across apps = one root cause, dedup accordingly)
- `09 - Knowledge Base/Reference Card - External Skills Catalog.md` (dynamic-testing / mobile skills for hand-off)
