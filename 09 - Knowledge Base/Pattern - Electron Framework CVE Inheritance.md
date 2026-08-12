---
type: pattern
title: Pattern - Electron Framework CVE Inheritance (outdated framework + transitive deps)
tags: [pattern, cwe-1104, cwe-428, electron, supply-chain, local-privesc, ipc-spoof, dependency-confusion, bb-pattern]
status: static-confirmed
severity_range: P2 (CVSS 7.3 High, CWE-428 anchor) — aggregate advisory
precedents: Slack/libwebp-2023, Signal-Electron-2022, Discord-Electron-2022
last_updated: 2026-04-25
---

# Pattern - Electron Framework CVE Inheritance

## TL;DR

**Electron framework CVEs and Chromium bundle CVEs are entirely separate attack surfaces. An app can ship the latest Chromium runtime (no browser CVEs) while running on an outdated Electron framework version with 11+ unpatched CVEs in the framework layer itself.**

Most auditors check `navigator.userAgent` for the Chromium version and conclude "browser is current, no CVEs." This misses the framework entirely. You must audit both independently:

1. **Chromium runtime** — via `navigator.userAgent` or the Electron→Chromium version mapping
2. **Electron framework version** — via `process.versions.electron` in DevTools, or `resources/app/package.json`
3. **Transitive npm dependencies** — via `npm ls` inside an unpacked `app.asar` (e.g. `follow-redirects`, `electron-dl`)

**Case study (ACME-007)**: the Chromium 144 runtime was current (zero browser CVEs). The Electron 40.6.1 framework was outdated by 2 minor versions — 11 CVEs published 2026-04-02/03, fixed in 40.8.5.

**Filing strategy**: one aggregate **CWE-1104** advisory anchored on the highest-confidence statically-verified CVE (CVE-2026-34768). Do not file 11 separate reports. Precedent: Slack did not receive per-CVE advisories for libwebp-2023.

## Root-Cause Ingredients

### Ingredient 1 — Electron release cadence vs. Chromium update cycle

Chromium ships every ~4 weeks; Electron tracks Chromium N-1 with a further 1-4 week lag. But Electron framework-layer security fixes (IPC, preload, contextBridge, setLoginItemSettings, nodeIntegration) have their own independent CVE stream. A vendor who auto-updates Chromium (e.g., via Electron's internal auto-update) but pins `"electron": "40.6.1"` in `package.json` can simultaneously have:

- Chromium 144 → latest → zero browser CVEs
- Electron 40.6.1 → two minor versions behind → 11 framework CVEs

The lag compounds if the vendor ships packaged installers (MSI/DMG) on a quarterly cycle while the npm ecosystem ships patches weekly.

### Ingredient 2 — Framework vs. runtime distinction

```
Electron app
├── [Framework layer]   ← Electron process model, IPC, contextBridge, Node.js integration
│   ├── main.js, preload.js — developer-written, inherits Electron's API surface
│   └── electron/  — the framework binary (Node + modified Chromium shell)
│       └── version pinned in package.json: "electron": "40.6.1"
│
└── [Runtime layer]     ← Chromium content layer (Blink renderer, V8)
    └── Chromium 144.x — auto-updated by the Electron project, tracks upstream
```

CVEs in the **framework layer** (IPC auth bypass, unquoted paths, contextBridge isolation breaks) are NOT the same as CVEs in the **runtime layer** (browser renderer exploits, V8 sandbox escapes, GPU memory corruption). A `navigator.userAgent` check ONLY covers the runtime layer.

### Ingredient 3 — How transitive dependencies travel

Electron apps bundle their entire `node_modules` tree inside `resources/app.asar`. That asar includes:

- Direct deps (`electron-dl`, `image-downloader`) → each pulls `follow-redirects`
- `follow-redirects` ≤ 1.15.9 → CVE-2026-40895 (header leak on cross-domain redirect)
- Outdated `node_modules` versions survive indefinitely because `npm audit` is rarely run against the asar contents during routine builds

The attack surface: any `fetch()`/`http.get()` call that follows redirects and sets sensitive headers (`X-API-Key`, `Authorization`) is potentially affected even if the outer Electron framework is current.

## Detection Methodology

### Step 1 — Find the Electron framework version

**Method A: DevTools console** (if DevTools is accessible)
```javascript
// In Electron DevTools (Ctrl+Shift+I or F12)
process.versions.electron  // → "40.6.1"
process.versions.node      // → "20.18.3"
process.versions.chrome    // → "144.0.7251.168"  ← Chromium runtime (separate!)
```

**Method B: package.json in app resources**
```bash
# macOS
cat "/Applications/AcmeMessenger.app/Contents/Resources/app/package.json" | grep '"electron"'

# Windows
cat "C:\Users\<user>\AppData\Local\Programs\acme-messenger\resources\app\package.json" | grep '"electron"'

# Linux
cat "/opt/acme-messenger/resources/app/package.json" | grep '"electron"'
```

**Method C: dist-electron/main.js size heuristic**
If `package.json` shows no pinned version, check `resources/app/dist-electron/main.js` size and grep:
```bash
grep -o 'electron":"[^"]*"' resources/app/package.json
# or check the lock file
grep '"electron"' resources/app/package-lock.json | head -5
```

### Step 2 — Map the Electron version to the Chromium runtime

Cross-reference: https://releases.electronjs.org/ (column: `chrome`)

```
Electron 40.6.1  → Chromium 144.0.7251.x  ← runtime (check for browser CVEs separately)
Electron 40.8.5  → Chromium 144.0.7251.x  ← same runtime, different framework fixes
```

Key insight: the same Chromium version can appear across multiple Electron framework versions. Matching on Chromium version alone proves nothing about framework security.

### Step 3 — Check framework CVEs

```bash
# NVD search
# https://nvd.nist.gov/vuln/search/results?query=electron+40&results_type=overview

# GitHub Security Advisories for electron/electron
# https://github.com/electron/electron/security/advisories

# GHSA search (GitHub Advisory Database)
# https://github.com/advisories?query=electron+framework
```

Always check the official Electron releases page for "Security" tagged releases:
```
https://releases.electronjs.org/
```

### Step 4 — Find transitive dependency versions

```bash
# Unpack asar
npx asar extract resources/app.asar /tmp/app_extracted

# List all installed versions of a suspicious dep
find /tmp/app_extracted/node_modules -name "package.json" \
  -path "*/follow-redirects/package.json" \
  -exec grep '"version"' {} \; -print

# Full dependency tree
cd /tmp/app_extracted && npm ls --depth=3 2>/dev/null | grep -E "(follow-redirects|electron-dl|image-downloader)"

# Check for known vulnerable patterns
grep -rn "X-API-Key\|Authorization" /tmp/app_extracted/node_modules/follow-redirects/ 2>/dev/null
```

### Step 5 — Match CVE descriptions to in-source call sites

For each CVE, search for the call pattern described in the advisory:

```bash
# CVE-2026-34768: app.setLoginItemSettings without path quoting
grep -rn "setLoginItemSettings" /tmp/app_extracted/dist-electron/
grep -rn "setLoginItemSettings" /tmp/app_extracted/dist-electron/ -A 5 | grep -i "path\|exec\|open"

# CVE-2026-34778: executeJavaScript called on a service-worker-capable page
grep -rn "executeJavaScript" /tmp/app_extracted/dist-electron/

# CVE-2026-34780: contextBridge VideoFrame exposures
grep -rn "contextBridge.exposeInMainWorld" /tmp/app_extracted/ | wc -l
grep -rn "VideoFrame\|transferToImageBitmap" /tmp/app_extracted/

# CVE-2026-34775: nodeIntegrationInWorker
grep -rn "nodeIntegrationInWorker" /tmp/app_extracted/ | grep "true"

# CVE-2026-34765: contextBridge isolation (general)
grep -rn "contextIsolation.*false\|nodeIntegration.*true" /tmp/app_extracted/
```

Count of call-sites is evidence for exposure surface, even when the specific exploit requires an attacker-controlled page.

## Variants

### Variant A — Outdated Electron framework (current Chromium runtime)

**ACME-007 case.** Chromium runtime is current; no browser CVEs. Electron framework is behind by ≥2 minor versions. Framework-layer CVEs affect:
- IPC authentication (sender origin not validated)
- contextBridge isolation edge cases
- setLoginItemSettings path handling
- Service worker IPC interception

**Verification**: `process.versions.electron` → compare against latest stable release. Check the electronjs.org releases page for "Security" releases between the pinned version and latest.

**Filing**: CWE-1104 aggregate. Anchor on the highest-CVSS statically-confirmable CVE. List the remaining CVEs as "conditional" with explicit attack prerequisites.

### Variant B — Outdated Chromium bundle (e.g. CefSharp, old Electron major)

**ACME-006 case (CefSharp 98 = Chromium 98).** An entirely different attack surface: browser renderer CVEs, V8 sandbox escapes, GPU process exploits. CVSS can reach 9.8 if a known V8 exploit exists for that Chromium version.

Detection: check `navigator.userAgent` for the Chromium version string. Cross-reference against the Chrome release archive for known CVEs. For CefSharp: `BrowserSettings.JavascriptEnabled`, check version via `Cef.ChromiumVersion`.

**Do NOT conflate with Variant A.** Variant A = framework layer. Variant B = runtime layer. Both can coexist in the same app.

### Variant C — Outdated transitive dependencies (follow-redirects, electron-dl)

**CVE-2026-40895**: `follow-redirects` ≤ 1.15.9. When an HTTP request follows a cross-domain redirect, sensitive headers (`Authorization`, `X-API-Key`) are forwarded to the redirect destination. Attack scenario: an attacker controls a redirect target (e.g., via MITM on an HTTP endpoint, or a server returning a 301 to an attacker domain).

Affected components in the ACME-007 case study:
- `image-downloader` → `follow-redirects` 1.15.9
- `electron-dl` → `follow-redirects` 1.15.9

Impact: if the app downloads images with authentication headers and any endpoint performs cross-domain redirects, tokens leak to the redirect destination. Lower impact than framework-layer CVEs; CVSS ~5.3 Medium.

**Filing**: include as a supplemental finding in the CWE-1104 aggregate, lower confidence than the statically-confirmed framework CVEs.

### Variant D — app.setLoginItemSettings unquoted path (CWE-428, Windows local privesc)

**CVE-2026-34768.** On Windows, `app.setLoginItemSettings({ openAtLogin: true })` registers the app binary path in the Windows Registry under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. If the registered path contains spaces and is NOT quoted, Windows will attempt to execute each space-separated token as a potential executable before finding the real one.

Example: `C:\Program Files\AcmeMessenger\acme-messenger.exe` → unquoted → Windows tries:
1. `C:\Program.exe` (attacker-planted)
2. `C:\Program Files\AcmeMessenger.exe` (attacker-planted)
3. `C:\Program Files\AcmeMessenger\acme-messenger.exe` (legitimate)

Attack path: a local attacker with write access to `C:\` (standard user) plants `C:\Program.exe` → executes at SYSTEM-level login of any user running the app.

**Static confirmation**: grep `setLoginItemSettings` call-sites, verify no `path:` property with explicit quoting, or check if the Electron version is affected (the framework handles quoting — older versions did not).

```bash
grep -rn "setLoginItemSettings" /tmp/app_extracted/dist-electron/ -A 5
# red flag: called with no explicit path property, or an unquoted path property
```

CVSS 7.3 High (AV:L, AC:L, PR:L, UI:N, S:U, C:H, I:H, A:H). Requires local access — Windows only.

## Live Verification SOP

```
1. Obtain the Electron version
   → process.versions.electron in DevTools, or grep package.json

2. Determine the version delta
   → check https://releases.electronjs.org/
   → count how many patch/minor releases behind the pinned version is
   → note which releases are tagged "Security"

3. For each security release between the pinned version and latest:
   → read the release notes and linked GitHub Security Advisories (GHSA)
   → for each CVE: note CWE, CVSS, description, affected API

4. For each CVE: grep the unpacked asar for the call-site pattern
   → record exact file path + line number (or match count)
   → classify: static-confirmed / conditional / N/A

5. For conditional CVEs (require an attacker-controlled tenant page):
   → determine whether the app loads any tenant-supplied content (yes/no)
   → rate the prerequisite difficulty (high AC if no tenant content exists)

6. For transitive dep CVEs (follow-redirects etc.):
   → find node_modules -name "package.json" → confirm version
   → grep for header-setting patterns near HTTP calls

7. Draft the aggregate report:
   → anchor = highest-CVSS static-confirmed CVE
   → list conditional CVEs with explicit AC: prerequisites
   → NEVER fabricate or guess CVE IDs — verify each against NVD before citing
```

**Critical rule (lesson from a real filing round)**: Do NOT invent CVE IDs. If a CVE ID cannot be verified via NVD or GHSA, omit it and describe the vulnerability class only. Filing with a fabricated CVE ID destroys report credibility.

## Real-World Examples Table

| Case | Finding | Electron/runtime version | CVE/Advisory | Outcome |
|------|---------|---------------------------|---------------|---------|
| Case study (ACME-006) | Outdated Chromium bundle | CefSharp 98 = Chromium 98 | Multiple Chromium 98 CVEs | Static-confirmed |
| Case study (ACME-007) | Outdated Electron framework | Electron 40.6.1 | CVE-2026-34768 + 10 others | Aggregate CWE-1104, static-confirmed |
| Slack (2023) | libwebp bundled in Electron | Electron 26.x | CVE-2023-4863 (libwebp CVSS 8.8) | Slack acknowledged but did NOT receive per-CVE advisories for each bundled Electron app — one advisory, one fix |
| Signal Desktop (2022) | Electron version lag | Electron 14.x | Context isolation bypass | Updated to a fixed Electron version; no separate CVE issued for Signal |
| Discord | Electron IPC sender spoof | Electron 28.x | CVE-2024-27288 | P2 bounty on HackerOne; framework-layer finding |
| 1Password | libwebp + Electron composite | Electron 26.x | CVE-2023-4863 | One aggregate advisory; no per-libwebp CVE for the 1Password binary |

**Libwebp-bundler precedent**: when libwebp CVE-2023-4863 (CVSS 8.8 Critical) was disclosed in 2023, every Electron app bundling Electron 26.x was technically affected (Electron bundles Chromium, which bundles libwebp). Slack, Signal, Discord, and 1Password all issued single security updates rather than derivative per-CVE advisories. The precedent establishes: **file one aggregate advisory with the highest-confidence anchor CVE; mention all others as "also addressed in the same framework update."**

## Defense

### Vendor-side

1. **Pin Electron to latest stable, not latest of a specific major** — `"electron": "^40.0.0"` tracks security patches automatically
2. **Enable Electron's auto-update mechanism** for the framework binary itself (separate from app-content auto-update)
3. **Run `npm audit` against the asar contents** as part of CI/CD — requires unpacking the asar and running `npm audit` in the extracted directory
4. **Set `openAtLogin` path explicitly with quoting** — `app.setLoginItemSettings({ openAtLogin: true, path: `"${process.execPath}"` })` (quotes inside the string)
5. **Upgrade `follow-redirects`** to ≥ 1.15.10 and periodically audit all transitive HTTP-client deps
6. **Subscribe to electron/electron GitHub security advisories** — Security Advisories → Watch → Custom → Security alerts

### Reporter-side (CWE-1104 aggregate filing strategy)

```
One advisory covering:
  - Anchor: highest-CVSS static-confirmed CVE (e.g. CVE-2026-34768, CVSS 7.3)
  - Body: list all additional CVEs with a classification
    • Static-confirmed: found call-sites in the asar, no tenant-page prerequisite
    • Conditional: require an attacker-controlled tenant page (state AC: High explicitly)
    • Transitive deps: follow-redirects version mismatch (state as supplemental)
  - Recommendation: upgrade Electron to 40.8.5 (or latest stable)
  - Do NOT claim live exploitation for conditional CVEs
```

**Honest AC-framing table** (mandatory for conditional CVEs):

| CVE | CVSS (NVD) | In-source call-sites | Prerequisite | File as |
|-----|-----------|-----------------------|---------------|---------|
| CVE-2026-34768 | 7.3 H | 2x setLoginItemSettings | Local write access (Windows) | Static-confirmed |
| CVE-2026-34778 | 6.0 M | 36+ executeJavaScript | Tenant page that registers a service worker | Conditional (AC:H) |
| CVE-2026-34780 | 8.9 H | 13 contextBridge exposures | Attacker-controlled tenant page | Conditional (AC:H) |
| CVE-2026-34775 | 7.4 H | nodeIntegrationInWorker:true | Attacker-controlled tenant page | Conditional (AC:H) |
| CVE-2026-34765 | 6.0 M | contextBridge isolation | Attacker-controlled tenant page | Conditional (AC:H) |
| CVE-2026-40895 | ~5.3 M | follow-redirects 1.15.9 | Cross-domain redirect + auth header | Transitive dep (supplemental) |

## Filing & Severity

### Aggregate filing rationale

Do not file 11 separate CVE-anchored reports. Reasons:
1. **Precedent**: libwebp-2023 established that bundling apps don't receive per-CVE advisories
2. **Credibility**: filing 11 separate reports for the same "upgrade Electron" fix inflates numbers and irritates triagers
3. **Conditional CVEs**: most framework CVEs require an attacker-controlled tenant page — in many apps (especially enterprise messengers), this is a high-AC prerequisite that significantly lowers effective CVSS
4. **One fix closes all**: the remediation is identical for all — upgrade to Electron 40.8.5

### Severity anchoring

- **Anchor CVE**: CVE-2026-34768 (CWE-428, CVSS 7.3 High) — unquoted search path, static-confirmed, no tenant-page prerequisite, Windows local privesc
- **Report severity**: P2 High (outdated framework = aggregate risk, single fix available)
- **Do NOT claim CVSS 8.9** (CVE-2026-34780) as the headline if that CVE requires an attacker-controlled tenant page and the app's architecture makes that unlikely — honest framing is required

### Platform routing

| Platform | Appropriate? | Notes |
|---------|-------------|-------|
| HackerOne (vendor program) | Yes | Frame as a CWE-1104 aggregate; attach static evidence of call-sites |
| Bugcrowd (vendor program) | Yes | Same framing |
| National CERT (domestic vendors) | Yes | Use CWE-1104 + list all CVEs; include framework version evidence |
| NVD submission | Only if the vendor won't acknowledge | Requires a coordination period first |

## Chains

Electron framework CVEs become more exploitable when combined with other primitives:

### Chain 1: Framework CVE + Custom Scheme Handler Injection (ACME-001 + ACME-007)

```
customscheme://?eventData=<JS>
  → executeJavaScript (ACME-001, scheme-XSS)
  → attacker JS runs in the tenant renderer
  → the tenant renderer registers a service worker (CVE-2026-34778 prerequisite now met)
  → the SW intercepts IPC replies → spoof responses to other IPC handlers
  → combined: near-0-click desktop takeover (CVSS upgrade: 8.9→9.6)
```

CVE-2026-34778 alone requires a "tenant page" that can register a service worker. The scheme-XSS finding PROVIDES that tenant-page code execution, eliminating the AC:High prerequisite. The combined CVSS rises accordingly.

### Chain 2: Framework CVE + Origin-Agnostic Preload (ACME-007 + ACME-010)

```
Attacker page loaded via ACME-010 (openWindow-style IPC handler)
  → preload.js attached to the attacker origin (ACME-010 class)
  → the attacker page now satisfies the "attacker-controlled page" prerequisite for ALL conditional CVEs
  → CVE-2026-34780 (VideoFrame) + CVE-2026-34775 (nodeIntegrationInWorker) both unlocked
  → combined surface: contextBridge bypass + worker nodeIntegration = full Node.js access from the renderer
```

In this chain, conditional CVEs (AC:High standalone) become AC:Low because the ACME-010 finding already delivers arbitrary page loading with preload attached.

### Chain 3: CVE-2026-40895 (follow-redirects) + Tenant MITM

```
A tenant page triggers an image download via image-downloader (follows redirects)
  → the download request includes an X-API-Key or Authorization header
  → the tenant server (or a MITM) responds 301 → attacker domain
  → follow-redirects 1.15.9 forwards the header to the attacker domain
  → the attacker harvests the session token
```

Requires either MITM capability (network attacker) or a tenant-side redirect (social engineering). Lower severity standalone but relevant in enterprise settings with per-tenant API keys.

## Related

- [[Pattern - Electron Preload Injection Chain]] — the ACME-001 + ACME-010 chain; provides the "attacker-controlled page" that upgrades conditional CVEs to AC:Low
- [[Lessons Learned]] — never fabricate CVE IDs; Electron framework version ≠ Chromium runtime version
- [[Pattern - Hardcoded Credentials]]
