---
type: pattern
title: "SourceMap Endpoint Family Disclosure"
tags: [information-disclosure, source-map, spa, react, vue, webpack, api-enum, attack-surface-expansion, cwe-200, cwe-540, bb-pattern]
status: active
last_updated: "2026-05-13"
---

# Pattern — SourceMap Endpoint Family Disclosure

## Core Idea

Modern SPAs (React / Vue / Angular) built with webpack / vite generate `.js.map` files by default in dev mode (containing the full original `.js` source via `sourcesContent`, variable names, and comments). Production builds **should** disable this, but it's frequently forgotten.

Once a source map is publicly accessible:
- **The entire frontend source is recoverable** (React components / Vuex store / Angular services)
- **The full backend API endpoint list is exposed** (backend URLs are hardcoded in the frontend)
- **The complete auth flow is exposed** (which cookie/localStorage key holds the JWT, the SSO mechanism, the login sequence)
- **Environment variables / build-time secrets leak** (`process.env.REACT_APP_*` gets baked into the bundle)

→ **A single exposed file expands the attack surface 4-10x.**

## Detection (try this on every SPA)

```bash
# Grab the main bundle hash from the HTML
MAIN=$(curl -s "https://$TARGET/" | grep -oE 'static/js/main\.[a-f0-9]+\.js' | head -1)

# Try the matching .map
curl -sI "https://$TARGET/${MAIN}.map"
# 200 + Content-Length > 100KB = hit

# Sweep the common hashed filenames in one pass
for F in main runtime vendors polyfills; do
  for HASH in $(curl -s "https://$TARGET/" | grep -oE "${F}\.[a-f0-9]+\.js" | head -3); do
    curl -sI "https://$TARGET/static/js/${HASH}.map" -o /dev/null -w "%{http_code} ${HASH}.map\n"
  done
done
```

**Framework reference**:

| Framework | Source map path convention |
|---|---|
| Create React App | `/static/js/main.<hash>.js.map`, `/static/js/<chunk>.chunk.js.map` |
| Vite | `/assets/index-<hash>.js.map`, `/assets/<name>-<hash>.js.map` |
| Angular CLI | `/main.<hash>.js.map`, `/polyfills.<hash>.js.map`, `/runtime.<hash>.js.map` |
| Next.js | `/_next/static/chunks/main-<hash>.js.map` |
| Nuxt.js | `/_nuxt/<hash>.js.map` |
| Webpack default | `/dist/bundle.js.map`, `/bundle.<hash>.js.map` |

## Extraction (what to do once you have the map)

```python
import json, re

m = json.load(open("main.map"))
# 1. Full list of original source files
sources = m.get("sources", [])
print(f"file count: {len(sources)}")

# 2. Extract API endpoints from sourcesContent
endpoints = set()
for content in m.get("sourcesContent", []) or []:
    if not content: continue
    endpoints.update(re.findall(r'/api/[a-zA-Z0-9_/\-]+', content))
    endpoints.update(re.findall(r"['\"]/v\d+/[a-zA-Z0-9_/\-]+['\"]", content))

# 3. Extract hardcoded base URLs from sourcesContent
urls = set()
for content in m.get("sourcesContent", []) or []:
    if not content: continue
    urls.update(re.findall(r'https?://[a-z0-9.\-]+\.[a-z]{2,}(?:/[a-z0-9_\-/]*)?', content))

# 4. Extract build-time secrets from sourcesContent
for content in m.get("sourcesContent", []) or []:
    if not content: continue
    for m in re.finditer(r'(api[_-]?key|secret|token|password)["\']?\s*[:=]\s*["\']([^"\']+)["\']', content, re.I):
        print(f"  potential secret: {m.group(0)[:80]}")
```

## Case Study

### SaaS product SPA (production)

A production SPA's main bundle source map was found publicly accessible at HTTP 200, weighing in at several megabytes.

| What was obtained | What an attacker can do with it |
|---|---|
| Dozens of React source files (auth context / SSO login / app shell / chat UI) | Complete understanding of the auth flow |
| Half a dozen backend API endpoints (login, greeting/status, chat listing, chat messages, feedback, FAQ listing) | Candidates for auth-required brute forcing / IDOR |
| SSO `?key=` mechanism exposed | Basis for SSO-bypass hypotheses |
| Hardcoded frontend↔backend base URL | Confirms the relationship between the SPA origin and its API origin |

→ A single exposed source map added roughly half a dozen previously-unknown backend endpoints to the attack-surface queue.

### Vendor-shared telemetry key (downgraded to informational)

A separate control-panel login page (a widely-used commercial hosting-panel product, unrelated version) had a hardcoded AWS IAM key and a Sentry DSN baked into its JS.

**But** — the same key showed up across every deployment of that hosting-panel product regardless of the operator, indicating it was a **vendor-shared telemetry key baked into the product itself**, not something leaked by the specific target being tested.

→ **Lesson**: when you find a key inside a source map, Google the key prefix first to check whether it's a known vendor default. If 3+ unrelated hosts share the same key, it's vendor-shared — **downgrade to Informational**.

## Severity Tiers

| Scenario | Severity |
|---|---|
| Source map is public but every endpoint it reveals is already public/documented | P5 Info |
| Source map reveals an internal endpoint (not in the published OpenAPI/Swagger spec) | **P4 Low** |
| Source map reveals endpoints + auth-flow detail (enables planning a bypass) | **P3 Medium** |
| Source map contains a build-time secret (API key / private endpoint URL) | **P2 High** |
| Source map contains a verifiable IAM credential / internal cluster URL | **P1 Critical** |

**Downgrade rules**:
- Vendor-shared key (hosting-panel product / control-panel product / analytics tracking ID) → -1 tier
- Endpoint is already documented in the public OpenAPI/Swagger spec → -1 tier
- HSTS + CSP `frame-ancestors` restrictions narrow the attack surface elsewhere, but do nothing to mitigate the source-map exposure itself

## Non-Findings (does not count as a vulnerability)

| Scenario | Why it doesn't count |
|---|---|
| `.js.map` returns 403 / 404 | Already correctly disabled |
| `.js.map`'s `sourcesContent` is `null` (cheap-source-map mode) | Only line mappings remain, no original source, low value |
| A pure dev/staging subdomain the tester already knows is a test environment | Out of scope, or downgrade to a dev-environment leak |
| The officially hosted version of an open-source project | The source code is public by design |

## Related Patterns

- [[Pattern - Hardcoded Credentials]] — for secrets found inside a source map
- [[Pattern - IDOR Broken Object Authorization]] — once you have the endpoint list, test any `/id`-suffixed route for IDOR
- [[Pattern - CORS Misconfiguration]] — pairs naturally with the SPA's CORS Origin config once you can see it in the source map

## Tooling / Automation Suggestion (bbflow hunter candidate)

```bash
# Hunter: sourcemap-probe
# Trigger condition: fingerprint identifies a React/Vue/Angular SPA
# Actions:
#   1. Grab the main bundle hash from index.html
#   2. Try the matching .map path
#   3. If 200 + sourcesContent present, download and extract API endpoints / secrets
# Output: sourcemap_report.md (endpoint list / secret list)
```

Candidate for future inclusion in a bbflow-style hunter pipeline.

## Learned Items

1. **Modern SPAs should disable source maps in production by default** — for any SPA target, the very first thing to try is `main.<hash>.js.map`; hit rate is above 50%.
2. **Every framework has a different source-map path convention** — fingerprint the framework first (check `<meta name="generator">` or the HTML structure) before guessing paths.
3. **`sourcesContent: null` means nothing to extract**: getting a `.map` file with a null `sourcesContent` means cheap-source-map mode was used — only line-number mapping is available, no recoverable source.
4. **Any key found inside a source map must be Googled by its prefix** to rule out a vendor-shared default before reporting it as a target-specific leak — otherwise it's an easy N/A on H1/Bugcrowd.
