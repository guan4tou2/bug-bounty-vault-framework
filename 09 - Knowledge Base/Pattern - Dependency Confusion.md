---
type: pattern
title: Pattern - Dependency Confusion
tags: [pattern, cwe-829, supply-chain, dependency-confusion, npm, pypi, bb-pattern]
status: verified
vuln_class: supply-chain
severity_range: P2-P1
last_updated: 2026-06-05
---

# Pattern - Dependency Confusion

> Supply-chain attack: an internal package name is unclaimed on a public registry (npm/PyPI/RubyGems/Maven) → an attacker squats the name and publishes a higher version → the target's build/CI installs it at install-time RCE. Alex Birsan's pioneering research breached Apple, Microsoft, and 35+ other companies, earning $130k+. A single bounty on this class often hits a program's cap ($2.5k-$5k+).

## 1) Detection (finding candidates)

**Sources**: internal package names referenced in the target's JS bundles / source maps / `package.json` / `.npmrc`.
- npm scoped packages: `@org/pkg` (high confidence — clearly an internal naming convention)
- Extract `node_modules/@scope/pkg` paths from a sourcemap
- Automation: a scoped dependency-confusion scanner re-sweeping in-scope domains on a regular interval

**Necessary condition**: the package returns **404 (unclaimed)** on the public registry.

## 2) Verification (the three tiers that determine viability, weakest to strongest)

### Tier 1: scope/org claim status (non-intrusive, do this first)

- Package returning 404 ≠ exploitable. **The key question is whether the scope's org/user has already been claimed.**
- npm: `https://www.npmjs.com/org/<scope>` or `https://www.npmjs.com/~<scope>`
  - **404 = scope entirely unclaimed → can be squatted → strong candidate**
  - **200 = org already claimed (even with 0 packages) → cannot be squatted → dead**
- Warning: querying from a datacenter IP will get blocked by npmjs's Cloudflare (403). Use `curl_cffi` (Chrome impersonation) or a regular browser instead — a 403 is not a real signal.
- Query the registry API for a scope's package count: `https://registry.npmjs.org/-/v1/search?text=scope:<scope>` → only proceed if `total=0`.

### Tier 2: does the build actually pull from the public registry? (hard to prove externally)

- **Core uncertainty**: a 404 plus a reference could mean either (a) a private registry with public fallback (exploitable) or (b) a monorepo local workspace package / strictly private registry (not exploitable, false positive).
- Weak external signal: if the target is security-conscious, it would have defensively registered the scope placeholder already; a fully unclaimed scope leans toward "no defensive registration was done" = leans exploitable.
- **This cannot be proven 100% externally** — that's an inherent limitation of dependency confusion as a bug class.

### Tier 3: canary PoC (the only decisive method, but intrusive)

- Claim the scope → publish a package with a **version number higher than the internal one** (npm prefers the higher version, so the build will pull yours).
- Put an **out-of-band callback** (DNS/HTTP) in a `preinstall` script — install-time execution → receiving the callback (with hostname/user/path) is hard proof the target's CI pulled your package.
- The payload must be harmless (callback only, no destructive action).
- **Warning — active/intrusive testing**: many programs prohibit this, or it may violate scope rules → **check the program's rules before submitting; never do this autonomously without checking.**

## 3) Submission Pitfalls

- **Some programs reject this class outright**: if the package isn't in an official public repo, or a private registry is used → judged N/A. Microsoft MSRC has historically dismissed dependency-confusion reports.
- Run the three-question filter: what can the attacker actually get (CI RCE / source access) → is this default behavior (no) → what's left once you strip out theory (a canary callback is hard proof vs. just an unclaimed scope).
- An unclaimed scope with no canary = low/triage-only; a canary callback = high/critical.

## 4) Related Techniques (same supply-chain family, worth hunting together)

- **Subdomain takeover**: dangling CNAME → takeover a subdomain (a dedicated scanner can automate discovery)
- **Typosquatting / namespace confusion**: register a visually similar package name
- **PyPI / RubyGems / Maven / Composer / Docker**: same idea — check the corresponding public registry for internal package names
- **GitHub Actions / CI referencing an unclaimed Action**

## Worked Example (anonymized)

- A scanner found `@acmecorp-internal/core` referenced in a fintech target's production JS across 15 in-scope domains
- Tier 1: the registry scope had 0 packages, the package returned 404; the org page required a browser check to distinguish 404 from 200
- Tier 2: the sourcemap only showed an indirect path reference — could not prove the build pulls from public npm → judged honestly as unverifiable
- Lesson: the scanner has high recall for finding candidates; the analyst needs high precision to verify. A canary is the only decisive proof method, and it requires both manual judgment and a check against program rules.

## Sources

- Alex Birsan — Dependency Confusion (Apple/Microsoft, $130k): <https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610>
- $2.5k RCE via unclaimed Node package: <https://medium.com/@p0lyxena/2-500-bug-bounty-write-up-remote-code-execution-rce-via-unclaimed-node-package-6b9108d10643>
- $5k RCE (Chevon Phillip): <https://chevonphillip.medium.com/rce-due-to-dependency-confusion-5000-bounty-fd1b294d645f>
- Geek Freak (DhiyaneshGeek): <https://dhiyaneshgeek.github.io/web/security/2021/09/04/dependency-confusion/>
- x1337loser/Dependency-Confusion: <https://github.com/x1337loser/Dependency-Confusion>
- Microsoft Security Blog, 2026-05: <https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/>
