---
type: reference-card
title: "Version and CVE Precheck — Mandatory Pre-Flight Gate"
tags: [methodology, cve, version-check, firmware, saas, pre-flight, stop-loss]
status: draft
last_updated: 2026-08-12
---

# Reference Card - Version and CVE Precheck

> **TL;DR**: A mandatory pre-flight gate that runs the moment you have a concrete software/firmware/SaaS target version and *before* you invest any hands-on analysis time. Its job is to prevent two failure modes: (1) reporting a vulnerability that is already a known, disclosed CVE against an outdated version — dead on arrival at most bounty programs — and (2) burning hours of analysis before discovering the issue was already publicly fixed. This is a procedural methodology card, not filler: follow it in full, every time.

## Quick Reference

### Applicability — what counts as a "software/firmware target"

| Category | Examples | Precheck type |
|---|---|---|
| Firmware | Router/NAS/camera/peripheral-management firmware | Sub-table A (has a version number) |
| Native app / desktop | Any installed desktop client with a version number | Sub-table A |
| Mobile (APK/IPA) | Any mobile app with a version number | Sub-table A |
| Library / SDK | Apache / nginx / busybox / OpenSSL (often embedded in firmware) | Sub-table A (component-level) |
| OS / Kernel | Linux kernel / RTOS | Sub-table A |
| SaaS / Cloud (rolling release) | Any cloud product with no user-visible version number | Sub-table B (no version number) |
| Recon phase (subdomain enum / fingerprinting) | — | **Does not trigger this gate** — no target version is locked in yet |

**Trigger point**: once you have a concrete target version, or a locked-in cloud target, and are about to start hands-on analysis. Fingerprinting/banner-grabbing before a version is confirmed does not trigger this gate.

### "Latest version" definition (mandatory)

| Situation | Verdict |
|---|---|
| Vendor officially labels it `latest stable` | ✅ counts as latest |
| Vendor maintains multiple branches (e.g. 5.0.x / 5.1.x / 5.2.x) but still ships security updates to each | ✅ the highest version within each supported branch counts as latest |
| LTS/ESR branch | ✅ counts as latest, provided the vendor still publishes security advisories for that branch |
| Beta / RC / nightly | ❌ does not count as latest (unstable, not a general release) |
| Vendor has declared EOL, no more security updates | ⚠️ EOL but still widely deployed → route to advisory disclosure (vendor disclosure / national CERT), **do not** submit to a bounty program; EOL with no customer impact → stop immediately |
| No explicit EOL notice but >2 years without a release | ⚠️ treat as unsupported; check the last release notes and confirm whether the vendor's security page still lists it as maintained |

**Exceptions that still permit analyzing an old version**:
- A pentest engagement explicitly pins the version in scope — record `engagement_pinned_version: <ver>` in the scope document
- Written vendor authorization to research a specific old version (coordinated disclosure agreement)
- Educational/research use only (not submitted for bounty, purely for knowledge-base accumulation)

Even under an exception, still run this full gate — the decision is simply recorded as `proceed - exception (<reason>)`.

### Sub-table A — versioned targets (firmware / native / mobile / library / OS)

| Check | Action | Why |
|---|---|---|
| **Release timeline** | Check the vendor's official site / GitHub releases / firmware update center for the latest stable version (per the definition above) | Being behind latest sharply raises the odds of hitting an already-known CVE |
| **Matching CVEs** | Search NVD / GitHub Advisory / CVE.org: `"<vendor> <product> CVE"` | LLM training-data recall of specific CVE details is wrong more often than not — never cite a CVE from memory; always verify by live web search |
| **Vendor advisory** | Search `"<vendor> security advisory"` and check the vendor's security/changelog/release-notes pages | An already-patched attack surface may only be documented in release notes — skipping this risks a dead-on-arrival submission |
| **Component-level grep** | Once a suspicious binary/endpoint/behavior is found, follow up with `"<component> CVE"` + `"<component> security advisory"` | A real-world case cost 6 hours of analysis and a full report draft before discovering the root cause was already CVE-2023-50358 |

### Sub-table B — SaaS / Cloud rolling release (no version number)

No version to compare against "latest" — instead check "advisories + disclosed reports within a time window":

| Check | Action | Why |
|---|---|---|
| **Research timestamp** | Record today's date `<YYYY-MM-DD>` as the baseline | Substitutes for the firmware "version" concept |
| **CVEs/GHSAs in the last 12 months** | NVD search `"<vendor> <product>"` + GitHub Advisory, filtered to `published_after = baseline - 12 months` | Rolling releases have no version, but vendors still publish advisories |
| **Disclosed reports in the last 12 months** | HackerOne hacktivity for the program's handle + Bugcrowd disclosures | If bug bounty hunters already publicly disclosed this class of finding, the same surface has likely already been swept |
| **Vendor changelog / blog** | Vendor engineering blog / security page / status page | Rolling changes may only be documented in a blog post, not a formal advisory |
| **Component precheck** | If a third-party component is spotted (a frontend library version, backend framework, OAuth provider), apply Sub-table A to it | SaaS products embed components too |

> For SaaS, the "stop condition" becomes: finding a matching disclosed report → mark as known, stop investing further; or a recent advisory mentioning the same endpoint → treat as known.

### Required sources to check

**Mandatory, every time this gate runs (3):**
1. **NVD** — `https://nvd.nist.gov/vuln/search`, keyword `"<vendor> <product>"`
2. **Vendor's own security advisory page** — most authoritative source; may include internal fixes with no assigned CVE
3. **Vendor changelog / release notes** — `"<vendor> <product> changelog <version>"`

**Recommended for higher-value targets/programs (3):**
4. **GitHub Security Advisory (GHSA)** — `https://github.com/advisories`, mandatory for any open-source component
5. **HackerOne hacktivity / disclosed reports** — search `is:disclosed` on the relevant program
6. **Third-party advisories** — major security research blogs, vulnerability databases, or conference writeups covering the same product

**What counts as "already known"**: the fix does not need an assigned CVE number — a vendor-disclosed internal fix (a vendor advisory ID or a GHSA-only entry with no CVE) **also counts as known**, and should stop further investment in the same root cause.

### Stop conditions (mandatory)

| Trigger | Action |
|---|---|
| Firmware is ≥1 major version behind latest and not on a supported branch | **Download the latest version and restart analysis there**, or review the changelog to confirm the attack surface wasn't already patched |
| A matching CVE / GHSA / vendor advisory already covers the same root cause | Mark as known, **do not** invest in dynamic verification or a report |
| Uncertain whether the current version is the latest | Check the vendor's release page **first**, before doing any further hands-on work |
| SaaS target matches a disclosed report on the same endpoint + same root cause | Mark as a known duplicate, stop |
| Target is EOL with no customer impact | Close out immediately (do not route to advisory, do not submit for bounty) |

### Post-stop-loss procedure (mandatory sequence)

Once a stop condition is confirmed, execute these steps in order:

1. **Recon notes**: record a pre-flight-check entry (see template below)
2. **Scope tracking**: mark the target as `status: skipped` or `status: known_cve` with a reason and the CVE/advisory URL
3. **Session handoff notes**: note the skip reason so the next session doesn't repeat the work
4. **If a submission draft already exists**: change its status to `withdrawn` with `withdrawn_reason: known_cve_<CVE-ID>`; if none exists yet, no action needed
5. **Tracking board**: move the target to closed or parked, annotated with `(known CVE - <CVE-ID>)` / `(EOL no fix)` / `(version too old)`

Optional step 6: if the version-check/advisory-search process itself taught a reusable lesson (e.g. a vendor's advisory page was hard to find, or needed a specific search query to surface), capture it as a knowledge-base lesson.

### N-day handling (vendor already patched, but the target hasn't updated)

The vendor has published a patch, but **the specific target instance in front of you has not applied it** (a customer missed the update, firmware wasn't pushed, a device in the field never updated):

| Situation | Handling |
|---|---|
| The bounty program (most do) does not accept known CVEs | **Do not submit for bounty**; route to vendor disclosure or a national CERT, labeled `n-day - unpatched in production` |
| PoC confirms the vulnerability still triggers on your target's version | Cite the original CVE number + note `Affected: <product> v<your_version> (patch was not backported)` |
| Attack surface is broad (affects many customers / many in-field devices) | Consider an advisory + technical writeup (public research / knowledge-base value) without seeking a bounty |
| Code was fixed but the firmware/build was never pushed to production | May still be submittable as a patch-deployment gap — but **first** check the program's policy on whether deployment gaps are in scope |

## Details

### Pre-flight record template

**Versioned target (Sub-table A):**

```
### Target Pre-flight - <YYYY-MM-DD> - <vendor>/<product>/<version>
- Category: <firmware | native | mobile | library | OS>
- Version on hand: <version> (<release date YYYY-MM-DD>)
- Latest stable: <latest> (<release date>) — source: <vendor release page URL>
- Supported branch: <yes / no / EOL — source: <vendor lifecycle page>>
- Version gap: <0 (latest) | minor-N | major-N | EOL>
- CVE search: NVD <URL> → <0 / N hits affecting this version>
- Vendor advisory: <URL> → <0 / N hits>
- GHSA / 3rd-party: <URL or "skipped">
- Decision: <proceed | proceed - exception (<reason>) | abort - too old | abort - known CVE <CVE-ID> | abort - EOL>
```

**SaaS / Cloud (Sub-table B):**

```
### Target Pre-flight - <YYYY-MM-DD> - <vendor>/<product> (SaaS)
- Category: SaaS / Cloud (rolling)
- Baseline date: <YYYY-MM-DD>
- 12-month CVE / GHSA: NVD <URL> + GHSA <URL> → <0 / N hits since baseline-12mo>
- 12-month disclosed reports: HackerOne <URL> → <0 / N hits>
- Vendor changelog / blog: <URL> → <last security-related entry: YYYY-MM-DD>
- Component pre-check (if any third-party component spotted): <component> → <sub-table A result or "n/a">
- Decision: <proceed | abort - known disclosed dup | abort - recent advisory covers same endpoint>
```

### Handling multiple versions / models / components under one vendor

**Atomic unit = one `<vendor>/<product>/<version>` entry.** Rules for related targets:

| Situation | Example | Handling |
|---|---|---|
| Same vendor, different product line (different codebase) | An enterprise access point vs. a consumer router from the same vendor | **Separate entry** — CVEs cannot be assumed to carry across product lines |
| Same vendor, same product line (shared codebase) | Two enterprise access-point models from the same generation | **Separate entry**, but the vendor-advisory field may cross-reference a single advisory covering multiple models |
| Same model, different firmware versions | v1.0.0 vs v1.0.5 of the same device | **Separate entry** (applicable CVEs may differ by version) |
| Same firmware, multiple third-party components | OpenSSL / busybox / nginx / libcurl | Do **not** force a full gate run per component — check the specific component only once a suspicious binary/endpoint/behavior is found |
| Large-scale firmware component precheck | Want to bulk-generate an SBOM + CVE report | **Recommended tools**: `cve-bin-tool <rootfs>` / `syft <rootfs>` for automated component-level CVE reports; store results alongside the target's working files and cite the report in the Decision field |
| Same component/version already checked under a different model | e.g. OpenSSL 1.1.1q already checked for model A, model B uses the same version | **Cross-reference is fine** — model B's entry can say "see model A's pre-flight (same component+version)"; no need to re-run |

**Component-level tooling (optional, for firmware targets):**
- `cve-bin-tool` — Python tool, scans binaries for embedded version strings and matches against NVD (zero-config)
- `syft` — generates an SPDX/CycloneDX SBOM; pair with `grype` for automated CVE matching
- After extracting a rootfs with `binwalk`, run `cve-bin-tool` against `/usr/lib/`, `/bin/`, `/sbin/`

### Automation

| Tool | Purpose |
|---|---|
| A version+CVE precheck script that accepts `<vendor> <product> <version>` and calls the public NVD CVE API (no key required), printing matching CVEs plus a ready-to-paste markdown snippet | Speeds up the first pass on a new target; does not parse individual vendor advisory pages (structure varies too much — that step stays manual/WebFetch) |
| A "start of session" skill/hook that auto-loads this gate's summary whenever a new target or firmware analysis begins | Removes reliance on the operator remembering to run it |

**Deliberately not automated**: continuous scanning for version/CVE changes as a background monitoring job — this gate is a one-shot pre-flight decision at the start of analysis, not a continuous-monitoring pipeline; those are different concerns.

### Recommended execution order (session-start checklist)

```
claim target  →  internal dedup check (cheap, seconds)  →  this gate (web search, ~5 min)  →  start hunting
                                                                                                    ↓
                                                                          knowledge-base query (mid-hunt trigger)
```

> Internal dedup runs first because it's near-zero cost (reading two local files); this gate involves web search cost (~5 min), which is worth spending only after the cheap check has already ruled out internal duplicates. **Exception**: on a genuinely new target (no prior internal data exists yet), the dedup check is a guaranteed no-op — skip straight to this gate.

> **Cross-reference**: a separate "CVE citation" check applies when *writing* a report and validating the CVE citation itself; this gate applies *before* hands-on analysis begins. Both require verification via live web search/fetch — never cite from memory.

## Related

- [[bb-version-cve-precheck]]
- [[bb-cve-citation]]
- [[Reference Card - Remediation Verification Methodology]]
