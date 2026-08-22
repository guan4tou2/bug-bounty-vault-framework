---
type: reference-card
title: "External Skills Catalog"
tags: [external-skills, hack-skills, yaklang, third-party, install, supply-chain]
status: draft
last_updated: 2026-08-23
---

# Reference Card - External Skills Catalog

> **TL;DR**: This framework recommends installing a curated subset of [`yaklang/hack-skills`](https://github.com/yaklang/hack-skills) — a third-party, community-maintained Agent Skills pack. README.md and `Playbook - External Resource List to Skill Gap-Fill.md` both point here for "the curated list, install commands, audit status, and the security considerations of running third-party skills." This card is that list.

## Why this exists

`.claude/skills/` in this repo (the `bb-*` skills) are **process/SOP skills** — they tell an agent *when* and *in what order* to do things (dedup, safety gates, evidence discipline). They deliberately do not carry deep per-vuln-class payload catalogs, because that content churns fast and is easy to source from a maintained, audited-by-usage external pack instead of duplicating and rotting it here.

`yaklang/hack-skills` fills that gap: **technique-depth** playbooks (payloads, bypass matrices, PoC walkthroughs) per vulnerability class, distilled from public references (PayloadsAllTheThings, hacktricks, ctf-wiki, and others — see the upstream repo's own "Knowledge Sources" section for its distillation boundaries). It is **not bundled** in this repo — install it yourself, review what you install, and treat it the same as any other third-party code you run.

## Third-party trust considerations (read before installing)

- **You are running someone else's markdown as agent instructions.** A `SKILL.md` can contain anything a prompt can — including guidance an agent might follow uncritically. Read a skill before your agent acts on it for the first time, the same way you'd review a dependency before `npm install`.
- **This framework has not independently re-audited every line of every skill below.** The upstream project states its own distillation principles (no raw dictionary dumps, public-source-only, no customer-identifiable case details) — this card documents what upstream *claims*, not an independent security review by this framework's maintainers.
- **Some skills describe techniques that are destructive or leave artifacts if actually executed** (e.g. publishing a proof-of-concept package to a public registry to confirm dependency confusion, or persisting a reverse shell). Reading the technique is safe; *acting* on it is bound by this framework's own `bb-scope-safety-check` gate and GET-first principle regardless of what the external skill's own text suggests — the external skill is a knowledge source, not a permission source.
- **Pin what you install.** `npx skills add` pulls from `main` at install time; re-running it later can silently change skill content. If reproducibility matters, note the commit hash you installed against.

## Installation

```bash
# Whole pack (all skills upstream ships — currently 100+, growing over time)
npx skills add yaklang/hack-skills

# Single skill only, via raw URL (no npx tool required)
curl -fsSL https://raw.githubusercontent.com/yaklang/hack-skills/main/skills/<skill-name>/SKILL.md
```

There is no first-party "install just these N skills" flag in the upstream tool as of this writing — `npx skills add` pulls the full pack. If you only want the curated subset below, either install the full pack and ignore the rest, or script the raw-URL form per skill name from the table.

## Curated subset (web / API bug-bounty relevant)

Upstream `yaklang/hack-skills` has grown well beyond web/API bug bounty — it now spans OS privilege escalation, Active Directory, binary exploitation, cryptography CTF attacks, mobile forensics, and more (100+ skills across 14 domains as of 2026-08-23). Most of that is out of scope for this framework's web/API/cloud bug-bounty focus. The table below is the subset whose category matches what this framework's README already advertises ("JWT/SSRF/XSS/IDOR/SAML/OAuth/business-logic/WAF-bypass and more") plus the two mobile skills that come up in Electron/mobile-app bug bounty work already covered elsewhere in this vault.

> Earlier drafts of this framework's README cited a count of "22" recommended skills. That number was never enumerated anywhere in the repo (this card is the first enumeration) and predates upstream's growth — treat the table below, not any historical count, as current.

| Skill | Description (upstream frontmatter) | Notes |
|---|---|---|
| [`401-403-bypass-techniques`](https://github.com/yaklang/hack-skills/tree/main/skills/401-403-bypass-techniques) | 401/403 bypass playbook — path manipulation, HTTP method tampering, header injection, protocol downgrade, automated bypass tools | Pairs with `bb-web-vuln-scan` A01 access-control checks |
| [`android-pentesting-tricks`](https://github.com/yaklang/hack-skills/tree/main/skills/android-pentesting-tricks) | Android SSL pinning bypass, exported component abuse, WebView vulns, intent redirection, root detection bypass, tapjacking, backup extraction | Mobile-app scope only; confirm program covers mobile before using |
| [`authbypass-authentication-flaws`](https://github.com/yaklang/hack-skills/tree/main/skills/authbypass-authentication-flaws) | Login flows, password reset logic, account recovery, MFA bypass, token predictability, brute-force resistance, session boundary flaws | Overlaps `wiki/80-mfa-bypass.md` — cross-check both |
| [`business-logic-vulnerabilities`](https://github.com/yaklang/hack-skills/tree/main/skills/business-logic-vulnerabilities) | Workflows, race conditions, price manipulation, coupon abuse, state machines, multi-step authorization gaps | Overlaps `wiki/61-race-condition.md` |
| [`cors-cross-origin-misconfiguration`](https://github.com/yaklang/hack-skills/tree/main/skills/cors-cross-origin-misconfiguration) | Cross-origin trust, credentialed browser reads, origin reflection, preflight policy bugs | — |
| [`crlf-injection`](https://github.com/yaklang/hack-skills/tree/main/skills/crlf-injection) | Response-header / redirect / Set-Cookie / log CRLF injection | Overlaps `wiki/70-host-header-crlf.md` |
| [`csp-bypass-advanced`](https://github.com/yaklang/hack-skills/tree/main/skills/csp-bypass-advanced) | CSP policy weaknesses, trusted-endpoint abuse, nonce leakage, exfiltration channels CSP cannot block | Overlaps `wiki/71-xss-deep.md` CSP-bypass section |
| [`dependency-confusion`](https://github.com/yaklang/hack-skills/tree/main/skills/dependency-confusion) | npm/pip/gem/Maven/Composer/Docker manifest review for internal-package-name takeover via public registries | **Highest risk of accidental impact** — confirming this class can require publishing a proof-of-concept package to a public registry; get explicit program authorization and prefer namespace-registration-only verification, never a package with an actual payload |
| [`deserialization-insecure`](https://github.com/yaklang/hack-skills/tree/main/skills/deserialization-insecure) | Java `ObjectInputStream`, PHP `unserialize`, Python `pickle` → RCE/file-access/privesc | Overlaps `wiki/67-deserialization.md` |
| [`graphql-and-hidden-parameters`](https://github.com/yaklang/hack-skills/tree/main/skills/graphql-and-hidden-parameters) | Introspection, batching, undocumented fields, hidden parameters, schema abuse, GraphQL authz gaps | Overlaps `wiki/17-graphql-deep-attacks.md` |
| [`http-host-header-attacks`](https://github.com/yaklang/hack-skills/tree/main/skills/http-host-header-attacks) | Host-header-trusted URL generation, routing, access control — reset-poisoning, cache poisoning, SSRF-via-routing, vhost bypass | Overlaps `wiki/70-host-header-crlf.md` |
| [`http-parameter-pollution`](https://github.com/yaklang/hack-skills/tree/main/skills/http-parameter-pollution) | Duplicate query/body keys parsed differently by server/proxy/WAF/framework layers | Overlaps `wiki/69-mass-assignment-hpp.md` |
| [`idor-broken-object-authorization`](https://github.com/yaklang/hack-skills/tree/main/skills/idor-broken-object-authorization) | Object identifiers, tenant boundaries, writable fields, missing object-level authz | Pair with `bb-idor-coverage` (the read+write verb-matrix gate) and `wiki/77-idor-bola-bfla.md` |
| [`jwt-oauth-token-attacks`](https://github.com/yaklang/hack-skills/tree/main/skills/jwt-oauth-token-attacks) | Token trust, signing algorithms, key handling, claim abuse, bearer flows, OAuth account-binding weaknesses | Overlaps `wiki/31-jwt-attack-walkthrough.md` and `wiki/16-oauth-attack-chains.md` |
| [`mobile-ssl-pinning-bypass`](https://github.com/yaklang/hack-skills/tree/main/skills/mobile-ssl-pinning-bypass) | Certificate/public-key/SPKI pinning bypass — Android, iOS, React Native, Flutter, Xamarin | Mobile-app scope only |
| [`nosql-injection`](https://github.com/yaklang/hack-skills/tree/main/skills/nosql-injection) | MongoDB-style operators, JSON query objects, flexible search filters, backend query DSLs | Overlaps `wiki/72-sqli-deep.md` NoSQLi section |
| [`open-redirect`](https://github.com/yaklang/hack-skills/tree/main/skills/open-redirect) | URL params / form actions / JS sinks controlling navigation targets | Overlaps `wiki/78-open-redirect.md` (30+ bypasses) |
| [`prototype-pollution`](https://github.com/yaklang/hack-skills/tree/main/skills/prototype-pollution) | JS object-merge pollution — query parsers, JSON bodies, deep assign, library config | Overlaps `wiki/63-prototype-pollution.md` |
| [`prototype-pollution-advanced`](https://github.com/yaklang/hack-skills/tree/main/skills/prototype-pollution-advanced) | Server-side RCE escalation, client-side gadgets, filter bypasses, detection — companion to the base skill | Install alongside `prototype-pollution`, not instead of it |
| [`recon-and-methodology`](https://github.com/yaklang/hack-skills/tree/main/skills/recon-and-methodology) | Asset discovery, endpoint discovery, tech fingerprinting, structured testing-plan methodology | Overlaps `wiki/19-subdomain-recon-deep.md` and this framework's own `bb-surface-mapping` |
| [`request-smuggling`](https://github.com/yaklang/hack-skills/tree/main/skills/request-smuggling) | CL/TE desync across front-proxy/CDN/load-balancer boundaries, HTTP/2→1 translation, client-side desync | Overlaps `wiki/60-request-smuggling.md` — see that file's 2025 addendum for newer 0.CL / browser-powered-desync coverage this external skill may not yet have |
| [`saml-sso-assertion-attacks`](https://github.com/yaklang/hack-skills/tree/main/skills/saml-sso-assertion-attacks) | Signature validation, assertion wrapping, audience restrictions, ACS handling, XML trust boundaries | Overlaps `wiki/83-saml-oidc-attacks.md` |
| [`ssrf-server-side-request-forgery`](https://github.com/yaklang/hack-skills/tree/main/skills/ssrf-server-side-request-forgery) | URL-fetching / hostname-resolving / remote-import surfaces toward internal networks, cloud metadata, secondary protocols | Overlaps `wiki/66-ssrf-deep.md` |
| [`ssti-server-side-template-injection`](https://github.com/yaklang/hack-skills/tree/main/skills/ssti-server-side-template-injection) | Template expressions, SSR, preview features, templating engines evaluating attacker content | Overlaps `wiki/73-ssti-deep.md` |
| [`subdomain-takeover`](https://github.com/yaklang/hack-skills/tree/main/skills/subdomain-takeover) | Dangling CNAME/NS/MX → deprovisioned cloud resources, expired third-party services, unclaimed SaaS tenants | Overlaps `wiki/79-subdomain-cloud-takeover.md`; **claiming** a dangling resource to prove takeover is a write action — scope-check first |
| [`type-juggling`](https://github.com/yaklang/hack-skills/tree/main/skills/type-juggling) | PHP loose-equality (`==`) / numeric-coercion / hash-comparison bypass | Mostly legacy-PHP-specific; low hit rate on modern stacks |
| [`upload-insecure-files`](https://github.com/yaklang/hack-skills/tree/main/skills/upload-insecure-files) | Upload validation, storage paths, processing pipelines, preview behavior, overwrite risk, upload-to-RCE chains | Overlaps `wiki/62-file-upload-exploitation.md` |
| [`waf-bypass-techniques`](https://github.com/yaklang/hack-skills/tree/main/skills/waf-bypass-techniques) | Generic WAF evasion — encoding, protocol-level tricks, vendor-specific weaknesses | Overlaps `wiki/01-waf-bypass-playbook.md` and `wiki/14-waf-bypass-commands.md` |
| [`web-cache-deception`](https://github.com/yaklang/hack-skills/tree/main/skills/web-cache-deception) | CDN/reverse-proxy/app caching serving authenticated content to other users via path confusion or cache-key manipulation | Overlaps `wiki/64-cache-poisoning.md` |
| [`xss-cross-site-scripting`](https://github.com/yaklang/hack-skills/tree/main/skills/xss-cross-site-scripting) | HTML/attribute/JS/DOM-sink/upload/multi-context XSS | Overlaps `wiki/71-xss-deep.md` |
| [`xxe-xml-external-entity`](https://github.com/yaklang/hack-skills/tree/main/skills/xxe-xml-external-entity) | XML/SVG/OOXML/SOAP/parser-driven external-entity and internal-resource resolution | Overlaps `wiki/75-xxe-deep.md` |

That is 31 skills. Descriptions above are quoted from each skill's own `SKILL.md` frontmatter as of 2026-08-23 (fetched from `github.com/yaklang/hack-skills@main`) — re-verify if you install later, since upstream content is not version-pinned by this card.

## Overlap with this vault's own `wiki/`

Most rows above name an overlapping `09 - Knowledge Base/wiki/NN-*.md` file. That is intentional, not redundant: this vault's `wiki/` docs are the **operational, house-style version** (worked examples tied to this framework's tooling, safety gates, and evidence conventions — see `wiki/README.md`); the external skill is a second, independently-maintained source for the same technique. When they disagree, prefer your own judgment and current WAF/vendor behavior over either single source — both are static snapshots that go stale.

## Not included here (deliberately out of scope for this framework)

Active Directory / Kerberos / ADCS, OS privilege escalation (Linux/Windows/macOS), binary exploitation (heap/stack/kernel/ROP), reverse engineering, cryptography CTF attacks (RSA/lattice/symmetric/classical), blockchain/smart-contract, digital forensics (memory/pcap/steganography), and general network pivoting/tunneling. These are real upstream categories but sit outside this framework's web/API/cloud bug-bounty focus — install them yourself from `yaklang/hack-skills` if your engagement scope needs them (e.g. an internal pentest with AD in scope).

## Cross-References

- `README.md` § "Recommended external skill packs"
- `09 - Knowledge Base/Playbook - External Resource List to Skill Gap-Fill.md` — the general method this catalog was built with (ingest → graph → gap-analyze → backfill)
- `09 - Knowledge Base/wiki/README.md` — this framework's own first-party technique-depth index
- `bb-scope-safety-check` — the gate that governs whether you may act on a technique this external skill describes, regardless of what the external skill's own text says
