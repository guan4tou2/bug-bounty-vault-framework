---
type: checklist
title: "Attack Surface Coverage"
category: coverage
gate_type: soft
tags: [checklist, exploration, surface-mapping, coverage, bb-checklist]
status: verified
last_updated: 2026-06-03
---

# Checklist — Attack Surface Coverage (vuln-agnostic surface coverage, not pattern coverage)

> Guiding principle: measure whether the attack surface has been *thought through*, not whether a pattern scanner has been *run over it*. Hunters clean ≠ surface explored. This is the FLOOR — every dimension must be considered for every target, before pattern-matching.

This is the dimension-level FLOOR companion to the element-level "Attack Surface Map" produced during recon and in [[Playbook - Exploratory Surface Mapping]]. The Surface Map enumerates concrete elements; this checklist makes sure no DIMENSION is forgotten.

---

## 1. Inputs / Params

> "Anywhere data can be fed in is attack surface."

- [ ] Has every param on every endpoint been enumerated? (GET query, POST body, JSON key, header)
- [ ] Has `arjun` / param-miner been run to search for hidden / undocumented params?
- [ ] Are there client-side-only params? (fields assembled by JavaScript but never logged server-side)
- [ ] Are non-obvious delivery channels covered? (Cookie value, Referer, X-Forwarded-For, User-Agent, multipart field name)

---

## 2. Roles / Auth Matrix

> "Every access path only counts as considered once at least one role has exercised it."

- [ ] Are all roles in the system listed? (user / admin / guest / service account / API key)
- [ ] Has every cross-role access path been individually confirmed? (low-priv → high-priv, tenant A → tenant B)
- [ ] Are API key / token scope boundaries explicitly documented? (which operations a token can and cannot perform)
- [ ] Has it been verified that the same resource ID, accessed under a different role/tenant, triggers a fresh server-side authz check?

---

## 3. State / Multi-Step Flows

> "A flow is not one request — it's a chain of assumptions."

- [ ] Are all multi-step flows mapped? (checkout, MFA, email verify, password reset, onboarding)
- [ ] Has every step been tested for: skip, reorder, replay?
- [ ] Is there a race window? (what happens when the same request is sent × 2 / × 5 concurrently)
- [ ] Can an attacker directly access or abuse an intermediate state? (pending / partial)

---

## 4. Trust Boundaries

> "Every boundary is an assumption; every assumption might be a lie."

- [ ] Are all boundaries listed? (client ↔ server, service ↔ service, tenant ↔ tenant, CDN ↔ origin)
- [ ] What data does the server trust unconditionally? (IP, header, JWT claim, user-supplied metadata)
- [ ] Do internal services authorize each other, or do they rely purely on network isolation (assuming "internal = trusted")?
- [ ] Does the reverse proxy / load balancer have a header-laundering issue? (can `X-Forwarded-For` / `X-Real-IP` be spoofed?)

---

## 5. Integrations / Third-Party

> "Every webhook / callback URL is an externally-controllable exit."

- [ ] Are all external integrations mapped? (payment gateway, SMS provider, OAuth IdP, email service, webhook)
- [ ] Does the server-side fetch any user-supplied URL? (potential SSRF surface)
- [ ] Are webhooks / callbacks signature-verified? Can an attacker forge an event?
- [ ] Have third-party credentials (API key, secret) leaked to the client or into an error response?

---

## 6. Dependencies / Framework

> "Homegrown components are invisible to pattern libraries — dig into them first."

- [ ] Have all framework / library versions been fingerprinted? (HTTP header, error page, JS bundle, HTML comment)
- [ ] Which components are homegrown / non-standard? (custom auth, custom ORM, custom template engine) — homegrown = priority attack surface
- [ ] Are there outdated, EOL, or known-CVE dependencies? (`composer.lock`, `package-lock.json`, `requirements.txt`)
- [ ] Has the framework's "magic" behavior been exploited before? (Rails mass assignment, Laravel query injection, Spring EL injection)

---

## 7. Files / Uploads / Storage

> "Any byte a user can push into the system is attack surface."

- [ ] Are all upload entry points listed? (form upload, base64-in-JSON, multipart, avatar, import)
- [ ] Does the server-side fetch a file from a URL? (URL → server → storage; dual SSRF + path traversal surface)
- [ ] Does the storage bucket have a broken ACL? (publicly listable, anonymous write, overly long presigned URL)
- [ ] How are file paths handled? Any possibility of path traversal / symlink following?

---

## 8. Business Logic Flows

> "The code isn't broken, but the business assumption is wrong — this is what pattern scanners can't find."

- [ ] Has every value/quantity/price/limit field been asked: "what happens with negative, zero, huge, or float values?"
- [ ] For every "only an admin/other user can do this" action, has it been asked: "can a regular user bypass it?"
- [ ] Can discount / loyalty-point / quota logic be double-spent or raced?
- [ ] Is there a fuzzy boundary between "free tier" and "paid tier" functionality? (can downgraded accounts still access old resources?)

---

## Anomaly Sweep

> Every target has its own oddities. Pattern libraries are blind to them. List the oddities first, then decide how to dig.

- [ ] Any non-standard custom headers? (`X-Internal-Token`, `X-Debug-Mode`, `X-Request-Source`)
- [ ] Any non-standard auth mechanism? (custom token scheme, non-JWT/OAuth session, HMAC-in-query-string)
- [ ] Any self-built framework or heavily customized routing? (hand-rolled MVC, hand-rolled middleware chain)
- [ ] Any odd param naming convention hinting at an undocumented feature? (`_internal=1`, `debug=true`, `mode=legacy`)
- [ ] Any behavior differences that only appear under specific conditions? (IP range, User-Agent, time window, feature flag)

---

## Related

- [[Playbook - Exploratory Surface Mapping]]
- [[Lessons Learned]]

---

## Session-Mined Additions

- **Mandatory KB backfill step at session end:** before running the session-end checklist, confirm knowledge-capture has already happened (or manually backfill Lessons/Pattern/Checklist entries); skipping KB backfill should trigger a WARNING that doesn't block but does remind.
- **Quick-reference count reconciliation:** when reconciling counts, only take the findings rows (excluding header, attempts, and submissions rows); if `findings_total` differs from the findings row count by more than 2, trigger a manual recheck.
