---
type: pattern
title: Pattern - GitLab Anonymous Fingerprinting (version + open-signup + info disclosures)
tags: [pattern, cwe-200, cwe-284, gitlab, fingerprint, info-disclosure, bb-pattern]
status: verified
first_seen: 2026-04-23
severity: P3 Medium (open signup) / P4 Low (version+info disclosures only)
---

# Pattern - GitLab Anonymous Fingerprinting

## TL;DR

Public-facing GitLab instances (even without `/users/sign_up` enabled) leak version + configuration intel via anon-accessible routes. When combined with open self-registration on internal R&D instances, severity jumps to **P3 Medium**. These are common misconfigurations across GitLab Enterprise / Community deployments that researchers often miss because most tooling focuses on authenticated GraphQL abuse.

## Exact version pinning (without auth)

### Primary: `/-/graphql-explorer`

GitLab's GraphQL IDE page is anon-accessible. Its inline bootstrapping JavaScript leaks:

```html
<script>
  window.gon = {
    current_user_id: null,
    revision: "5f9db3887f3",  // <-- exact Git revision
    gitlab_version: null,      // often null for EE
    ...
  };
</script>
```

The `gon.revision` is the exact GitLab source-tree commit. Cross-reference at:
```
https://gitlab.com/gitlab-org/gitlab/-/commit/<revision>
```
Returns the commit title (typically "Update VERSION files" for release commits) → pins exact version.

**Real case** (Example Vendor internal GitLab): `5f9db3887f3` → "Update VERSION files for 17.11.7-ee on 2025-08-14".

### Secondary fallbacks when `/-/graphql-explorer` is blocked

- `/help` — often leaks version in page header (`GitLab Community Edition 15.x`)
- `/api/v4/version` — anon-accessible by default on many deployments (returns `{"version": "...", "revision": "..."}`)
- `/-/metrics` — Prometheus metrics, may show version label (usually auth-gated but check)
- `/assets/webpack/*.chunk.js` — bundle hash is version-deterministic, can be cross-referenced via `gitlab-org/gitlab` release tags
- `robots.txt` pattern: older GitLab (<14) uses `/groups/*/analytics`, newer uses `/-/analytics`
- OIDC `/.well-known/openid-configuration` — `scopes_supported` changes across major versions:
  - 17.x adds: `manage_runner`, `self_rotate`, `read_virtual_registry`, `ai_workflows`, `user:*`
  - If absent → pre-17

## Open self-registration check

The single highest-impact misconfig. Check:

```bash
curl -skI https://TARGET/users/sign_up
# HTTP/2 200 = open signup
# HTTP/2 302 to /users/sign_in = registration DISABLED (good)
# HTTP/2 404 = registration route removed (best)
```

On internet-facing internal-R&D GitLab instances, this is **P3 Medium** — anyone can get a developer-class account on the vendor's source code platform.

## Anon info disclosures (always non-destructive, always worth checking)

### `/help/instance_configuration`

Leaks:
- SSH host-key fingerprints (MD5 + SHA-256 for ECDSA/ED25519/RSA) — useful for later MITM-claim authenticity
- GitLab Pages IP / CDN IPs
- Rate-limit configuration (unauth rate limits often shown as `- -` meaning unlimited)
- Backup / archive configuration (git repositories, uploads, LFS objects paths)

### `/-/jwks`

GitLab's public JWKS endpoint. Its presence confirms the instance has JWT configured for external identity federation (e.g., CI job tokens, Omniauth). Absent on minimal instances.

### `/explore/projects`

Language filter dropdown UI **leaks R&D tech stack** even if all projects are private. GitLab pre-populates the filter with languages present in internal+private projects. Observed (2026-04-23, rd3-gitlab): `Dockerfile, HTML, Java, JavaScript, SCSS, Shell, TSQL, Vue`.

### `/explore/groups`, `/explore/snippets`

May leak group names + public snippet content (if snippets are set to visibility=public). Empty on well-configured instances.

### `/api/v4/projects?visibility=public` / `?visibility=internal`

- Anon access is DEFAULT-ALLOWED on `visibility=public` (by design)
- `visibility=internal` (authenticated-users-only) — anon access should return empty; if it returns content, that's a major config bug
- Compare counts on both query strings to detect the bug

### `/api/v4/users`

Default: returns 403 for anon (good). If it returns 200 with a user list, user enumeration is trivial (bad).

### `/api/graphql` (GET shows IDE, POST works)

Anon GraphQL introspection is default-enabled on GitLab. Test:

```bash
curl -sk -H 'Content-Type: application/json' -X POST https://TARGET/api/graphql \
     -d '{"query":"{ __schema { types { name } } }"}'
# Returns full schema for anon callers
```

Not a direct vuln (introspection is by design) but enables reconnaissance of internal API surface.

## CVE matrix (as of 2026-04)

When version is pinned, cross-reference:

| CVE | CVSS | Affected ≤ | Class |
|-----|-----:|-----------|-------|
| **CVE-2023-7028** | **10.0** | 16.5.5 / 16.6.3 / 16.7.1 | Password-reset ATO via email header injection. **DO NOT TEST** in bounty context — triggers email sends |
| CVE-2024-6385 | 9.6 | 17.1.1 | Pipeline-arg RCE |
| CVE-2024-6678 | 9.9 | 17.3.2 | SSRF in CI webhooks (authenticated) |
| CVE-2024-9164 | 9.6 | 17.4.2 | Arbitrary branch push |
| CVE-2023-2825 | 10.0 | 16.0.0 | Path traversal allowing arbitrary file read |

**Ethical stop**: fingerprint + list applicable CVEs. Do NOT exploit in a recon context.

## Pre-submit checklist (non-destructive advisory)

- [ ] Version pinned via `gon.revision` + NVD cross-ref
- [ ] `/users/sign_up` tested (without registering)
- [ ] Info disclosures enumerated (/help/instance_config, /-/jwks, /explore, /api/v4/*)
- [ ] GraphQL introspection tested
- [ ] Severity honest: **open signup = P3**; version + info disclosures alone = P4-P5
- [ ] No actual registration, no password reset trigger, no clone of private repos

## Case studies

### Example Vendor rd-gitlab + rd3-gitlab (generic)

- `rd-gitlab.vendor-app.example.com`: GitLab EE **17.11.7-ee** (pinned via `gon.revision=5f9db3887f3`)
- `rd3-gitlab.vendor-app.example.com`: pre-17 EE (OIDC scopes lack post-17 additions)
- **Both `/users/sign_up` returned 200** → open public registration on internal R&D GitLab
- rd3 additionally leaks: SSH host keys + `/-/jwks` + `/explore/projects` language filter revealing `Vue/TSQL/SCSS/Dockerfile` private-project tech stack

Finding: [[Target - Example Vendor]] ACME-002.

## Related

- [[Pattern - Supply Chain Analysis]] — GitLab leaks often expose CI/CD infra
- [[Pattern - Source Map Exposure]] — source code recovery if GitLab assets are exposed
- [[Pattern - User Enumeration]] — `/api/v4/users` unauth access
- [[Target - Example Vendor]] — primary case study
