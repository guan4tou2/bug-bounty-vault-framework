---
type: playbook
title: "Harbor v2 Registry API Enumeration"
tags: [harbor, container-registry, api-enumeration, cve, docker]
status: draft
last_updated: 2026-08-12
category: hunting
estimated_time: "60-90 min"
---

# Playbook - Harbor v2 Registry API Enumeration

> This is a deep-dive that expands on a lighter Harbor registry recon pattern: that pattern gives a fast pre-auth-intel SOP, this playbook adds a systematic CVE-applicability table, the anonymous-to-private-image chain, the replication/webhook SSRF attack surface, and GET-first detection scripts.
>
> **Principle**: everything here is GET-first / read-only. Any push / write / config change is marked "**requires authorization**" and must never be triggered against an unauthorized target. Where CVE applicability is uncertain, it's marked "**needs version verification**".

---

## Scope / When to use

- Recon identifies a Harbor container registry (`/api/v2.0/systeminfo` returns `harbor_version`, the portal shows "Harbor" branding, or you see `Www-Authenticate: Bearer realm=.../service/token`).
- You've already confirmed the version but **have not yet done** a systematic CVE lookup + API enumeration (a common shortfall: stopping at "confirmed pre-auth project enumeration + anonymous JWT" without pushing further into image pull / SSRF).
- The goal is pushing "enumeration" toward "private image content disclosure / SSRF / privilege escalation".

---

## Phases

### Phase 1: Pre-Auth Endpoint Enumeration (GET-first, read-only)

Most of Harbor v2's `/api/v2.0/*` requires auth, but a few endpoints **are designed to allow anonymous access** (the response gets sensitive fields stripped). The Registry v2 protocol endpoints (`/v2/`, `/service/token`) also return error messages to anonymous callers and are the main enumeration workhorse.

| # | Endpoint | Method | Auth | Returns / purpose | Risk |
|---|----------|--------|------|---------------------|------|
| 1 | `/api/v2.0/systeminfo` | GET | anonymous OK (trimmed) | `harbor_version`, `auth_mode`, `self_registration`, `registry_url`, `external_url`, `project_creation_restriction`, storage provider | Version fingerprint + auth mode -> directly decides which CVE track to pursue |
| 2 | `/api/v2.0/health` | GET | anonymous OK | up/down status for core/database/jobservice/portal/redis/registry/registryctl/trivy | Internal component topology |
| 3 | `/api/v2.0/ping` | GET | anonymous OK | `Pong` | Liveness |
| 4 | `/api/v2.0/statistics` | GET | **requires auth** (anonymous sees nothing) | public/private project & repo counts | Private asset-scale disclosure (check once you have any account) |
| 5 | `/api/v2.0/projects` | GET | **requires auth** (anonymous usually 401 / public-only) | Project list (metadata, public flag) | Full enumeration once you have an account |
| 6 | `/api/v2.0/projects?name=<x>` | GET | Partially probeable anonymously | Name filter | Existence oracle (complements #11) |
| 7 | `/v2/` | GET / HEAD | anonymous (returns 401 + header) | `Www-Authenticate: Bearer realm="https://<internal>/service/token"` | **Internal / dev-platform hostname disclosure** (the realm is often an internal host) |
| 8 | `/v2/_catalog` | GET | Usually requires auth; older/misconfigured deployments may allow anonymous | Full repo directory | If misconfigured = a full registry map (report directly) |
| 9 | `/service/token?service=harbor-registry&scope=...` | GET | anonymous OK | Issues a JWT (anonymous: `access: []`, no permissions) | Token-behavior oracle; scope differences hint at what exists |
| 10 | `/v2/<project>/<repo>/tags/list` | GET | requires token | tags (with permission) / unauthorized (without) | Same existence oracle as #11 |
| 11 | `/v2/<project>/<repo>/manifests/<ref>` | GET | requires token | manifest (with permission) | **Entry point for private image pull** (see Phase 3) |

#### Run the full pre-auth fingerprint in one pass

```bash
T="https://<target>"
# Version + auth mode + self-registration (highest value)
curl -sk "$T/api/v2.0/systeminfo" | jq '{harbor_version, auth_mode, self_registration, registry_url, external_url, project_creation_restriction, has_ca_root}'

# Component health
curl -sk "$T/api/v2.0/health" | jq '.components[] | {name, status}'

# Token-service realm (internal hostname disclosure)
curl -sk -I "$T/v2/" | grep -i www-authenticate

# Anonymous catalog (only returns 200 when misconfigured)
curl -sk "$T/v2/_catalog" | jq . 2>/dev/null || echo "catalog locked (expected)"
```

> `self_registration: true` combined with `auth_mode: db_auth` is a high-value combination (self-service account creation -> an authenticated view -> unlocks #4/#5/#8 and most auth-required BOLA surface). **Confirm the target is in scope and self-registration is authorized before creating an account.**

---

### Phase 2: Known-CVE Applicability Check

> ⚠️ **Important**: treat any version snapshot below as an example, not a permanent truth — Harbor ships frequent security fixes, and most pre-2024 CVEs are patched in recent releases. Check each CVE's fixed-in version individually, **never assume an old CVE still applies**. The table below illustrates the applicability-check methodology against an example version (v2.11.0, a 2024-era release); any row you actually intend to test must be **re-verified against the target's live version** first (the `harbor_version` field returned by `systeminfo` can also be spoofed/rewritten by a proxy).

| CVE | Type | Affected versions | Fixed-in | Applicable to the example version (v2.11.0)? | Precondition | Impact |
|-----|------|---------------------|----------|-------------------------------------------------|---------------|--------|
| CVE-2022-46463 | Unauthorized image pull (access-control / "by design") | v1.x - v2.5.3 | v2.5.4+ | No (patched — re-verify against target version) | None (anonymous) | Anonymous read + pull of public and private repos |
| CVE-2019-16097 | Zero-to-admin privilege escalation (`has_admin_role` injection) | 1.7.0 - 1.8.2 | 1.7.6 / 1.8.3 | No (far below range) | `db_auth` + `self_registration=true` | Any self-registered user can create an admin account -> full control |
| CVE-2020-13788 | Restricted SSRF (webhook Test Endpoint internal port scan) | <= v1.10.2 | v1.10.3 | No (patched) | **project admin** (requires an account / authorization) | Internal TCP port probing |
| CVE-2022-31668 | Unauthorized push (P2P preheat) | v2.x early | see advisory | Needs version verification | Depends on config | Unauthorized push (**requires authorization to test**) |
| CVE-2023-20902 | Timing attack (robot-account job-task authorization) | <= v2.8.2 range | v2.8.3 etc. | Mostly patched | robot account | Unauthorized job-task actions |
| CVE-2024-22278 | BOLA / IDOR (project metadata API) | < 2.9.5; 2.10.0-2.10.2 | 2.9.5 / 2.10.3 / v2.11.0 | No — patched by the example version | **Maintainer role** (requires an account) | Maintainer can modify project metadata (flip to public / evade scanning) |
| Open redirect (public advisory) | Open redirect | see advisory | see advisory | Needs version verification | None | Redirect (low; may chain into OAuth/OIDC) |
| Various IDOR findings (multiple, 2022) | Multiple IDORs (including cross-project robot-account updates) | <= v2.5.1 | v2.5.2+ | No (patched) | Low-privilege account | Cross-project object manipulation |

**Practical takeaway for a recent version**:
- The well-known "anonymous -> private image" CVE-2022-46463 and "zero-to-admin" CVE-2019-16097 are **long since patched** in current releases — don't report them as live findings without verifying the actual target version.
- What's actually left pre-auth on a current version is **info disclosure / existence enumeration / internal hostname leakage** (Phase 1, Phase 4), plus **misconfiguration** (anonymous `_catalog`, sensitive images inside a public project, `self_registration` left open).
- Any "requires auth / requires an account" BOLA / SSRF / push CVE needs a legitimate test account first (self-registration, or one issued by the program), and the write/push step is **always marked as requiring authorization**.

---

### Phase 3: Anonymous -> Private Image Content Chain (detection approach)

Goal: determine whether an anonymous or low-privilege view can read image content it **should not** be able to. On a current version this is usually the result of **misconfiguration** rather than a core CVE (CVE-2022-46463 is patched).

```
[step 1] systeminfo confirms version / auth_mode          <- GET, anonymous
   |
[step 2] /v2/ gets the token realm                         <- GET, anonymous
   |
[step 3] /service/token gets an anonymous JWT               <- GET, anonymous
   scope=repository:<project>/<repo>:pull
   | (anonymous: access:[] = no permission, expected)
[step 4] Existence enumeration: compare "not found" vs "unauthorized"  <- GET (see Phase 4)
   | confirm which projects exist
[step 5] test whether a public project's manifest/config/layer contains anything sensitive
   curl with the anonymous token: GET /v2/<proj>/<repo>/manifests/latest
   -> 200 = readable (a finding if the repo should be private; not reportable if public-by-design)
   |
[step 6] if the manifest is readable -> get the config blob digest -> GET /v2/<proj>/<repo>/blobs/<digest>
   -> image config (env vars / labels / possible secrets) = high value (read-only, no `docker pull` needed)
```

**Reportability threshold (anti-overclaim)**:
- A public project / a public-by-design image being readable is **expected behavior, not reportable** (same logic as "public-by-design isn't a finding").
- Only report when a **repo marked private, or a manifest+blob that should not be public, is readable from an anonymous or unrelated account's view**. Before submitting, ask "what does the attacker actually end up with": a CA certificate / a public base image -> don't report; a private image's config containing secrets / an internal image inventory -> report.
- Use the raw registry HTTP API (curl GET) throughout — **`docker pull` is not necessary** and avoids unnecessary traffic. `docker push` / a blob PUT is a write and **requires authorization**; never trigger it against an unauthorized target.

---

### Phase 4: Existence Enumeration Oracle (CWE-204, pre-auth)

Registry v2 returns **different errors** for "an existing private project" vs. "a non-existent project":

```bash
TOK=$(curl -sk "$T/service/token?service=harbor-registry&scope=repository:probe/x:pull" | jq -r .token)

# Existing project (no permission) -> "unauthorized to access repository"
curl -sk "$T/v2/<project>/app/tags/list" -H "Authorization: Bearer $TOK"

# Non-existent -> "project <x> not found"
curl -sk "$T/v2/<nonexist>/app/tags/list" -H "Authorization: Bearer $TOK"
```

- This confirms **whether a project exists**; repo names inside a project usually cannot be enumerated this way (any repo name returns "unauthorized").
- A useful project-name wordlist to seed enumeration: `test dev staging production release build deploy library internal public private default admin base infra tools app web api backend frontend`, plus target-specific business keywords / company abbreviations / product codenames.

---

### Phase 5: SSRF / Replication / Webhook Attack Surface (requires authorization)

Harbor's outbound-fetch components are the main SSRF surface, but they **all require authentication + project-admin or system-admin**, and the historical SSRF CVE (CVE-2020-13788) is patched in current releases. Treat this as "a deep-dive direction once you already have a sufficiently privileged account", not pre-auth surface.

| Surface | Endpoint / feature | Required role | SSRF angle | Note |
|---------|----------------------|-----------------|-------------|------|
| Webhook Test Endpoint | `POST /projects/{id}/webhook/policies` + test | project admin | Point the endpoint URL at an internal address / metadata endpoint (169.254.169.254) for blind SSRF / port scanning | **Requires authorization**; CVE-2020-13788 is patched, re-verify residual behavior on current versions |
| Replication adapter | `POST /replication/adapters` probing / `/replication/policies` setting a remote registry URL | system admin | Remote registry URL -> internal / metadata fetch | **Requires authorization**; mostly admin-only, ROI depends on reaching admin |
| Proxy Cache project | Proxy-cache remote-registry URL | project admin | Remote endpoint -> internal fetch | **Requires authorization** |
| Scanner adapter (Trivy/Clair) | Scanner registration URL | system admin | Adapter URL SSRF | **Requires authorization** |
| Robot account | `POST /robots` / `PUT /robots/{id}` | project / system admin | Cross-project unauthorized updates (an older class of IDOR, patched in recent releases) | Already patched in current versions — note it for comparison, don't re-report |

GET-first rule: SSRF testing triggers outbound requests — confirm in-scope + authorization + no impact to third parties before testing; use a self-controlled OAST/collaborator endpoint for blind SSRF, **never probe a third party's internal network**. Any POST that creates a webhook/replication policy is a write and **requires authorization**.

---

### Phase 6: Authenticated-View Unlock (once you have an account)

If `self_registration: true` (or the program issued an account), log in and test further:

```bash
# Full project list (with metadata)
curl -sk -u "$U:$P" "$T/api/v2.0/projects?page_size=100" | jq '.[] | {name, metadata}'
# Global statistics
curl -sk -u "$U:$P" "$T/api/v2.0/statistics" | jq .
# Repos visible to this account
curl -sk -u "$U:$P" "$T/api/v2.0/projects/<proj>/repositories" | jq '.[].name'
# Default-credential test (Harbor's known default admin credential)
curl -sk -u 'admin:Harbor12345' "$T/api/v2.0/users/current" | jq .
```

Further directions to pursue (all require in-scope confirmation; writes are marked as requiring authorization): BOLA — use a low-privilege account to try operating on another project's object IDs (metadata / robot / member); reading another project's private repo without permission; OIDC redirect (`/c/oidc/login`, compare against the open-redirect advisory).

---

### Phase 7: Also Check — Direct Docker Daemon Access

```bash
for port in 2375 2376 5000 4443 8080; do
  timeout 3 bash -c "echo > /dev/tcp/<target>/$port" 2>/dev/null && echo "OPEN: $port"
done
# 2375 open + unauthenticated -> direct Docker API access (RCE-class); start with read-only GET /version /info
curl -sk "http://<target>:2375/version" | jq . 2>/dev/null
```

---

## Decision Points

- Version: **verify `harbor_version` dynamically** via `systeminfo` and compare against the current vendor-supported release; always check the fixed-in version for any older CVE before assuming it applies.
- Three-question check before submitting: what does the attacker actually get / is this the default (design) behavior (public project, token-realm disclosure by design)? / what's left once you strip out the theoretical parts?
- Token-realm disclosure of an internal hostname is info disclosure (usually a lower-severity finding) — don't inflate it into RCE.
- Only private-image content disclosure rises to High severity; public-by-design content is not reportable.
- Write / push / webhook / replication actions are always marked **requires authorization**; never trigger them against an unauthorized target.
- Check existing findings for the target before opening a new one, to avoid duplicate submissions.

---

## Expected Outputs

- Version + auth-mode fingerprint (`systeminfo`, `health`) with CVE-applicability determination per known CVE.
- Internal/dev hostname disclosure from the token realm, if present.
- A confirmed project-existence list from the CWE-204 oracle.
- A private-image-content-disclosure finding (manifest + blob evidence) if the anonymous/low-privilege chain succeeds, or a documented negative result if it doesn't.
- A documented SSRF/replication/webhook attack-surface assessment marked "requires authorization" for any part not yet tested.
- A direct-Docker-daemon exposure check result.

---

## Sources

- Harbor systeminfo anonymous behavior: https://github.com/goharbor/harbor/issues/9149
- Harbor v2.0 API swagger (endpoint list): https://github.com/goharbor/harbor/blob/main/api/v2.0/swagger.yaml
- SysteminfoApi documentation: https://container-registry.com/docs/harbor-api-client/api/systeminfoapi/
- Harbor REST API overview: https://goharbor.io/docs/2.5.0/working-with-projects/using-api-explorer/
- CVE-2022-46463 (unauthorized image pull) NSFOCUS: https://nsfocusglobal.com/harbor-unauthorized-access-vulnerability-cve-2022-46463-alert/
- CVE-2022-46463 cvedetails (affected version range v1.x-v2.5.3): https://www.cvedetails.com/cve/CVE-2022-46463/
- CVE-2022-46463 PoC: https://github.com/404tk/CVE-2022-46463
- CVE-2019-16097 (zero-to-admin) Unit42: https://unit42.paloaltonetworks.com/critical-vulnerability-in-harbor-enables-privilege-escalation-from-zero-to-admin-cve-2019-16097/
- CVE-2019-16097 advisory (fixed 1.7.6/1.8.3): https://github.com/goharbor/harbor/security/advisories/GHSA-fqvr-xx6w-m6m7
- CVE-2020-13788 (webhook SSRF) advisory: https://github.com/goharbor/harbor/security/advisories/GHSA-33p6-fx42-7rf5
- CVE-2020-13788 Miggo summary: https://www.miggo.io/vulnerability-database/cve/CVE-2020-13788
- CVE-2023-20902 (robot timing attack): https://www.cve.news/cve-2023-20902/
- CVE-2024-22278 (BOLA project metadata, fixed 2.9.5/2.10.3/2.11.0) Unit42: https://unit42.paloaltonetworks.com/bola-vulnerability-impacts-container-registry-harbor/
- CVE-2024-22278 GitLab advisory: https://advisories.gitlab.com/pkg/golang/github.com/goharbor/harbor/CVE-2024-22278/
- IDOR findings series (2022, <=v2.5.1): https://www.infosecurity-magazine.com/news/oxeye-idor-vulnerabilities-harbor/
- Harbor open redirect advisory: https://github.com/goharbor/harbor/security/advisories/GHSA-5757-v49g-f6r7
- goharbor security advisories index: https://github.com/goharbor/harbor/security/advisories
- CVE-2022-31668 GitLab advisory: https://advisories.gitlab.com/pkg/golang/github.com/goharbor/harbor/src/CVE-2022-31668
- Help Net Security (2022 high-severity Harbor vulnerabilities): https://www.helpnetsecurity.com/2022/09/19/vulnerabilities-harbor-open-source-artifact-registry/

---

## Related

- `ssrf-server-side-request-forgery` skill — general replication/webhook SSRF technique
- `idor-broken-object-authorization` skill — authenticated BOLA deep-dive
- `bb-version-cve-precheck` skill — version + CVE pre-check before hands-on work
- `bb-dedup-finding` skill — deduplication before opening a Finding
