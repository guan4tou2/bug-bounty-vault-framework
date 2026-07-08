---
name: bb-actuator-cloud-chain
description: Use when auditing exposed Spring Boot management endpoints (Actuator / Eureka / Jolokia / Nacos) for config/credential disclosure and, in cloud deployments, cloud-metadata reachability — the management-endpoint → config → cloud-metadata AUDIT chain (detect, validate, severity, writeup), distinct from generic SSRF and from batch debug-endpoint scanning. Triggers: actuator / X-Application-Context / eureka / nacos / jolokia / gateway routes / spring boot / cloud metadata / heapdump.
---

# Bug Bounty — Actuator/Nacos/Eureka → Cloud-Metadata Chain Audit

A consolidated audit checklist for the recurring "exposed Spring Boot management surface → config/credential disclosure → (cloud deployments) metadata exposure" misconfiguration class. This skill is the **orchestration/validation layer**. Framing is defensive/audit: find it, validate it's real, size the impact, write it up for the vendor — do not weaponize further than proof requires.

## Trigger

Any target running Java/Spring services (tech-stack fingerprint, an `X-Application-Context` header, Spring error pages, or a `spring-boot`/`spring-cloud` dependency in a JS/manifest scan), or any lead pointing at a management/admin API (`/actuator`, `/eureka/apps`, `/jolokia`, Nacos `:8848`, or a config-store hit mentioning `management.endpoints.web`). Also trigger after a web scan or a batch debug-endpoint sweep flags a candidate management endpoint — this skill takes over from "found a 200" to "validated + scoped + written up."

**Composes with `bb-version-cve-precheck`** (CVE-2022-22947 version window on Spring Cloud Gateway) — run that first if a version banner is available.

---

## Phase 1 — Fingerprint exposed management endpoints

What to look for:
- `X-Application-Context` response header on **any** path → a deterministic Spring Boot 1.x fingerprint. 2.x doesn't send it — absence is not evidence of absence.
- Default Actuator path `/actuator` (2.x) and legacy root-level endpoints (1.x, no prefix). Also sweep custom `base-path` guesses (`/manage`, `/monitoring`, `/mgmt`, `/admin`, vendor/app-name-derived paths) — **a custom base-path is a deliberate trap, not real protection**.
- `HTTP 405 Method Not Allowed` on a guessed path = the endpoint **exists**, wrong verb — retry with GET/POST before writing it off as 404.
- Behind an nginx/gateway prefix, the externally reachable path is `<gateway-prefix>` + `<management.base-path>` **composed**, not either alone.
- Eureka (`/eureka/apps`), Jolokia (`/jolokia/list`), Nacos console/API (`:8848/nacos/...`) as siblings of the same service-discovery stack.

How to validate:
- Confirm the response is genuine Actuator HAL-format JSON (a `_links` object) or a genuine Eureka/Jolokia/Nacos schema — a custom endpoint that merely echoes `null` or a bespoke JSON shape at a guessable path is a **false signal**, not a real management endpoint.
- If access requires auth and you get consistent 401/403 with no bypass on GET/HEAD/verb-tamper, treat it as hardened and move on — don't force it.

Severity floor: unauthenticated reachability of any genuine management endpoint (even health-only) = a baseline finding worth recording (≈P3/Medium at `health`-only).

---

## Phase 2 — Enumerate what each endpoint discloses

What to look for:
- `/env` (read env vars + masked secrets), `/heapdump` (a process heap dump — **bypasses masking**, contains plaintext creds), `/beans`, `/mappings`, `/nacos-config` (direct Nacos-backed config dump), `/gateway` + `/gateway/routes` (Spring Cloud Gateway route management).
- If a `gateway` link is present, check the two CVE-2022-22947 preconditions: `POST /gateway/routes/{id}` → 201, `POST /gateway/refresh` → 200. Both true = the SpEL-injection RCE path is confirmed (output is readable from `GET /gateway/routes` without triggering the route).
- `management.endpoints.jmx.exposure.include=*` in a leaked config only means JMX is exposed — it does **not** mean Jolokia is installed; verify `/jolokia` is independently reachable before claiming Jolokia RCE.
- If a SQLi (or direct API access) reaches a Nacos-backed `nacos_config.config_info` table, mine it by category: datasource, redis, rabbitmq/kafka, elasticsearch, jwt/oauth secrets, third-party api-key, and `management.endpoints.web.*` rows (which bootstrap Phase 1 on other services).
- Spring Boot 1.x: `/env` **POST** may be writable — but writes only take effect for a narrow set of live-reloaded properties (`logging.level.*`, some `management.*`); do not assume it can redirect a live Nacos/Eureka/Config-server connection — bootstrap-phase clients don't reconnect on a property change.

How to validate:
- Distinguish `swagger.host` (an externally reachable URL, worth pursuing) from `server.port` (an internal container port, meaningless without ingress mapping) when reading config dumps.
- For any endpoint hit, confirm the data is live/current, not a stale cached doc or a decommissioned service entry.

---

## Phase 3 — Assess disclosed config for secrets/credentials

What to look for: DB credentials (`spring.datasource.*`), cache/queue credentials (Redis/RabbitMQ/Kafka/Elasticsearch), JWT/OAuth signing secrets, third-party API keys, and any plaintext value that `/env` shows masked (`******`) but `/heapdump` reveals in the clear.

How to validate (read-only, non-destructive):
- Prefer a passive/read-only check over a live auth attempt where possible (e.g. decode+verify a JWT secret against a token you already legitimately hold, rather than forging new tokens; confirm a DB credential's *host reachability* without executing writes).
- Any live credential test must stay in scope and non-destructive — route it through a scoped out-of-band test host, never blind from the local machine.

Severity floor:
| Confirmed fact | Severity |
|---|---|
| Only `health`/`info` readable | Medium |
| `/env` readable (config disclosure) | High |
| `/env` writable | High |
| `/heapdump` yields plaintext creds | Critical |
| CVE-2022-22947 RCE confirmed | Critical |

---

## Phase 4 — Cloud deployments: metadata endpoint reachability

Only applies once you have RCE, or the leaked env/config shows the service runs on a cloud VM/pod. What to look for:
- `/env` or a k8s pod's environment already discloses internal `ClusterIP` topology (service names → IPs) **without needing RCE** — map it before assuming metadata access is the only path.
- From RCE (or an SSRF primitive), probe `metadata.google.internal` / `169.254.169.254`: `/computeMetadata/v1/instance/service-accounts/`, `/instance/hostname`, `/project/attributes/` — these can enumerate project/cluster/VPC topology **without any cloud API scope**.
- Check which service accounts are present — a bare GKE node's default compute SA token is typically `devstorage.read_only` only; do not assume broader IAM (Container/CRM/IAM APIs) is reachable without confirming.
- If a token is obtained, treat it as **long-lived** (GKE SA tokens can run ~1 year) — this changes the urgency language in the writeup regardless of scope.
- If the token's `devstorage.read_only` scope reaches a storage bucket with Terraform `apply_results/`, that can disclose full infra topology including a **second, otherwise-hidden cloud project**.
- Keep cluster `ClusterIP` ranges and private VM IPs mentally separate — they are two different network planes with different lateral-movement implications.

How to validate:
- Confirm token validity via a **read-only** introspection call (e.g. an OAuth `tokeninfo` endpoint) to see granted scopes — do not perform write/IAM-changing operations to "prove" impact.
- Escalate to Critical only with an actual token + a demonstrated read (e.g. a bucket listing) — "metadata reachable" alone is not Critical.

---

## Phase 5 — Severity/impact assessment + vendor writeup

- Cite the highest fact actually proven, not the theoretical ceiling.
- If the exposed instance is staging/pre-prod, explicitly reason about whether production shares the same config source (Nacos/shared image) and state that inference in the report rather than silently limiting scope.
- Conditional language unless dynamically verified: "may allow…", "static analysis indicates…" — never "confirmed RCE" without an executed PoC.
- No internal Finding IDs in the report body/title/CVSS; scrub any live tokens/PII captured during validation before they leave your notes.
- Remediation to recommend: `management.endpoints.web.exposure.include=health,info` (not `*`); base-path obscurity is not a control, pair with network-level auth; segment management ports off the public network; for cloud workloads, restrict metadata API reachability to workload-identity-bound pods; rotate any credential observed in plaintext immediately regardless of whether it was "just read."

---

## Cross-reference

- `09 - Knowledge Base/Pattern - SSRF.md` (SSRF confirmation without OOB, cloud-metadata path — the Phase-4 primitive) and `09 - Knowledge Base/Reference Card - External Skills Catalog.md` (the installed SSRF skill for the deeper IP-bypass / URL-parser-confusion mechanics).
- `bb-version-cve-precheck` (run first if a version banner exists — the CVE-2022-22947 window).
- `bb-exploit-chain` (once a finding lands, run the 6-question chain before moving to the next system).
- `bb-evidence-readiness` / `bb-submission-readiness` (before writing the Finding/Submission).
- `bb-dedup-finding` (the same root-cause exposure across sibling services = one Finding, not N).
- `bb-surface-mapping` (upstream — a batch debug-endpoint sweep hands its candidate management endpoints to this skill for validation).
