---
type: reference
category: checklist
tags: [checklist, ai, llm, saas, unauthenticated, endpoint, prompt-leak, memory, k8s, api-key]
last_updated: 2026-06-04
source: "Two independent AI SaaS vendor sessions both found unauthenticated AI-specific endpoints; pattern not operationalized in any existing checklist"
related_pattern: "AI LLM MCP Security"
---

# Checklist -- AI LLM SaaS Unauthenticated Endpoints

> **Problem**: AI SaaS platforms typically have an additional attack surface layer compared to traditional SaaS: skill/prompt systems, memory APIs, RAG tool routing, and agent orchestration endpoints. If these endpoints lack proper authentication, they can leak system prompts, user documents, K8s topology, or allow memory poisoning.
>
> **Two independent sessions (across different AI SaaS vendors) both found this type of endpoint**, confirming this pattern's cross-vendor reproducibility, making it worth operationalizing as a fixed checklist item.
>
> **When to use**: The target is an AI/LLM SaaS, or any backend service with path characteristics like "/skills/", "/agent/", "/memory/", "/registry/".
>
> **Pre-test requirement**: First obtain any legitimate API key (even free / trial tier). The testing logic is the diff between "no key" vs "with key", not blind unauthenticated requests.

---

## High-Risk Endpoint List (ordered by testing priority)

### 1. `/skills/v1`, `/skills/list` -- AI Skill System Prompt Leakage

**Risk**: Unauthorized disclosure of system prompts, tool descriptions, and function schemas. Exposes agent behavioral logic, which can assist prompt injection attacks.

**Test commands**:

```bash
# Unauthenticated
curl -s "https://api.target.com/skills/v1" | jq .
curl -s "https://api.target.com/skills/list" | jq .

# Compare with API key response
curl -s -H "Authorization: Bearer $API_KEY" "https://api.target.com/skills/v1" | jq .
```

**Hit signals**:
- Response contains `system_prompt`, `instructions`, `description` fields with substantive content
- Response structure is identical with and without key (no authorization difference)
- Response lists tool function schemas (e.g., `parameters`, `required` fields)

**Root cause assessment**: Confirm whether the routing layer completely lacks auth middleware (not a scope issue, but a full layer bypass).

---

### 2. `/history/v1/user/file-sessions` -- User File Session List + Presigned URLs

**Risk**: Leaks other users' uploaded file session lists; if the response contains presigned URLs, attackers can directly download file contents.

**Test commands**:

```bash
# Unauthenticated -- check if session list is returned directly
curl -s "https://api.target.com/history/v1/user/file-sessions" | jq .

# With your own account's token, then manually remove token and retry
curl -s -H "Authorization: Bearer $VALID_TOKEN" \
  "https://api.target.com/history/v1/user/file-sessions" | jq '.[0]'
```

**Hit signals**:
- Response contains `session_id`, `file_name`, `presigned_url`, `s3_key`, `blob_url`
- Without token, you can access others' sessions (not just your own)
- Presigned URL validity > 1 hour

**Note**: If you obtain presigned URLs, record the URL structure only -- **do not actually download others' files** (GET-first principle, file contents may contain PII).

---

### 3. `/registry/v1/services` -- K8s Service List

**Risk**: Leaks internal microservice names, ClusterIPs, ports, and health status. Can be used to map internal network topology, serving as prerequisite knowledge for further SSRF.

**Test commands**:

```bash
curl -s "https://api.target.com/registry/v1/services" | jq .
curl -s "https://api.target.com/v1/registry/services" | jq .
curl -s "https://api.target.com/services" | jq .
```

**Hit signals**:
- Response contains `service_name`, `cluster_ip`, `port`, `namespace`
- RFC-1918 addresses appear: `10.x.x.x`, `172.16.x.x`, `192.168.x.x`
- Contains DSN fragments like `redis://`, `postgres://`, `rabbitmq://`

**Rationale**: Kubernetes service discovery endpoints that lack both network-level and auth-level dual-layer protection are easily leaked from public API gateways.

---

### 4. `/api/keys`, `/auth/keys`, `/v1/keys` -- Self-Service API Key Issuance Endpoints

**Risk**: If an endpoint can issue API keys without authentication or at low privilege, attackers can self-issue high-privilege keys or enumerate existing keys.

**Test commands**:

```bash
# Enumerate
curl -s "https://api.target.com/api/keys" | jq .
curl -s "https://api.target.com/v1/keys" | jq .

# Attempt creation (GET first, POST only after confirming scope)
curl -s "https://api.target.com/api/keys/create" | jq .
```

**Hit signals**:
- Unauthenticated GET returns key list (containing `key_id`, `prefix`, `created_at`)
- POST creation endpoint doesn't validate session, directly returns `api_key` field
- Issued key has higher scope than the originating account

**Stop-loss**: If it's just a UI-layer "application page" returning 200 (requiring manual review), it's not a vulnerability. Must confirm whether the server actually issues a valid key.

---

### 5. `/metrics`, `/health`, `/jobs`, `/sessions` -- Observability Paths

**Risk**: Leaks Redis IP/port, job UUIDs, worker status, queue depth, internal service DSNs.

**Test commands**:

```bash
# Try common observability paths
for path in /metrics /health /healthz /ready /jobs /sessions /workers /queue /status; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://api.target.com$path")
  echo "$code $path"
done

# Expand on hits to see content
curl -s "https://api.target.com/metrics" | grep -E "(redis|postgres|rabbit|job_|session_)"
curl -s "https://api.target.com/jobs" | jq '.[0]'
```

**Hit signals**:
- `/metrics` returns Prometheus format (`# HELP`, `# TYPE` lines) with DSN labels
- `/jobs` returns job UUID lists (can be used to infer user activity)
- `/health` contains sub-service check results, exposing `redis://host:6379`, `amqp://` addresses

**Note**: `/health` returning only `{"status":"ok"}` is not a leak; must contain substantive architectural information to qualify.

---

### 6. All 4xx / 5xx Error Responses -- RAG Tool Names & Internal Architecture Collection

**Risk**: Error responses leak RAG tool names (`tool_name`), agent organization (`agent_org`), stack traces, and internal package paths.

**Test commands**:

```bash
# Send malformed requests to legitimate endpoints, observe error detail level
curl -s -X POST "https://api.target.com/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{"model":"","messages":null}' | jq .

# Try accessing nonexistent skill/agent IDs
curl -s "https://api.target.com/skills/v1/NONEXISTENT_SKILL_12345" | jq .
curl -s "https://api.target.com/agents/org/NONEXISTENT_ORG" | jq .

# Send malformed session IDs
curl -s "https://api.target.com/history/v1/user/file-sessions/INVALID_SESSION" | jq .
```

**Hit signals**:
- Error response contains `tool_name`, `skill_name`, `rag_source`, `retriever`
- Contains `org_id`, `agent_org`, `workspace_id` (usable for IDOR testing)
- Stack trace or `detail` field reveals internal frameworks (LangChain, LlamaIndex, Weaviate)
- 400 response body > 500 bytes with nested JSON structure (Ignition/debug page similar characteristics)

**Method**: Systematically traverse all discovered endpoints, sending malformed requests to each one; don't just try a random few.

---

### 7. `/memory/v1/*` -- AI Memory CRUD Endpoints (Three-Dimensional Impact)

**Risk**: If AI memory systems lack proper authz, they can cause:
1. **Memory Poisoning**: Attacker writes malicious memories, influencing AI's future responses (persistent form of prompt injection)
2. **Memory Exfiltration**: Read other users' memories (containing PII, preferences, conversation summaries)
3. **Memory DoS**: Batch-write invalid memories, consuming user quota or causing AI response degradation

**Test commands**:

```bash
# Enumerate your own account's memories
curl -s -H "Authorization: Bearer $VALID_TOKEN" \
  "https://api.target.com/memory/v1/memories" | jq .

# Remove token and retry (IDOR -- can you read others' memories without auth)
curl -s "https://api.target.com/memory/v1/memories" | jq .

# Attempt to read a specific user's memories (substitute user_id)
curl -s -H "Authorization: Bearer $VALID_TOKEN" \
  "https://api.target.com/memory/v1/user/OTHER_USER_ID/memories" | jq .

# Attempt write (GET-first; only evaluate POST execution after confirming endpoint exists)
# If write testing is needed, first confirm scope allows it and cleanup method exists
curl -s -X POST "https://api.target.com/memory/v1/memories" \
  -H "Authorization: Bearer $VALID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content":"test memory entry for security testing"}' | jq .
```

**Hit signals**:
- Can read memory list without token
- Has token but can read another `user_id`'s memory (IDOR)
- Written memory affects AI responses for other users in the same session

**Classification**:
- Unauthenticated read -> Information Disclosure
- Cross-user read -> IDOR
- Cross-user write -> Memory Poisoning (must clearly state exploitable impact in report, don't exaggerate)
- DoS -> Evaluate program policy (some BB platforms don't accept DoS)

---

## Testing Methodology

### Basic Test Matrix (execute for each endpoint)

| Test | Command Pattern | Observation Focus |
|------|----------------|-------------------|
| Unauthenticated access | `curl -s "URL"` | HTTP 200 + substantive data |
| Valid token access | `curl -H "Authorization: Bearer $TOKEN" "URL"` | Establish baseline |
| Token diff comparison | User A token vs User B token | Any cross-user data? |
| No-token vs with-token diff | `diff <(curl URL) <(curl -H "Auth" URL)` | If identical = no auth protection |
| Malformed request error collection | Send `null`, empty body, wrong ID | Error response information volume |

### Path Naming Variants (don't just try one path pattern)

```
/skills/v1          /v1/skills          /api/v1/skills
/skills/list        /skills             /skill
/history/v1/...     /api/history/...    /v1/history/...
/registry/v1/...    /service-registry   /services
/memory/v1/...      /memories           /api/memories
/metrics            /prometheus/metrics /actuator/prometheus
/jobs               /job                /queue/jobs
```

### Permission Level Confirmation (three steps)

1. **Unauthenticated GET** -- Is the HTTP code 200 or 401/403?
2. **Invalid token GET** -- Send `Authorization: Bearer invalid_token` to the same endpoint, is the response the same as no token? (indicates token is not validated at all)
3. **Cross-account GET** -- Use Account A's token to attempt accessing Account B's resources (IDOR test)

If step 1 = 200 -> directly confirmed unauthenticated access.
If step 1 = 401 but step 2 also = 200 -> token validation not properly implemented.
If step 3 = Account B data -> IDOR.

---

## Stop-Loss Points (situations that should NOT be reported)

- `/health` only returns `{"status":"ok","uptime":12345}` -- no substantive architectural information
- `/skills/list` only returns public skill names (no system prompt content, consistent with what the unauthenticated UI shows) -- publicly allowed information by design
- `/metrics` only has aggregate counts (request count, latency p99), no DSN or IP -- not a leak
- Self-service API key requires email verification or manual review process -- not unauthorized issuance
- Memory endpoint requires valid token and can only read your own data -- normal design

---

## Report Writing Notes

1. **Anti-exaggeration**: "Attacker can read RAG tool names" and "attacker can control AI behavior" are two different things -- state them separately.
2. **Evidence requirements**: `live` evidence requires actual screenshots (including response body); you cannot just say "theoretically accessible."
3. **IDOR vs Unauth Access**: IDOR (authenticated but cross-user) and Unauthenticated Access (no authentication) are different root causes -- **do not combine into one report** (different remediation directions).
4. **Memory Poisoning impact**: The report must show screenshots of AI response actually changing after memory injection to upgrade from "theoretical" to "verified."

---

## Related

- [[Pattern - AI LLM MCP Security]]
- [[Checklist - Attack Surface Coverage]]
- [[Checklist - Web Vuln Technique Coverage]]
- [[Lessons Learned]] -- Lesson #51 (IAM read endpoints are the first step in privilege escalation chains), #52 (Observability/admin endpoints are authentication blind spots in cloud services)
