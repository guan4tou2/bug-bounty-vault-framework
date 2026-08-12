---
type: reference-card
title: "GET-first / Dangerous-Ops Boundary"
tags: [safety, methodology, incident, vps, http-methods]
status: draft
last_updated: 2026-08-12
---

# Reference Card - GET-first Dangerous Ops

> **TL;DR**: A hard boundary for which HTTP methods and operations may be executed directly during testing versus which require explicit confirmation of consequences first. Grounded in a real incident: probing a Tomcat WebModule lifecycle MBean through an exposed Actuator/Jolokia endpoint and executing a `stop` operation caused a production outage of 9+ hours affecting multiple downstream customers. The root cause was executing a write/exec-class request without first confirming its consequences.

## Quick Reference

**Core rule: default to GET. POST / PUT / PATCH / DELETE must never be executed until the consequences are known with certainty.**

| HTTP method | Default behavior | Execution condition |
|---|---|---|
| `GET` / `HEAD` / `OPTIONS` | ✅ Execute directly | No extra confirmation needed |
| `POST` — read-only semantics (search / query / list) | ✅ May execute | Confirm it is purely a query with no side effects |
| `POST` — write/trigger semantics (create / exec / action / lifecycle) | ⚠️ Pause | **Consequences must be fully known first; execute only from an isolated VPS, never the local machine** |
| `PUT` / `PATCH` — partial update | ⚠️ Pause | **Consequences must be fully known first; execute only from an isolated VPS** |
| `DELETE` — deleting test data you created yourself | ⚠️ Caution | Only if you can confirm it is a resource you just created |
| `DELETE` — deleting any pre-existing data | ❌ Forbidden | **Never execute, no exceptions** |

### The "consequences fully known" test

> You may only execute the request if you can answer "what happens in production if this request succeeds?" — and the answer is **reversible or harmless**.

### Worked examples by method

| Example | Verdict | Reasoning |
|---|---|---|
| `POST /actuator/jolokia` read attribute | ✅ | Pure read, no side effect |
| `POST /api/items` creating a record with a test account | ✅ (VPS only) | Creates a disposable test record; consequence is known |
| `POST /actuator/jolokia` exec `stop` | ❌ | Can stop a production service — this is the real incident described above |
| `POST /gateway/refresh` | ❌ | May trigger SpEL evaluation server-side; consequence unknown |
| `PUT /api/user/profile` | ⚠️ | Confirm blast radius first, execute only from VPS |
| `PATCH /api/config` | ⚠️ | Confirm field semantics first, execute only from VPS |
| `DELETE /api/items/{uuid}` for a resource you just created | ⚠️ (caution) | Only if you can confirm it's your own just-created test resource |
| `DELETE /api/users/123` | ❌ | Deletes someone else's data — never execute |
| `DELETE /artifact/v1/files/{uuid}` | ❌ | Permanently deletes a production storage object with no undo |
| `DELETE bulk` / `truncate` / `drop` | ❌ | Batch and/or irreversible — never execute |

## Details

### Workflow when a POST/PUT/PATCH/DELETE outcome is uncertain

1. **Pause** — never send it just out of curiosity to "see what happens"
2. Use `GET` first to read related documentation, Swagger/OpenAPI specs, or endpoint descriptions to understand semantics and blast radius
3. Record it: `endpoint — consequence unconfirmed, not executed`
4. If the consequence turns out to be acceptable → **execute only from an isolated VPS** (never the local/home network); if still uncertain → record it as a finding without ever triggering it live

### Operations that are never executed, under any circumstances

- Any operation whose name contains `stop` / `destroy` / `shutdown` / `kill` / `restart`
- `DELETE` on any resource you did not just create yourself
- Batch operations (bulk delete / truncate / drop / purge / wipe)
- Any endpoint that sends email / SMS / push notifications to real users
- Any operation where you'd need to "just try it and see" to know the outcome — **uncertainty means do not execute**

### Case study — the incident behind this rule (never run this class of command)

```bash
# ❌ This exact request pattern caused a 9+ hour outage on a production host
curl -X POST https://target-host.example.com/actuator/jolokia \
  -d '{
    "type": "exec",
    "mbean": "Tomcat:J2EEApplication=none,J2EEServer=none,j2eeType=WebModule,name=//localhost/",
    "operation": "stop",
    "arguments": []
  }'
# Cause: the "stop" operation's semantics were not confirmed before execution.
# A Tomcat WebModule "stop" operation shuts down the entire web application.
# Correct procedure: GET /actuator/jolokia/read/<mbean> first to read every
# operation's description. If still uncertain, do not execute it.
```

### VPS isolation for dangerous operations

Any operation that lands in the ⚠️/pause category must be executed from an isolated remote VPS reserved for dangerous operations — never from the local network. This limits blast radius from the operator's own infrastructure and keeps a clean separation between recon traffic and higher-risk requests.

## Related

- [[Reference Card - Remediation Verification Methodology]]
- [[bb-scope-safety-check]]
- [[bb-incident-response]]
