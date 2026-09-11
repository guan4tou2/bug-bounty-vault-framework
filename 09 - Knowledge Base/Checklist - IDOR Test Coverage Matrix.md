---
type: reference
category: Checklist
tags: [checklist, idor, authz, write-path, verb-matrix, financial-api, deal-id, order-id, api-gateway, backend-authz, multi-role]
last_updated: 2026-06-04
source: Items #9, #10 (merged — same root cause), #11 — a multi-role ERP/SaaS session's tests, plus a trading API's observations. Converge on: testers stop at GET and miss higher-severity write-path IDOR. Lesson #50 covers file upload CRUD briefly; Playbook - IDOR Hunting (Burp) mentions verbs; no existing checklist item enforces this as a mandatory gate.
---

# Checklist — IDOR Test Coverage Matrix: Read AND Write Operations Required

> **Purpose**: For every resource ID discovered during testing, enforce a full HTTP verb matrix check before closing the IDOR test for that resource. Testers who stop at GET (read own / read other) routinely miss PUT/PATCH/DELETE write-path IDOR — which carries higher severity and is frequently unguarded in a different way from the read path.
>
> **Root cause of this checklist**: Items 9, 10 (merged — same root cause), and 11 all converge on the same failure mode: testers confirm read-path IDOR and move on, missing that the write path is independently unguarded and higher severity. Lesson #50 (file upload CRUD) and Playbook - IDOR Hunting (Burp) cover parts of this, but no gate enforced full verb coverage as a mandatory stopping condition.
>
> **When to use**: After discovering any resource ID (numeric, UUID, or structured token). Run before marking an IDOR test complete for that resource type. Applies to web, API, and financial/trading API targets.

---

## Gate 0 — Resource ID Inventory (Run First)

Before testing verbs, enumerate all resource ID types visible in the target.

- [ ] **List every resource ID type encountered during exploration.**

  Common forms:
  ```
  Numeric sequential:   /api/orders/12345
  UUID v4:              /api/documents/550e8400-e29b-41d4-a716-446655440000
  Structured/composite: /api/trades/DL-2024-001  (prefix + date + sequence)
  Opaque token:         /api/items/a8f3bc...      (hash or encoded)
  ```

  Record each type in your testing notes:
  ```
  resource_type: order
  id_format: numeric sequential (observed: 10234, 10235, 10236)
  endpoints_found: GET /api/orders/{id}, PUT /api/orders/{id}/status, DELETE /api/orders/{id}
  auth_mechanism: Bearer token (JWT) via Authorization header
  ```

- [ ] **Note which IDs belong to your test account vs other accounts.** You need at least two accounts (Account A = tester, Account B = victim) to test cross-account access. If you only have one account, you can still test write operations against IDs you do not own by using IDs observed in other API responses or guessed from sequential patterns.

---

## Gate 1 — Full Verb Matrix Per Resource

For each resource ID type, test ALL five operations below. Mark each with PASS / FAIL / BLOCKED / SKIP-WITH-REASON.

**Do not mark a resource as "IDOR tested" until all five rows are filled.**

### 1.1 — Read Own Resource (baseline)

- [ ] `GET /api/{resource}/{own-id}` returns expected data with your own session. Confirms the endpoint works and returns a useful response shape.

  Expected: HTTP 200, data matches your account.

### 1.2 — Read Other's Resource (cross-account read)

- [ ] `GET /api/{resource}/{other-account-id}` with your session token returns 403/404 (expected) or 200 with other user's data (IDOR confirmed).

  ```bash
  # Replace <YOUR_TOKEN> and <OTHER_ID>
  curl -s -X GET "https://target.com/api/orders/<OTHER_ID>" \
    -H "Authorization: Bearer <YOUR_TOKEN>" | jq .
  ```

  IDOR confirmed if: HTTP 200 + response contains other user's data.

### 1.3 — Modify Other's Resource (write-path IDOR — highest frequency miss)

- [ ] `PUT /api/{resource}/{other-account-id}` or `PATCH /api/{resource}/{other-account-id}` with your session.

  ```bash
  curl -s -X PUT "https://target.com/api/orders/<OTHER_ID>" \
    -H "Authorization: Bearer <YOUR_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"status":"cancelled"}' | jq .
  ```

  Also try PATCH for partial updates:
  ```bash
  curl -s -X PATCH "https://target.com/api/orders/<OTHER_ID>" \
    -H "Authorization: Bearer <YOUR_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"field":"new_value"}' | jq .
  ```

  IDOR confirmed if: HTTP 200/204 + change is reflected in a subsequent GET, OR error response reveals the resource exists and the action was partially processed.

  **Why this is a gate**: The read path and write path in multi-tier architectures often pass through different middleware or controller layers. An API gateway may enforce read authorization but delegate write authorization to a backend service that omits the check entirely. Confirming read-path IDOR does not confirm write-path protection; and write-path IDOR in the absence of read-path IDOR is a common separate finding.

### 1.4 — Delete Other's Resource

- [ ] `DELETE /api/{resource}/{other-account-id}` with your session.

  ```bash
  curl -s -X DELETE "https://target.com/api/orders/<OTHER_ID>" \
    -H "Authorization: Bearer <YOUR_TOKEN>" | jq .
  ```

  **Caution (GET-first principle)**: Before issuing a DELETE, verify you have documented the resource state (a prior GET). If the resource is not yours, confirm your test account can recreate equivalent resources, or use an ID you created specifically for this test. Do not DELETE production-critical resources belonging to real users outside a controlled test environment.

  IDOR confirmed if: HTTP 200/204 + resource is gone (confirmed by subsequent GET returning 404), or response body confirms deletion.

### 1.5 — Create Resource on Behalf of Other (cross-account creation)

- [ ] `POST /api/{parent-resource}/{other-account-id}/children` or any endpoint that assigns a resource to an account you do not own.

  ```bash
  # Example: create an order assigned to another user's account
  curl -s -X POST "https://target.com/api/accounts/<OTHER_ACCOUNT_ID>/orders" \
    -H "Authorization: Bearer <YOUR_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"item_id": "X", "quantity": 1}' | jq .
  ```

  IDOR confirmed if: HTTP 201/200 + the resource is created under the other account (confirmed by checking other account's resource list, if possible, or by the response body identifying the owner as the other account).

---

## Gate 2 — API Gateway vs Backend Authorization Check

- [ ] **Do not assume API gateway auth = backend authz.**

  Evidence of a split-layer architecture (check for these signals before starting):
  - Swagger/OpenAPI spec shows `security: []` on some paths but not others (see Lesson #49)
  - Different response times between authenticated and unauthenticated calls to the same path (gateway intercepts auth; slow path = forwarded to backend)
  - Error messages differ between 401 (gateway-level) and 403 (backend-level) on related endpoints
  - Some endpoints return gateway-formatted error JSON, others return backend-framework-formatted errors

  Test pattern: if GET is protected and returns 403, check whether PUT to the same resource also returns the gateway's 403 format or a different format. A different format suggests the PUT reaches the backend, and backend authz may be missing or different.

  ```bash
  # Compare error formats — mismatched formats = different authz layer
  curl -sv -X GET  "https://target.com/api/orders/<OTHER_ID>" \
    -H "Authorization: Bearer <YOUR_TOKEN>" 2>&1 | grep -E "< HTTP|{|}"

  curl -sv -X PUT  "https://target.com/api/orders/<OTHER_ID>" \
    -H "Authorization: Bearer <YOUR_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{}' 2>&1 | grep -E "< HTTP|{|}"
  ```

  Different HTTP status codes or different error body shapes = possible split authz — continue testing the write path even if the read path was blocked.

---

## Gate 3 — Financial / Trading API: Deal ID and Order ID Predictability Sub-Check

**Apply this gate only if the target is a financial or trading platform (trading APIs, payment processors, investment platforms, order management systems).**

- [ ] **For financial resource IDs, assess predictability class before testing cross-account access.**

  | ID format observed | Predictability | Action |
  |---|---|---|
  | Sequential integer (10234, 10235…) | High | Test: predict next ID, test unauthorized access, test increment/decrement range |
  | Structured token (DL-2024-001, ORD-20240601-0042) | Medium | Test: enumerate by date range or sequence component; test edge cases (first/last of day) |
  | UUID v4 | Low | Test: harvest UUIDs from other API responses (e.g., order history, search results, audit logs) before brute-force; brute-force is out of scope |
  | Opaque encoded | Unknown | Decode first (base64, JWT, custom encoding); classify after decoding |

- [ ] **Sequential or structured Deal IDs: test the full verb matrix across a predicted range.**

  ```bash
  # Example: sequential DealId range sweep (read-path)
  for id in $(seq 10230 10240); do
    resp=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://trading-target.com/api/deals/$id" \
      -H "Authorization: Bearer <YOUR_TOKEN>")
    echo "$id -> $resp"
  done
  ```

  For each ID that returns 200: check whether the response data belongs to your account. If it does not → read-path IDOR. Then proceed to Gate 1.3 (modify) and Gate 1.4 (delete) for that ID.

- [ ] **Financial write-path IDOR: test order status changes, cancellations, and amount modifications separately.**

  These are higher severity than read-path IDOR in financial context because:
  - Order cancellation IDOR → adversary cancels trades, causes financial loss
  - Amount modification IDOR → adversary alters trade size or price
  - Status modification IDOR → adversary marks orders as settled/completed

  ```bash
  # Status change on other account's order
  curl -s -X PUT "https://trading-target.com/api/deals/<OTHER_DEAL_ID>/status" \
    -H "Authorization: Bearer <YOUR_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"status": "cancelled"}' | jq .

  # Amount modification attempt
  curl -s -X PATCH "https://trading-target.com/api/deals/<OTHER_DEAL_ID>" \
    -H "Authorization: Bearer <YOUR_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"amount": 0.01}' | jq .
  ```

- [ ] **Record DealId/OrderId predictability class in RECON_DB regardless of whether IDOR is confirmed.**

  ```markdown
  ## DealId Predictability Assessment
  format: sequential integer (observed: 10234–10236 across 3 test orders)
  predictability: HIGH
  cross-account read: [PASS / IDOR-CONFIRMED]
  cross-account write: [PASS / IDOR-CONFIRMED / NOT-TESTED]
  ```

  Predictability alone (without access control failure) is not a finding. Document it as context for attack chain review — it may combine with a read-path IDOR to increase severity.

---

## Gate 4 — Multi-Role Testing: Role Separation Verification

**Apply this gate if the target has multiple user roles (e.g., admin/manager/viewer, enterprise/personal, buyer/seller).**

- [ ] **Test IDOR operations from each role that can interact with the resource type.**

  Roles to test (adapt to target):
  ```
  Role A (lower privilege) → access resource owned by Role B (higher privilege)
  Role B (higher privilege) → access resource owned by Role A (different org/tenant)
  Role A in Org X → access resource owned by Role A in Org Y (cross-tenant)
  ```

  Multi-role test matrix template:
  ```
  Resource: /api/documents/{id}
  
  | Tester role | Victim role | Verb  | Expected | Actual | Result |
  |-------------|-------------|-------|----------|--------|--------|
  | viewer      | admin       | GET   | 403      | ?      | ?      |
  | viewer      | admin       | PUT   | 403      | ?      | ?      |
  | viewer      | admin       | DELETE| 403      | ?      | ?      |
  | manager     | other-org   | GET   | 403      | ?      | ?      |
  | manager     | other-org   | PUT   | 403      | ?      | ?      |
  ```

  Source: multi-role ERP/SaaS sessions — viewer-role accounts were restricted from read-path by UI, but the underlying API did not enforce the same restriction on the write path. The fix required separate backend checks for each verb.

---

## Gate 5 — Closing Condition

- [ ] **A resource is "IDOR tested" only when all of the following are true:**

  - [ ] All five verb operations in Gate 1 have been attempted (or explicitly marked SKIP with a stated reason such as "no DELETE endpoint exists for this resource").
  - [ ] Gate 2 (API gateway vs backend authz) has been assessed.
  - [ ] Gate 3 has been applied if the target is a financial platform.
  - [ ] Gate 4 has been applied if the target has multiple roles.
  - [ ] Results (PASS / IDOR-CONFIRMED / BLOCKED / SKIP-WITH-REASON) are recorded in the Discovery Log.

  Discovery Log format per resource:
  ```
  [HH:MM] [<tester-ip>→<target-ip>] [audit:idor-verb-matrix] IDOR verb matrix — /api/orders/{id}
    GET own:          200 ✓
    GET other:        200 IDOR-CONFIRMED (OrderId 10235 returned Acct B data)
    PUT other:        403 PASS (blocked)
    PATCH other:      200 IDOR-CONFIRMED (status changed to cancelled — higher severity)
    DELETE other:     404 SKIP (resource already gone from prior test)
    POST on other:    403 PASS (blocked)
  ```

---

## Quick Reference — Gate Summary

| # | Gate | Condition | Fail action |
|---|---|---|---|
| 0 | Resource ID inventory | Always | List all ID types before testing |
| 1.1 | GET own (baseline) | Always | Fix test setup if this fails |
| 1.2 | GET other (read-path) | Always | Mark IDOR-CONFIRMED or PASS |
| 1.3 | PUT/PATCH other (write-path) | Always | **Do not skip — most common miss** |
| 1.4 | DELETE other | Always | Use GET-first; document resource state |
| 1.5 | POST on-behalf-of other | Always | Mark IDOR-CONFIRMED or PASS |
| 2 | API gateway ≠ backend authz | Always | Compare error formats; test write even if read blocked |
| 3 | Financial ID predictability | Financial targets only | Record predictability class; test range |
| 4 | Multi-role separation | Multi-role targets | Test each role pair |
| 5 | Closing condition | Before marking "tested" | All rows filled, Discovery Log updated |

---

## Related

- [[Pattern - IDOR Response Differential]] — how to confirm IDOR from response shape when status codes are identical
- [[Playbook - IDOR Hunting (Burp)]] — Burp-based workflow for intercepting and replaying IDOR requests
- [[Checklist - Web Vuln Technique Coverage]] — upstream checklist; IDOR is one item there; this checklist expands the IDOR row
- [[Lessons Learned]] §Lesson #50 (A→B: unauthenticated file upload → test all CRUD operations on the same resource), §Lesson #106 (frontend RBAC = zero RBAC)
- [[Reference Card - Bug Bounty Workflow 2026]] — severity guidance: write-path IDOR typically P2–P3; financial write-path IDOR typically P1–P2
