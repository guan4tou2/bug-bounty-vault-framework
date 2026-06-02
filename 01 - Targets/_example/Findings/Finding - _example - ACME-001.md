---
fileClass: Finding
finding_id: "ACME-001"
target: "[[Target - _example]]"
host: "api.example.com"
platform: ""
vuln_class: "IDOR"
cwe: "CWE-639"
cvss: "6.5"
severity: "P3"
risk: "medium"
verification_level: "B"
verified_evidence: "live"
status: "verified"
discovered_date: "2026-01-02"
discovered_time: "14:30"
last_verified: "2026-01-02"
hours_spent: 2
chain: false
related_recon: []
related_attempts: []
related_pattern: ["[[Pattern - IDOR]]"]
related_submission: "[[Submission - _example - ACME-001]]"
dedupe_checked_at: "2026-01-02 14:10"
dedupe_query: "idor invoice api.example.com"
dedupe_hits: []
tags: [idor, api]
---

# Finding — _example — IDOR in invoice download endpoint

> Example Finding. This is sample content so the dashboards render on a fresh clone. Delete `_example` (or keep it as a reference) once you create your own targets.

## Summary

`GET /api/v1/invoices/{id}` returns any user's invoice when the requesting account is authenticated but not the owner. The endpoint validates the session but not resource ownership.

## Discovery Log

| Time | Source → Target | Audit ref | Action → Result |
|------|-----------------|-----------|-----------------|
| 2026-01-02 14:30 | tester → api.example.com | [audit:example] | GET /api/v1/invoices/1041 as User B → 200, returns User A's invoice (PII) |

## Evidence

```http
GET /api/v1/invoices/1041 HTTP/1.1
Host: api.example.com
Authorization: Bearer <user-B-token>

HTTP/1.1 200 OK
Content-Type: application/json

{"invoice_id":1041,"account":"user-a@example.com","amount":"129.00","line_items":[...]}
```

User B's token successfully retrieves User A's invoice (sequential integer IDs, no ownership check).

## Impact

- **Verified:** Any authenticated user can read any other user's invoices (PII: name, email, billing amounts) by incrementing the `id`.
- **Potential (not yet proven):** Bulk enumeration of the full invoice range. Not demonstrated — do not claim without evidence.

## Remediation

Enforce resource-level authorization: verify the invoice's `account` matches the authenticated principal before returning it.

## Tasks

- [x] Reproduce cross-account read
- [x] Confirm scope and authorization
- [ ] Draft Submission
