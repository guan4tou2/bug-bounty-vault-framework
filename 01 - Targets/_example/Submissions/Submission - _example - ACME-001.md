---
fileClass: Submission
type: submission
finding_id: "ACME-001"
target: "[[Target - _example]]"
platform: "generic"
severity: "P3"
status: "ready"
submitted_date: ""
---

# Submission — _example — IDOR in invoice download endpoint

> Example Submission. Generated from `[[Finding - _example - ACME-001]]`. Platform-neutral draft — a FORM is produced from this at submission time.

## Title

IDOR: authenticated user can read any other user's invoices via `/api/v1/invoices/{id}`

## Summary

The invoice download endpoint authenticates the session but does not verify resource ownership, allowing any authenticated user to read other users' invoices (PII) by changing the numeric `id`.

## Steps to Reproduce

1. Authenticate as User B and capture the bearer token.
2. Send `GET /api/v1/invoices/1041` (an invoice belonging to User A).
3. Observe a `200 OK` returning User A's invoice data.

## Impact

Cross-account read of invoice PII (name, email, billing amounts). Verified for a single cross-account request; see the Finding for the verified-vs-potential boundary.

## Remediation

Enforce per-resource authorization: confirm the invoice owner matches the authenticated principal.

## Severity

P3 (CVSS 6.5 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N).
