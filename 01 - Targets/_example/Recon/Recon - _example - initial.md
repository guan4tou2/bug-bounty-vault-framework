---
fileClass: Recon
target: "[[Target - _example]]"
session_date: "2026-01-02"
session_time_start: "13:00"
session_time_end: "15:00"
hours_spent: 2
scope_focus: "api.example.com surface mapping"
tools_used: [subfinder, httpx, katana]
artefacts: []
findings_produced: ["[[Finding - _example - ACME-001]]"]
attempts_produced: ["[[Attempt - _example - graphql-introspection]]"]
kb_capture_done: true
kb_capture_verified_at: "2026-01-02 15:00"
status: "complete"
---

# Recon — _example — initial surface mapping

> Example Recon session note. Shows how a recon session is recorded. See [[Playbook - Recon]] for the methodology.

## Purpose

Map the `api.example.com` attack surface and identify candidate endpoints for authorization testing.

## Process

1. Subdomain enumeration (`subfinder`, crt.sh) → confirmed `api.example.com`, `www.example.com` in scope.
2. Live host detection (`httpx`) → both respond 200.
3. Content discovery (`katana`) → found `/api/v1/invoices/{id}`, `/api/v1/profile`, `/graphql`.
4. Tech fingerprint → REST API + a GraphQL endpoint with introspection disabled.

## Discoveries

- `GET /api/v1/invoices/{id}` uses sequential integer IDs → candidate for IDOR (became [[Finding - _example - ACME-001]]).
- `/graphql` introspection disabled → tested separately (see [[Attempt - _example - graphql-introspection]]).

## Learned Items

- The API authenticates the session but several object-fetch endpoints do not re-check ownership — worth sweeping every `/{id}` route.

## Knowledge Capture

- Captured the IDOR sweep heuristic in [[Pattern - IDOR]] (already covered; no new Pattern needed).
