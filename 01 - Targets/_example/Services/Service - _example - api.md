---
fileClass: Service
target: "[[Target - _example]]"
kind: "api"
url: "https://api.example.com"
ip: ""
tech_stack: [rest, graphql]
status: "auth-required"
risk: "medium"
in_scope: true
endpoints: ["/api/v1/invoices/{id}", "/api/v1/profile", "/graphql"]
credentials: []
---

# Service — _example — api.example.com

> Example Service note. Tracks one live service, its endpoints, and confirmed weaknesses.

## Snapshot

| Field | Value |
|-------|-------|
| Kind | REST API + GraphQL |
| URL | https://api.example.com |
| Status | Auth required |
| In scope | Yes |

## Endpoints

| Path | Method | Auth? | Notes |
|------|--------|-------|-------|
| `/api/v1/invoices/{id}` | GET | session | IDOR confirmed — [[Finding - _example - ACME-001]] |
| `/api/v1/profile` | GET | session | Returns own profile; not yet tested for IDOR |
| `/graphql` | POST | session | Introspection disabled — [[Attempt - _example - graphql-introspection]] |

## Confirmed Weaknesses

- IDOR on `/api/v1/invoices/{id}` ([[Finding - _example - ACME-001]]).

## Attack Surface Notes

- Object-fetch routes with `{id}` are the highest-value surface here; sweep `/profile` and any other `/{id}` route next.
