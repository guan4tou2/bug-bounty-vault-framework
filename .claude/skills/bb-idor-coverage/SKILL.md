---
name: bb-idor-coverage
description: Use when an IDOR is found or being tested — BEFORE marking it complete for a resource type — to enforce the full HTTP verb / coverage matrix (read AND write: GET + POST/PUT/PATCH/DELETE, object-ID variants, cross-tenant) so testing does not stop at GET and miss higher-severity write-path IDOR. The coverage / stop-condition GATE; complements (not replaces) the idor-broken-object-authorization technique skill. Triggers: IDOR / resource ID / object reference / before closing IDOR test.
---

# Bug Bounty — IDOR Coverage Matrix (Full Verb Stop-Condition Gate)

Recurring failure pattern: testers confirm **read-path** IDOR (read own -> read other) and move on — missing that the **write path (PUT/PATCH/DELETE) is independently unguarded and higher severity**. This gate mechanically blocks "closing" an IDOR until the full verb matrix is covered. It is the *stop condition*; the technique catalog is the external `idor-broken-object-authorization` skill (see External Skills Catalog).

## Trigger

When any resource ID is discovered (numeric sequential / UUID / structured like `XX-2024-001` / opaque token) -> **this gate must fire before marking IDOR testing complete** for that resource. Applies to web apps, APIs, and financial transaction APIs alike.

## Gate 0 — Resource ID Inventory

List **every** resource ID type that appears in the target. Do not test only the one you stumbled upon.

Four common ID types to look for:
1. **Numeric sequential** (e.g., `id=1234`) — trivially enumerable
2. **UUID** (e.g., `550e8400-e29b-41d4-a716-446655440000`) — check for UUID leakage points
3. **Structured** (e.g., `ORD-2024-0042`) — pattern is guessable
4. **Opaque token** (e.g., base64-encoded compound key) — decode and analyze structure

## Hard Gate — Full Verb Matrix (GET is NOT the finish line)

For each resource ID, test the complete verb matrix before marking as done:

| Verb | What to Test | Why |
|---|---|---|
| **GET** | Read own / read **other** | Read-path IDOR (everyone tests this far) |
| **PUT / PATCH** | Modify another user's object | Write-path is often independently unguarded; higher severity |
| **DELETE** | Delete another user's object | Destructive; commonly missed in testing |
| **POST** | Create / bind as another user | Create-path privilege escalation |
| **Variants** | Object-ID guessing (sequential/UUID leak), cross-tenant, batch endpoints, GraphQL `node` queries | Backend authz often only blocks frontend routes |

**Stop-loss criteria**: All verbs tested (confirmed / disproven / N/A with documented reason) before marking complete. **Testing only GET and closing = incomplete** (this gate exists specifically to block that).

## Testing Methodology Notes

- **Same root cause, same report**: If GET and PUT IDOR share the same missing authz check, report as a single finding covering all affected verbs — do not split into separate reports.
- **Cross-tenant testing**: If the application is multi-tenant, test across tenant boundaries, not just across users within the same tenant.
- **Batch/bulk endpoints**: Many APIs have batch variants (`/api/items/batch`) that bypass per-item authz checks.
- **GraphQL**: Test `node(id: "...")` queries and mutations separately — GraphQL resolvers may have inconsistent authz.
- **Rate limiting**: Sequential ID enumeration may trigger rate limits; note whether rate limiting exists (its absence is a finding amplifier).

## After Completing the Matrix

- Proceed to `bb-exploit-chain` (can this chain with other findings?)
- Then `bb-evidence-readiness` (document all tested verbs and results)
- Then `bb-dedup-finding` (same root cause -> do not split the report)
- Related: IDOR Test Coverage Matrix checklist (full per-verb detail), External Skills Catalog for the `idor-broken-object-authorization` technique reference
