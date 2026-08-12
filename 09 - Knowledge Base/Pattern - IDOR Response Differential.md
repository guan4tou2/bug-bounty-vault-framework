---
type: pattern
title: "Pattern - IDOR Response Differential"
tags: [pattern, cwe-639, idor, access-control, graphql, bb-pattern]
status: verified
vuln_class: idor
severity_range: P2-P3
seen_in: [graphql-api, salesforce-commerce-cloud, ecommerce-backend]
prerequisites: ["authenticated test account", "a second test account for phase-2 confirmation"]
last_updated: 2026-04-11
---

# Pattern - IDOR Response Differential

> **TL;DR**: Most real-world IDORs do not return `"You are not the owner"`. They return a generic `NotFoundException` / `Invalid{Type}Exception`, because the resolver only performs a lookup-by-ID and never performs an ownership check. Distinguishing "not found because it doesn't exist" from "not found because the resolver skipped an ownership check" is the core of this pattern — and it requires a second real account to fully confirm.

## Core Observation

When an API correctly implements an ownership check:

```
Request:  GET /resource/{other_user_id}
Response: 403 Forbidden / "You do not have permission"
```

When an API is missing an ownership check:

```
Request:  GET /resource/{other_user_id}
Response: 200 OK + data disclosure   <- successful IDOR
```
```
Request:  GET /resource/{non_existent_id}   (simulating someone else's ID that doesn't actually exist)
Response: 404 NotFoundException   <- the resolver reached the lookup stage and only then failed, meaning no ownership check ran first
```

**The decisive evidence**: `NotFoundException` is not the same as `ForbiddenException`.

## Triad Test

Run these three requests against every suspected IDOR endpoint/mutation:

| Test | Request | Expected |
|------|---------|----------|
| **A. Baseline** | Your own valid token + your own valid ID | 200 OK |
| **B. IDOR probe** | Your own valid token + a modified ID (someone else's / nonexistent) | Look at the error type |
| **C. Auth probe** | No token + your own valid ID | 401/403 (confirms auth is enforced at all) |

**Reading the result:**

- Test B returns `NotFoundException` -> IDOR signal present (resolver skipped the ownership check)
- Test B returns `Forbidden`/`Permission denied` -> ownership check is correctly implemented
- Test C returns `Forbidden` -> the auth mechanism itself is working
- Test C returns 200 -> there's no auth at all, which is a more severe **unauthenticated access** finding, not an IDOR

## Getting a Real ID Format (the "createX before updateX" trick)

Before testing `updateX` / `deleteX`, first call `createX` to make a throwaway test resource:

1. Observe the returned ID's format (UUID / hex32 / base64-encoded Relay global ID)
2. Modify only the last few characters of the ID — don't replace it entirely
3. Use the modified ID for Test B

**Why this works:**

- You get a real ID format, so the resolver won't reject it for being malformed before it even reaches the ownership check
- A slightly-modified ID is very likely to collide with another user's resource or with nothing at all
- If it hits another user's resource -> confirmed IDOR. If it hits nothing -> `NotFoundException` is still enough to demonstrate the missing-check pattern (pending Phase 2 confirmation below)

## Case Study — Example Vendor (Salesforce Commerce Cloud GraphQL storefront)

**Step 1** — `createCustomerAddress` to obtain a real Relay ID:

```
Q3VzdG9tZXJBZGRyZXNzOmFlYThhYmQxYjhmOWEyZWRlZTgzYjY2YzkyMTBmMjg5
= base64("CustomerAddress:aea8abd1b8f9a2edee83b66c9210f289")
```

**Step 2** — Baseline (own ID):

```graphql
updateCustomerAddress(input: { id: "...f289", address: {...} })
# -> SUCCESS
```

**Step 3** — IDOR probe (last 3 hex characters changed to `f000`):

```graphql
updateCustomerAddress(input: { id: "...f000", address: {...} })
# -> errors: [{
#     message: "The customer address 'aea8abd1b8f9a2edee83b66c9210f000' couldn't be found.",
#     extensions: { code: "AddressNotFoundException" }
#   }]
```

**Decisive evidence**: `AddressNotFoundException` is not `Forbidden`. The resolver performed a SQL lookup and never checked ownership.

### The same pattern across other mutations on the same API

A single finding is often systemic. In this case, the same missing-check pattern applied to:

- `cancelOrder` -> `ORDER_NOT_FOUND` (not `Forbidden`)
- `updateBasket` -> `BasketNotFoundException`
- `nodes(ids:[RegisteredCustomer:...])` -> `InvalidCustomerException`
- `nodes(ids:[CustomerAddress:...])` -> "The customer address ... couldn't be found"
- `guestOrder` -> `404: Not Found`

-> the entire GraphQL backend was missing ownership checks. One IDOR discovery expanded to seven distinct primitives worth testing.

## Report Writing (VRT severity guide)

| Scenario | Bugcrowd VRT | Severity |
|----------|--------------|----------|
| READ IDOR (leaks another user's PII) | Broken Access Control > IDOR > Read | P3-P2 |
| WRITE IDOR (modifies another user's data) | Broken Access Control > IDOR > Modify Auth User Data | **P2** |
| DELETE IDOR (deletes another user's data) | Broken Access Control > IDOR > Delete | P2 |
| IDOR touching payments/orders/financial data | +1 tier | P2 -> potentially P1 |

**When writing the report:**

- Lead with the response-differential evidence (`NotFoundException` vs `Forbidden`)
- List every affected primitive — chaining several IDORs into one report demonstrates larger impact
- Be explicit about what's verified vs. what would require a real victim ID to fully prove
- **Never** claim you "can imagine" a further attack chain — only describe verified behavior

## Trap: `NotFoundException` Alone Is Not Proof of IDOR

**The Triad Test is a necessary condition for IDOR, not a sufficient one.**

| Test B result (with a fake ID) | Interpretation | Next step |
|---|---|---|
| `NotFoundException` (fake ID) | The ID simply doesn't exist — this alone proves nothing yet | Proceed to Phase 2 |
| `InvalidCustomerException` (a real, other user's ID) | The backend does have an ownership check -> **false positive** | Confirm as false positive |
| `200 + another user's data` (a real, other user's ID) | Confirmed IDOR | Screenshot, report |

**Phase 2 (the decisive test):**

You must test with another user's **real, existing** ID — a fake ID alone is not enough.

```bash
# Not sufficient: a fake ID returning NotFoundException (may just mean the ID doesn't exist)
# Required:       Account #2's real resource ID + Account #1's token -> observe the result
```

**Ways to obtain another user's real ID:**

1. A second test account -> create a resource -> get a real ID
2. IDs embedded in shared URLs (wishlist share tokens, invoice links)
3. IDs leaked in Referrer headers

**Real-world counter-example:** in one engagement, the Triad Test's Test B looked like an IDOR signal (`NotFoundException`) for `updateBasket`, but Phase 2 confirmed that Account #1's token against Account #2's real basket ID returned `InvalidCustomerException` (session-scoped validation on the backend). **All seven candidate primitives from that engagement turned out to be false positives** once Phase 2 was run.

## Anti-Overclaim Discipline

- Don't write: "an attacker can read all users' data" — unless you actually did that.
- Do write: "the resolver is missing an ownership check — any token paired with another user's ID can read that resource."
- Don't write: "this finding leads to account takeover" — unless you demonstrated the full chain.
- Do write: "if an attacker obtains a victim's ID through another channel, they can access that resource via this endpoint."
- Don't write: "the Triad Test confirms IDOR" — a `NotFoundException` alone may just mean the ID doesn't exist.
- Do write: "Phase 2 cross-account verification: Account A's token + Account B's real ID succeeded."

## Remediation (for the report's fix recommendation)

1. Add an ownership check inside every resolver:
   ```ts
   const resource = await loadResource(input.id);
   if (resource.customerNo !== ctx.user.customerNo) {
     throw new ForbiddenError('Not authorized');
   }
   ```
2. Enforce this uniformly with middleware (e.g. `graphql-shield`) across every `update*`/`delete*` mutation.
3. Check ownership before checking existence, to avoid introducing a separate timing oracle.

## References

- [[Pattern - GraphQL Field Suggestion Enumeration]]
- [[Checklist - IDOR Test Coverage Matrix]]
- [[Lessons Learned]] — front-end-only RBAC is equivalent to no RBAC; response-tampering can flip a denied flag to allowed, which is a complementary variant of this pattern (attacker rewrites the response rather than merely observing a differential)
