---
type: wiki
category: attack
tool: grpcurl,protoscope,buf,blackboxprotobuf,grpcui
status: active
last-updated: 2026-08-23
---

# gRPC / Protobuf Attacks

> **Use case:** Mobile backends, internal microservices exposed through a public gateway, and increasingly public APIs (Google Cloud, many SaaS backends) speak gRPC over HTTP/2, or gRPC-Web over HTTP/1.1+2 through a browser-compatible proxy. The binary framing means most generic web scanners see nothing — no visible parameters, no obvious injection points — so gRPC surfaces are systematically under-tested even when the same authorization bugs (IDOR, BFLA, mass assignment) are sitting right there in the RPC methods. Treat "the traffic is binary" as an under-testing signal, not a dead end.

## 0. Recognize the surface

- Port hints: `50051` is the gRPC convention default, but production services run it on `443`/`8443` behind a normal TLS listener just as often — port number alone is not a reliable signal.
- `Content-Type` on the wire: `application/grpc` (native gRPC, HTTP/2 only), `application/grpc-web` or `application/grpc-web+proto` (gRPC-Web, binary), `application/grpc-web-text` (gRPC-Web, base64-encoded — this is the one you'll see most often talking to a browser, because some proxies/browsers historically only round-tripped text-safe bodies cleanly).
- In a browser's network tab: a POST to a path shaped like `/package.ServiceName/MethodName` with a `grpc-status` / `grpc-message` response header (sometimes as an HTTP trailer, sometimes echoed as a normal header by the gRPC-Web proxy) is the tell. The body is opaque bytes even in DevTools — that opacity is exactly why this surface gets skipped by hunters who don't know to look past it.
- JS bundle recon (you already do this for REST — do the same pass here): grep the app's JS for `.proto`-adjacent artifacts — generated client stubs reference method/service names in plaintext even when the wire payload is binary. See [84-source-code-review-flow.md](84-source-code-review-flow.md) and the framework's own `js-sourcemap-miner` agent for the extraction workflow; the difference here is what you're looking for: `grpc-web` client generated code (`*_pb.js`, `*_grpc_web_pb.js`, `*.pb.ts`) names every service, method, and message field even when reflection is off server-side.

## 1. Reflection enumeration (the fast path)

If [server reflection](https://github.com/grpc/grpc/blob/master/doc/server-reflection.md) is enabled — common in staging, internal services, and services that were never hardened for external exposure — you get the entire API surface for free: every service, every method, every message field, with no source code and no APK/JS reversing needed.

```bash
# Install: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# 1. List every exposed service (plaintext / no TLS)
grpcurl -plaintext target.internal:50051 list

# Same, over TLS (the far more common case for anything internet-facing)
grpcurl target.com:443 list

# 2. List every method on a service you found
grpcurl target.com:443 list acme.user.v1.UserService

# 3. Get the full message schema for one method — field names, types, field
#    numbers, nested messages. This is the equivalent of finding an OpenAPI
#    spec for a REST API, except almost nobody expects it to be exposed.
grpcurl target.com:443 describe acme.user.v1.UserService.GetUserProfile

# 4. Invoke it. Start with no auth metadata — you'd be surprised how often
#    an internal-only-by-assumption method has zero server-side auth check.
grpcurl -d '{"user_id": 1001}' target.com:443 acme.user.v1.UserService/GetUserProfile

# 5. Then with a real session's bearer token (metadata = gRPC's equivalent of
#    HTTP headers) to see what changes.
grpcurl -H 'authorization: Bearer <token>' \
        -d '{"user_id": 1001}' \
        target.com:443 acme.user.v1.UserService/GetUserProfile
```

For a browsable UI over the same reflection data (useful for manually poking around a large service catalog instead of round-tripping the CLI for every field): [`grpcui`](https://github.com/fullstorydev/grpcui) — `grpcui -plaintext target.internal:50051` opens a local web form auto-generated from the schema, with per-field inputs, exactly like Swagger UI does for REST.

## 2. Schema recovery when reflection is disabled

Reflection being off does **not** mean the schema is unknowable — it means you have to reconstruct it instead of asking the server for it.

### 2.1 You already have message bytes, no schema — protoscope

[`protoscope`](https://github.com/protocolbuffers/protoscope) (from the protobuf team itself) decodes raw wire-format bytes into a human-readable, editable text form **without needing the `.proto` file** — protobuf's wire format is self-describing enough (tag = field number + wire type) to get field numbers, types, and nesting even with zero schema. This is your first move on any captured gRPC/gRPC-Web body:

```bash
# Decode a captured binary payload (e.g. saved from Burp / mitmproxy) to readable text
protoscope captured_request.bin
# → field numbers + wire-type-inferred values, e.g.:
#   1: 1001          (varint — likely an int/enum/bool field)
#   2: {"user_id":1001}   (length-delimited — could be string, bytes, or nested message)
#   3: 3.14           (fixed64 — likely a double)

# Round-trip: edit the text form, re-encode back to wire bytes to build a
# tampered request (e.g. flip field 1 from your own ID to another user's)
protoscope -s edited.txt > tampered_request.bin
```
Because you have no field *names* from wire bytes alone, treat field numbers as your working vocabulary (`field 3`, not `user_id`) until you cross-reference with something that does have names (§2.2/§2.3).

### 2.2 You have a `.proto` file or can reconstruct one — `buf`

If you recovered `.proto` source (from a public SDK repo, a mobile app's decompiled sources, a leaked internal monorepo, or simply the vendor's public API docs), [`buf`](https://buf.build/docs/cli/) builds it into a `FileDescriptorSet` — the same schema object reflection would have handed you — so grpcurl can use it exactly as if reflection were on:

```bash
# Build a descriptor set from local .proto sources
buf build -o descriptor.bin path/to/protos

# Feed it to grpcurl in place of reflection
grpcurl -protoset descriptor.bin target.com:443 list
grpcurl -protoset descriptor.bin -d '{"user_id":1001}' \
        target.com:443 acme.user.v1.UserService/GetUserProfile
```
`grpcurl` also accepts raw `.proto` files directly (no `buf` step needed) via `-import-path <dir> -proto <file>.proto` — use whichever recovery source you actually have.

### 2.3 No schema, no protos, just captured traffic and field guessing — blackboxprotobuf

[`blackboxprotobuf`](https://github.com/nccgroup/blackboxprotobuf) (NCC Group) goes further than protoscope: it infers a *typed* structure from wire bytes (including nested-message boundaries) well enough to let you edit values field-by-field and re-encode — and it ships a **Burp extension**, so you can decode a captured gRPC(-Web) request in Repeater, edit a field's value in a readable form, and let the extension re-encode it back to wire bytes before sending. This is the practical everyday tool for "I found a gRPC-Web call in Burp, reflection is off, I have no `.proto`, I still want to tamper with field 4" — reach for protoscope when you just need to read bytes once, blackboxprotobuf when you're going to be editing and replaying repeatedly.

## 3. gRPC-Web proxy quirks

Browsers cannot speak raw HTTP/2 trailers the way native gRPC needs, so browser-facing gRPC goes through a **gRPC-Web proxy** (Envoy's `grpc_web` filter, `grpc-web` on nginx, or a language-specific gRPC-Web gateway) that translates between the browser-safe wire format and real gRPC to the backend. Test the translation layer itself, not just the RPC logic behind it:

- **Framing**: every gRPC and gRPC-Web message (binary variants) is wrapped in a 5-byte frame — byte 0 is a compressed-flag (0/1), bytes 1–4 are the message length as a big-endian uint32, followed by the raw protobuf bytes. Get this wrong when hand-crafting a request and you get a generic parse error that looks like "not vulnerable" when it's actually "malformed frame" — always frame-wrap manually-built payloads, don't send bare protobuf bytes to a gRPC(-Web) endpoint.
- **Text mode adds an extra step**: `application/grpc-web-text` is the same 5-byte-framed payload, base64-encoded on top. Forgetting the base64 layer (or the framing underneath it) is the single most common "my hand-crafted gRPC-Web curl request just gets rejected" mistake.
- **Hand-crafted curl example** (binary gRPC-Web, once you have the raw protobuf bytes from protoscope/buf):
  ```bash
  # Build the 5-byte frame + payload, then POST it
  python3 -c "
  import struct
  payload = open('tampered_request.bin','rb').read()
  frame = b'\x00' + struct.pack('>I', len(payload)) + payload
  open('framed.bin','wb').write(frame)
  "
  curl -s -X POST 'https://target.com/acme.user.v1.UserService/GetUserProfile' \
    -H 'Content-Type: application/grpc-web+proto' \
    -H 'X-Grpc-Web: 1' \
    -H 'authorization: Bearer <token>' \
    --data-binary @framed.bin
  ```
- **Auth/authz can drop silently at the proxy boundary**: the gRPC-Web proxy is a second hop the request passes through before reaching the actual gRPC service. Test whether the proxy itself enforces anything (CORS, auth-header presence) versus whether enforcement only happens once inside the real backend — a proxy that strips or ignores an `authorization` metadata value it doesn't recognize, then forwards the call anyway with the backend defaulting to an internal service-account identity, is a realistic and previously-seen misconfiguration class, not a hypothetical.
- **CORS**: gRPC-Web calls are still browser XHR/fetch under the hood — the same CORS misconfiguration checks from [63-prototype-pollution.md](63-prototype-pollution.md)'s neighbors and the OWASP CORS checklist apply; a permissive `Access-Control-Allow-Origin` reflecting arbitrary origins on a gRPC-Web endpoint is exactly as exploitable as on a REST one.
- **HTTP/JSON transcoding gateways** (Envoy `grpc_json_transcoder`, Google Cloud Endpoints, grpc-gateway) translate REST-looking JSON HTTP calls into gRPC on the backend. If a target exposes both a JSON-transcoded REST-ish surface and the raw gRPC/gRPC-Web surface behind the same backend, **test both** — a route or method restricted at the JSON-gateway layer (path-based ACL, WAF rule tuned for the REST paths) is frequently reachable directly against the gRPC-Web or native gRPC listener behind it, because that listener was never in scope for the REST-shaped controls.

## 4. Per-RPC authorization and IDOR testing methodology

This is where the payoff is — gRPC services have exactly the same authorization bug classes as REST APIs, just harder for less-experienced hunters to reach because of the binary wire format. Once you can invoke methods (§1/§2), the checklist is a direct translation of [77-idor-bola-bfla.md](77-idor-bola-bfla.md) onto RPC methods:

1. **Enumerate every method, not just the ones the client app actually calls.** Reflection/schema recovery hands you methods the frontend never uses (internal-only, deprecated-but-still-live, admin-only) — every one of them is in scope for the same authz testing as the ones you can see traffic for.
2. **No-auth baseline.** Call each method with zero `authorization` metadata. A method that returns real data with no auth at all is the gRPC equivalent of an unauthenticated REST endpoint — check this before anything more complex.
3. **Cross-user object access (the core IDOR check).** Authenticate as user A, call a method that takes an object identifier (`user_id`, `order_id`, `document_id`, any field that looks like a reference), then replay the exact same call with user B's session/token but user A's identifier value. No ownership check server-side = IDOR, identical in effect to REST IDOR, just delivered as a proto field instead of a URL path segment.
4. **BFLA — role/method-level, not just object-level.** With a low-privilege user's token, call methods whose names suggest elevated privilege (`AdminService/...`, `DeleteUser`, `UpdateUserRole`, anything with `Admin`/`Internal`/`Debug` in the service or method name from your enumeration in step 1). Missing role checks at the method level is BFLA regardless of transport.
5. **Streaming RPCs — the gRPC-specific gotcha.** Server-streaming and bidirectional-streaming methods are disproportionately likely to check authorization only once, on the initial request that opens the stream, and never again for the individual messages that stream back afterward. If a streaming method's later messages/pages of data are for a different logical resource than the one on the opening request (e.g. a live-updates stream a client can steer by sending follow-up messages), test whether authorization is re-checked on every message the server pushes, not only on stream-open. This has no direct REST equivalent — treat it as its own checklist item, not folded into step 3.
6. **Field-level mass assignment via unlisted/deprecated fields.** Protobuf messages are versioned by field *number*, and old field numbers are commonly left `reserved` (documented as retired, but not always actually rejected server-side) rather than fully removed, to avoid ever reusing a number. If a `.proto` you recovered (or an older SDK version's `.proto`) shows a field number that the *current* client-facing schema no longer lists — e.g. an old `is_admin` or `role` field at field number 7 that a newer message definition dropped from the public-facing schema but the server binary (built from the same message type) may still read — try sending it anyway by field number using protoscope/blackboxprotobuf to hand-craft the wire bytes. This is protobuf's version of REST mass-assignment (`isAdmin: true` in a JSON body the client form never exposes), except discovering the vulnerable field requires wire-level tooling instead of just reading a JSON schema. Confirm the field actually still does something server-side before reporting — a reserved field number that the server silently ignores is not a finding.

### Worked example (illustrative shape — field/service names are placeholders)

```bash
# 1. Reflection is open on staging, closed on prod — enumerate on staging,
#    carry the schema over to prod via -protoset once built with buf.
grpcurl -plaintext staging.internal:50051 list
# → acme.user.v1.UserService, acme.admin.v1.AdminService (unexpected — not in the mobile app's traffic at all)

grpcurl -plaintext staging.internal:50051 describe acme.user.v1.UserService.GetUserProfile
# → message GetUserProfileRequest { int64 user_id = 1; }

# 2. Baseline as your own account
grpcurl -H 'authorization: Bearer <user_a_token>' \
        -d '{"user_id": 1001}' \
        prod.target.com:443 acme.user.v1.UserService/GetUserProfile
# → 200-equivalent, your own profile

# 3. IDOR check — same token, someone else's id
grpcurl -H 'authorization: Bearer <user_a_token>' \
        -d '{"user_id": 1002}' \
        prod.target.com:443 acme.user.v1.UserService/GetUserProfile
# → if this returns user 1002's data: IDOR, exactly as in 77-idor-bola-bfla.md

# 4. BFLA check — the admin service reflection revealed but the app never calls
grpcurl -H 'authorization: Bearer <user_a_token>' \
        -d '{"user_id": 1002, "role": "admin"}' \
        prod.target.com:443 acme.admin.v1.AdminService/UpdateUserRole
# → if a non-admin token succeeds here: BFLA
```

## 5. Safe testing rules

1. ✅ Enumerate and describe (read-only reflection calls) freely — this is equivalent to reading an exposed OpenAPI spec, not an attack.
2. ✅ Cross-user IDOR checks with your own two test accounts only — never someone else's real data.
3. ❌ Do not invoke destructive-sounding methods (`Delete*`, `Purge*`, `Reset*`) speculatively — treat the method name as a strong hint of blast radius, same discipline as GET-first on REST.
4. ✅ Record the exact `grpcurl`/curl command, service/method name, and full request/response pair as your evidence — a reviewer without gRPC tooling installed cannot re-run a vague description of a binary call the way they could re-run a `curl` against a REST endpoint, so over-document reproduction steps here specifically.
5. ⏳ Streaming-RPC and mass-assignment findings (§4.5–4.6) need a second, skeptical pass before reporting: confirm the field/stream behavior is actually exploitable end-to-end, not just "the server didn't immediately reject it" — see `bb-exploit-chain` and the anti-exaggeration principle before writing these up.

## Related files

- [77-idor-bola-bfla.md](77-idor-bola-bfla.md) — the REST-side version of §4's checklist; read both together
- [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md) — closest sibling: another schema-driven API style where introspection/reflection being on is a full attack-surface disclosure
- [84-source-code-review-flow.md](84-source-code-review-flow.md) — where to look for `.proto` sources / generated client stubs when reflection is off
- [65-csrf-deep.md](65-csrf-deep.md) and CORS checks — apply to gRPC-Web's browser-facing surface (§3)
- grpcurl: https://github.com/fullstorydev/grpcurl
- grpcui: https://github.com/fullstorydev/grpcui
- protoscope: https://github.com/protocolbuffers/protoscope
- blackboxprotobuf (+ Burp extension): https://github.com/nccgroup/blackboxprotobuf
- buf CLI: https://buf.build/docs/cli/
- gRPC server reflection protocol spec: https://github.com/grpc/grpc/blob/master/doc/server-reflection.md
