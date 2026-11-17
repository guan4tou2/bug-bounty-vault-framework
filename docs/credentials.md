# Reference-based credential lifecycle

`credentials.py` separates a discovered value from a validated identity/permission.
Raw values use an OS-protected keyring backend; ASG stores an opaque `credential_ref`,
origin evidence, service/account/role/tenant/scope references, expiry and history.
There is no plaintext/null fallback. The optional public runtime dependency is
`requirements-credentials.txt`; the private Vault includes keyring in its uv lock.
See the [official keyring interface and supported backends](https://keyring.readthedocs.io/en/latest/).

## Ingress and dispatch

```sh
python3 automation/credentials.py TARGET capture --input PRIVATE_CAPTURE.json
python3 automation/credentials.py TARGET discover --input PRIVATE_METADATA.json
python3 automation/credentials.py TARGET view
python3 automation/work_dispatch.py TARGET --config PRIVATE_ROUTING.json
```

`discover` prompts for a value through hidden input, never argv. `capture` is an opt-in
JSON-pointer adapter for a private (0600), bounded source artifact. Parameters are
`artifact`, `pointer`, `context`, `kind`, and `expires_at`; no raw value belongs in a
metadata/routing file. Existing parsers can call the same capture interface when an
explicit extraction mapping and ownership context are known. This is not automatic
detection of every credential format or inference of an unknown credential's owner.

`context` names exactly `service` (explicit origin), `account_ref`, `role`, `tenant`
and `scope_ref`. Discovery may preserve explicit `unknown` ownership fields in a
pending resource; validation/reuse requires known matching context. The `bind` CLI
completes missing fields from current evidence before any probe, preserving history
and refusing changes to already-known service/account/role/tenant/scope fields.
Wildcards and cross-service/account/role/tenant/scope reuse are
rejected. `expires_at` is an explicit usable-until bound, not an inferred issuer TTL.
Repeated discovery of the same value/context reuses its reference/history.

Configure capability/adapter `credential-validation` with a distinct operator-owned
identity/permission adapter. Its binding, keyed by credential reference, supplies a
ready `hypothesis`, `scope_ref`, `risk`, `argv` and explicit `permissions`. The adapter
receives `VAULT_CREDENTIAL` only in its child environment. It must implement the
actual service probe and emit bounded JSON:

```json
{"auth_status":"authenticated","identity":{"service":"https://service.example","account_ref":"account:fixture","role":"member","tenant":"tenant:fixture"},"permissions":["read:own"]}
```

Identity must match every declared field and requested permissions must be observed.
200/302 alone cannot validate it. Scope, program, risk and execution gates still apply.
Declared URL arguments must match the service origin; adapter code is trusted operator
configuration, and this check is not network isolation or proof of probe semantics.
No raw value is sent to an analysis model. Known discovery-source snippets are withheld.

## Scoped reuse and invalidation

Validated permissions appear as `CREDENTIAL_REF:permission:PERMISSION` capabilities,
without creating a confirmed Finding. They unlock ordinary hypothesis prerequisites.
Per-branch comparison bindings may add `credentials.test` / `credentials.control`,
each containing `credential_ref`, the exact `context`, and required `permission`.
The executor selects/checks the reference and injects it immediately before the tool.
`credentials.choose` returns a unique matching valid resource and refuses ambiguity.
Reuse of a valid token/session does not repeat login validation.

Captured output is private (0600); exact injected values are redacted across stream
chunk boundaries before writing artifacts. Adapters must not emit secrets or transformed
secret values; this is not universal DLP or process-memory isolation. Child environment
access follows the host's normal process security. Original source artifacts remain
private evidence, separate from general logs/prompts and public exports.

Two validation attempts per reference are retained across recovery, with an additional
limit of two attempts per service/account in a 15-minute window across references.
Unknown ownership/applicability is rejected. Lock/rate-limit
signals stop the account's further validations; failed tools become
`validation_blocked`, not proof that a credential is invalid. Structured authentication
failure during reuse withdraws permissions. Expiry/revocation/stale validation evidence
also withdraws capability and pauses dependent work, with reassessment triggers.

```sh
python3 automation/credentials.py TARGET status CREDENTIAL_REF revoked --reason 'Issuer revoked this fixture token'
python3 automation/credentials.py TARGET recover --input PRIVATE_RECOVERY.json
```

Recovery supplies `reference`, fresh `evidence` and `changed_condition`; it requires
remaining original budget and reconciled execution. Revoked/expired references are
not revived. Fresh account-unlock evidence may clear an account stop even after its
old token expires, without reviving that token or resetting attempt counters.
`password` discovery is supported as a protected pending resource, but
generic password login/refresh, arbitrary service adapters, and remote secret transport
are not implemented. The former `credential_reuse_tester.sh` is disabled: no default
password fallback or plaintext account dump runs through that entry.

Validation uses fake stores, synthetic values and real local child processes. Actual
OS keyring access and service-specific probes need environment acceptance; this change
does not claim real credential validity or contact real targets.
