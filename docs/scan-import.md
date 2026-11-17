# Native scan import pilot

The offline adapter imports Nmap XML and Nuclei JSONL into the existing ASG ledger.
It never launches a scanner, resolves a hostname, authorizes an operation, creates
a Finding, or writes a verdict. Nmap produces observations; positive Nuclei
matches produce unverified hypotheses. Matcher failures remain observations.

```sh
python3 automation/scan_import.py <target> nuclei-jsonl <raw.jsonl> \
  --manifest <manifest.json> --context <context.json> --evidence-dir <private-evidence-dir>
```

Manifest fields: `run_id`, `scope_ref`, `tool_version`, `started_at`,
`execution_status` (`completed`, `failed`, `timed_out`, `cancelled`, `interrupted`).
Context fields: `account_ref`, `role`, `conditions` (mapping). Supply explicit
anonymous/unknown references when applicable. Store secret values elsewhere;
these fields are controlled references, never credentials.

For evidence applicability, also capture target `version`, `settings` (explicit
mapping, including `{}` when no settings apply), and `environment` (stable lab /
deployment reference) in context. These are target conditions; `tool_version`
remains the scanner version. Manifest `observed_at` defaults to `started_at`;
optional `expires_at` is an explicit timezone-qualified expiry, with no global
TTL. Missing/wildcard conditions remain `unknown`, never automatically applicable.

Declare the **current actual conditions separately**, using the same ledger:

```sh
python3 automation/evidence_applicability.py <target> \
  --context <current-target-conditions.json> --context-id target
```

Current context accepts `version`, `role`, `settings`, `environment`, optional
`account_ref`, `conditions`, `revision`, and `effective_at`. Set `effective_at`
only for an actual condition change; evidence predating it requires revalidation
even if the setting was subsequently reverted. Context IDs can isolate labs or
test profiles; scan context `context_id` selects one. Historical imports never
declare themselves current. This command records references, not secret values.

`assess_evidence(bindings, current_context, now=None)` returns `status`, `reasons`,
and `requires_revalidation`. Status is `applicable`, `unknown`, `expired`, or
`conditions_changed`. `assess_artifact(artifact, events)` reads the appropriate
latest `evidence_context` ledger event. Applicability and artifact integrity are
separate checks. Explicit bindings on typed evidence participate in the existing
`evidence_refs` proof resolver; unknown/expired/changed bindings cannot grant a
proof. Historical unbound evidence remains readable through the legacy resolver
and is shown as applicability unknown. No historical events are rewritten.

`import_scan(target, source, format, manifest, context, evidence_dir=None)` returns
a receipt. `scan_import` records `success`, `empty`, `partial`, or `failed`;
partial/failed CLI results exit 1. Malformed XML is rejected as a whole. JSONL
keeps valid rows but records invalid line locations as partial, never clean zero.
Execution failure prevents a clean zero-result conclusion. No scan is retried.

`scan_candidate` and `scan_observation` include `candidate_id`, `candidate`,
`source` (parser/version/run metadata), `import_id`, and `artifacts`. Each artifact
pins SHA-256 plus a JSONL line and line hash or XML XPath. `evidence_valid()`
checks the bytes and locator. Private raw bytes are copied without modification
to a content-addressed archive (default: `.scan-evidence/` beside the input).
Canonical events exclude Nuclei request/response/extracted values; inspect the
private raw evidence during independent validation. Evidence retention is manual.

Import receipt identity includes run, parser and complete actor/test context.
Repeated imports are no-ops; changed bytes/metadata under the same receipt require
a new run ID. Logical candidate IDs use target, format, actor/test context and
match location/template/matcher identity, so a new run preserves provenance
without adding a duplicate hypothesis. Changed evidence creates a new analysis
version and marks older analyses stale. Different tools/roles remain separate;
cross-tool semantic deduplication requires a reviewer.
Older ledger events are unchanged. Stop using this command to revert the pilot;
legacy bbflow import remains available. No history migration is required.

Limitations: Nmap pilot reads up hosts and open IP services, not NSE findings or
OS fingerprint conclusions. Explicit input context is trusted metadata and must
describe the actual execution. Source scope references do not establish that a
live operation was authorized. A parsed scanner match is never verification.

## Research receipt

- question: Can native structured formats provide deterministic, offline,
  traceable pilot imports without introducing a full external scan platform?
- checked_at: 2026-11-16.
- queries: direct official Nmap XML format, Nuclei output flags, and pinned
  Nuclei ResultEvent implementation.
- sources read: [Nmap XML documentation](https://nmap.org/book/output-formats-xml-output.html)
  (official sample contains host/address/ports/runstats and recommends XML),
  [Nuclei running/output documentation](https://docs.projectdiscovery.io/opensource/nuclei/running)
  (`-jsonl`, raw response and matcher status flags),
  [Nuclei v3.5.1 output.go](https://github.com/projectdiscovery/nuclei/blob/v3.5.1/pkg/output/output.go)
  (ResultEvent JSON fields).
- applicability: offline native artifacts; output schemas, not scanner execution.
- candidates: existing Vault `hunt_integration.import_bbflow`; native parsers;
  Faraday comparison is recorded by the main integration research receipt.
- decision: build a small stdlib adapter. Existing bbflow reader expects a
  different contract and lacks record locators. Retain it without changing its
  producer. No external parser dependency or upstream code was copied.
- unknowns: full Nmap/Nuclei format coverage is outside this two-format pilot;
  no assertion of compatibility with every past/future scanner version.
- next validation: fixed samples for evidence integrity, errors, identities,
  actor separation, and canonical locking; independent pipeline integration QA.

### Applicability extension receipt

- question: preserve existing invalidation while distinguishing intact bytes from
  evidence valid for today's target version, role, settings and environment.
- checked_at: 2026-11-16.
- queries: local `asg_research` invalidation, `evidence_refs` artifact resolution,
  `logic_vuln_loop.Env`; official RFC 3339 timestamp format.
- local sources inspected: `asg_research.project` already invalidates changed
  source/goal fingerprints; `evidence_refs` resolves hashes and comparison proofs;
  `logic_vuln_loop.Env.matches` uses wildcard version/role/host for execution
  selection. Reuse those mechanisms without interpreting wildcard execution
  eligibility as applicability evidence.
- public source read: [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339), July 2002,
  timezone-qualified timestamp convention. The parser accepts the practical
  timezone-qualified ISO timestamp subset, not all RFC leap-second spellings.
- candidate decision: adapt the existing ledger/reference proof path and add a
  small shared evaluator; no external database, dependency or default TTL.
- applicability: condition identity and explicit expiry are task contracts, not
  requirements claimed from RFC 3339. The RFC supports timestamp representation.
- unknowns: determining the actual current target conditions still requires
  operator/runner observation; this helper cannot infer an unrecorded upgrade.
- validation: fixed clock tests for expiry, missing fields, changed conditions,
  legacy readability, typed-proof gating, and current-context CLI round trip.
