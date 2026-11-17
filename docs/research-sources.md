# Supplemental research as ASG work

`research_sources.py` records a decision question, known/excluded explanations,
current evidence, explicitly public technical terms and a refresh deadline. With a
configured public profile, obstruction/conflict/no-progress reassessment events can
request this work. Explicit requests also cover new products, pre-build reuse research
and root-cause comparison. The current implementation does not infer all such events
from arbitrary text or automatically create Skills.

```sh
python3 automation/research_sources.py TARGET profile --input PUBLIC_PROFILE.json
python3 automation/research_sources.py TARGET request --input PRIVATE_QUESTION.json
python3 automation/research_sources.py TARGET view
```

The profile supplies `public_terms`, product `version` and `allowed_domains` for
primary sources. Questions/decisions/excluded explanations and raw evidence remain
local. Only the explicitly public product/version/technical labels form the external
query. URLs, IP addresses, assignments and opaque values are rejected as query terms;
the operator remains responsible for declaring those labels public.

Local KB retrieval runs first using existing lexical retrieval and at most three
hits. Local hits are context, not a claim that changing product behavior is current.
External retrieval is capability `research-retrieval` / adapter `argv-research`.
No search service, daemon or new top-level orchestrator is installed.

The binding supplies `hypothesis`, `scope_ref`, `risk` and operator `provider_argv`,
which contains one literal `{public_query}` argument and may use `{artifact_dir}`
as the local destination for fetched source files. Sources must resolve inside that
retrieval work directory; arbitrary local paths are rejected. The controlled executor
runs the configured provider, with timeout/lifecycle/policy handling. A missing provider
is visible as unavailable work, not a successful search or a new approval requirement.

The provider must search **and read** primary sources, then return a JSON source bundle
on stdout. It cannot substitute search snippets or model summaries. Each of at most
three sources supplies `id`, HTTPS `url` on an allowed domain, `version`,
`prerequisites`, `limitations`, actual `checked_at`, `retrieval_kind: full_source`, local
`path` and `sha256`. Original source bytes are pinned and checked. Receipts are claims
by the trusted provider, not independent proof that a URL served those exact bytes.
Publication/update dates may remain unknown; the current contract records read time
and declared applicability rather than inferring dates from a search summary.

`research-source-analysis` uses the normal tool-less analysis adapter to review selected
source content and method cards. It returns an evidence-linked adopt/reject/insufficient
decision. Adoption requires matching declared version evidence and creates an exploration
proposal with prerequisites; normal hypothesis adoption, scope and actual testing still
follow. The source remains `source-claimed`, never an observed target result.

Question/profile/evidence signatures reuse prior research until conditions or the
configured 1–168 hour refresh horizon change. Stale/altered cards are rejected. Empty
search results retain an `insufficient` gap and do not refute a hypothesis. Changed
source artifacts make dependent exploration proposals stale, preserving original
observations and verdict history. Version applicability and adapter probe semantics
still require judgment; exact version matching is not a general semantic-version solver.

Fixture validation runs the provider through a real local process and supplies synthetic
source files. A real external search provider and representative decision-quality/token
evaluation have not been exercised by these tests.
