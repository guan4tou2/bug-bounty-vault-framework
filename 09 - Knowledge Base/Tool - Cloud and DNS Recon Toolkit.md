---
type: tool
category: tool
tags: [tool, recon, cloud, aws, azure, entra, iam, dns, subdomain, takeover]
source: user-provided GitHub repo list
added: 2026-06-30
last_updated: 2026-06-30
---

# Tool - Cloud and DNS Recon Toolkit

## TL;DR

Use this as the selection map for cloud account review, cloud key triage, and DNS/subdomain expansion. It does not replace target scope review: credentialed cloud enumeration, exploit simulation, high-volume DNS resolving, and takeover verification still follow the workspace safety gates and VPS boundary.

## Tool Selection

| Phase | Tool | Best use | Notes |
|---|---|---|---|
| Cloud posture audit | [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Multi-cloud security configuration review | Good first pass when a client or authorized test account provides cloud credentials. Treat findings as configuration leads, not proof of exploitability. |
| AWS situational awareness | [cloudfox](https://github.com/BishopFox/cloudfox) | Enumerate practical AWS attack surface from available credentials | Pair with manual validation. Useful after leaked key triage or authorized account access. |
| AWS exploit simulation | [pacu](https://github.com/rhinosecuritylabs/pacu) | Authorized AWS exploitation framework | Use only with explicit authorization and an isolated profile. Avoid destructive modules and record every action in the Operation Log. |
| AWS IAM graphing | [PMapper](https://github.com/nccgroup/PMapper) | Model IAM privileges and escalation paths | Best after collecting IAM users, roles, policies, and trust relationships. |
| Azure resource recon | [MicroBurst](https://github.com/NetSPI/MicroBurst) | Azure subdomain, storage, and resource enumeration | PowerShell-based. Good for Azure public exposure and authenticated recon. |
| Entra ID graphing | [ROADtools](https://github.com/dirkjanm/ROADtools) | Entra ID / Azure AD directory enumeration and relationship analysis | Use when tokens, tenant access, or account credentials are in scope. |
| Takeover triage | [subzy](https://github.com/PentestPad/subzy) | Detect dangling CNAME / takeover fingerprints | Fast candidate finder. Confirm manually with DNS, provider behavior, and ownership rules before reporting. |
| DNS permutation | [gotator](https://github.com/Josue87/gotator) | Generate domain permutations from known subdomains | Feed only high-quality seed data. Resolve output with wildcard-aware tooling. |
| DNS resolve / brute force | [puredns](https://github.com/d3mondev/puredns) | Fast resolving, brute force, and wildcard filtering | Prefer VPS for large lists. Keep resolver quality fresh or results become noisy. |

## Workflow Fit

| Situation | Start with | Then |
|---|---|---|
| Leaked AWS key or scoped cloud account | cloudfox | PMapper for IAM paths, ScoutSuite for broad posture, Pacu only for authorized exploit simulation |
| Azure / Entra tenant access | ROADtools | MicroBurst for Azure storage/resource exposure |
| New apex domain recon | gotator + puredns | subzy + nuclei takeover templates, then manual provider-specific verification |
| Cloud storage exposure hunt | ScoutSuite or cloudfox | S3Scanner and manual bucket/object ACL checks |

## bbflow Integration

VPS `<your-vps>` has a manual `bbflow` entrypoint for the DNS trio:

```bash
cd ~/bbflow
./bbflow.sh dns-toolkit <domain> [known_subs_file]
```

Pipeline:

```text
known seeds -> gotator permutations -> puredns + massdns resolve -> subzy takeover fingerprint triage
```

Output goes to:

```text
$BBFLOW_WORKSPACE/workshop/<domain>/dns_toolkit/
```

The command is intentionally explicit-only. It is not part of default `hunt` or `flow`, because DNS permutation and takeover probing require target scope review and Operation Log when used on real programs.

Smoke test on `example.com`:

| Mode | Seeds | Permutations | Resolved | Takeover-interest |
|---|---:|---:|---:|---:|
| bare domain | 1 | 29 | 1 | 0 |
| seed file (`api`, `www`) | 3 | 306 | 2 | 0 |

Additional regression results:

| Test | Result |
|---|---|
| URL normalization (`https://www.example.com:443/path`) | normalizes to `example.com` and writes the expected report |
| Missing seed file | exits `1` without creating output directories |
| Invalid domain (`bad_domain`) | exits `1` without creating output directories |
| `bbflow dry-run` | 65 passed, 3 pre-existing warnings, 0 errors |
| `bbflow test` | 19 null-case hunters passed on `example.com` |

Cloud tool availability on `<your-vps>`:

| Tool | Status | Smoke test |
|---|---|---|
| cloudfox | installed from official `linux-arm64` release zip | `cloudfox --version` -> `2.0.5`; help lists AWS/Azure/GCP commands |
| ScoutSuite | installed with `uv tool install scoutsuite` | `scout --help` lists AWS/GCP/Azure/Aliyun/OCI/Kubernetes/DO providers |
| PMapper | installed with `uv tool install --python 3.9 principalmapper` | `pmapper --help` works; Python 3.11 crashed due `collections.Mapping` compatibility |
| ROADrecon | installed with `uv tool install roadrecon` | `roadrecon --help` works |
| ROADtx | installed with `uv tool install roadtx` | `roadtx --help` works |
| Pacu | installed with `uv tool install pacu` | `pacu --help` works; creates local sqlite DB on first run |
| PowerShell | installed with `sudo snap install powershell --classic` | `pwsh` 7.6.3 works |
| MicroBurst | cloned to `~/Tools/MicroBurst` | `Import-Module ~/Tools/MicroBurst/MicroBurst.psm1` works; Az/AzureAD/MSOnline modules are not installed, REST/Misc functions load |

`bbflow tools` now includes the installed cloud tools in the inventory. They remain inventory/help-only; none are invoked by default `hunt` or `flow`.

The VPS also has an explicit safety wrapper:

```bash
cd ~/bbflow
./bbflow.sh cloud-tools help
./bbflow.sh cloud-tools status
./bbflow.sh cloud-tools check
```

Behavior:

| Action | Result |
|---|---|
| `help` | prints the safety contract |
| `status` | lists installed cloud tools and required gates |
| `check` | runs bounded help/version/import probes only |
| `run`, `exec`, `scan`, `enum`, `gather`, `graph`, `whoami` | blocked with exit `2` |

`cloud-tools check` confirmed MicroBurst imports 27 functions with REST/Misc modules; Az/AzureAD/MSOnline modules are still absent. This wrapper intentionally does not run provider APIs, credential import, account graphing, Pacu modules, or cloud enumeration.

## Safety Boundaries

- Do not run cloud exploit modules against production accounts unless the program explicitly authorizes that action.
- Keep cloud profiles, tenants, and test accounts separated. Never mix personal cloud credentials with target credentials.
- High-volume DNS brute force and resolving belongs on the VPS unless the task is a tiny local sanity check.
- Takeover tools only identify candidates. Report only after proving ownership state or using the program-approved takeover workflow.

## Existing KB Coverage

- [[09 - Knowledge Base/wiki/32-cloud-key-abuse|Cloud key abuse wiki]] already covers cloudfox, PMapper, ROADtools, MicroBurst, and ScoutSuite snippets.
- [[Playbook - Recon Methodology]] and [[Pattern - Subdomain Takeover Fastly]] already cover puredns and subzy in recon flows.
- [[Tool - Arsenal Index]] is the broad installation and phase index; this page is the cloud/DNS decision layer.

## Knowledge Capture

- Reusable learning: cloud and DNS tooling should be selected by workflow phase, not stored as an undifferentiated repo list.
- Existing KB coverage: partial and scattered across Arsenal Index, cloud-key-abuse wiki, recon playbooks, and external source index.
- Destination: `Tool - Cloud and DNS Recon Toolkit.md` plus index pointers.
- New note needed: yes.
- Pattern / Lesson / Checklist update: no new vuln pattern; this is tool-selection guidance.
- bbflow update idea: implemented explicit-only `bbflow dns-toolkit <domain> [known_subs_file]` on VPS; keep out of default hunt/flow until target scope and Operation Log are present.
- Recon note link: n/a.
- Done: created canonical tool note, linked it from indexes, and documented VPS smoke test.
