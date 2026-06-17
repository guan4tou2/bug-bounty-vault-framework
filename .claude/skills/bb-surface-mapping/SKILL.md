---
name: bb-surface-mapping
description: Use when starting work on any target — after recon, before any pattern/hunter/scan/dedup — to force vuln-agnostic full attack-surface mapping that counters the streetlight effect (pattern tunnel vision). Triggers include start recon, explore, map the attack surface.
---

# Bug Bounty — Surface Mapping (explore-first, anti-streetlight)

This is the **FIRST gate in the candidate lifecycle**. It exists because relying on a known pattern/hunter library biases hunting toward known vulnerability types and misses novel surface — the "streetlight effect" (searching only where the light is good).

**Map the full surface vuln-agnostically and ask "how could this break?" per element BEFORE running any pattern/hunter/scanner. Patterns are a post-mapping checklist, not the search starting point.**

## Trigger

Run this at the very start of working a target — after recon enumeration, before any pattern/hunter/scan/dedup:

- "start recon", "explore", "map the attack surface", "begin hunting"
- whenever you are about to run a scanner / hunter / grep-for-known-sinks → STOP, map first

## Hard Rule

A target that has discovered endpoints but an **empty Attack Surface Map is incomplete**. Do not proceed to pattern-matching, scanning, or close a session by skipping this. If your vault has an audit/lint step, it should fail this condition (the reference automation does — a target with Discovered Paths and an empty Surface Map is a hard violation).

**Scan-time block:** the reference automation ships `automation/surface_map_gate.sh`, a `PreToolUse(Bash)` hook that **blocks the scan in real time** — `bbflow hunt <target>` / `hunt-*.sh <target>` exits 2 when that target's RECON_DB has Discovered Paths but an empty Surface Map. Loud override: prefix with `BB_SKIP_SURFACE_GATE=1`.

## Method

0. **Run a recon floor first** (do not skip). Recon tool output is the raw material for the Surface Map; manual browsing alone does not count. At minimum: subdomain enumeration + live-host probing + historical URL mining (e.g. wayback/CDX) + crawl + a known-vuln scan pass + JS analysis. See `Playbook - Recon`.
1. **Enumerate every surface element** into `RECON_DB.md ## Attack Surface Map`: one row per element. **Tag each row with its recon source** (crawler / historical / subdomain enum / scanner / manual…). Too many `manual` rows means the recon floor was not run to completion — treat that as a warning, not a result.
2. **Per element, write a free-text "how could this break?" hypothesis.** This forces thinking. Tick-boxes are forbidden; the column cannot be empty and cannot just name a vuln type.
3. **Mark anomalies first** (homegrown framework, non-standard header/auth scheme, unusual parameter naming). That is where pattern libraries are blind and where novel bugs hide.
4. **Test each hypothesis.**
5. **ONLY THEN** run pattern/hunter/scanner checks as a "did I miss a known type?" backstop — never as the starting point.

## The 8 vuln-agnostic dimensions (do not skip any)

Every input/parameter · every role (auth matrix) · every state transition (multi-step flow) · every trust boundary · every integration / third party · every dependency / framework · every file / upload path · every business flow — plus the **anomaly sweep** (anything homegrown or non-standard).

## Anti-gaming

- Map at the **element level, not the dimension level** — you cannot satisfy this by pasting 8 boilerplate lines.
- Every discovered endpoint must have a matching Surface Map row (cross-check it).
- The "how could this break?" column must contain a real hypothesis, not a vuln-type name.

## Catch-all / false-200 filter (run before trusting any 200)

Before mapping a host's "live" endpoints, screen for SPA / framework catch-all behavior: if a host returns 200 on a random non-existent path, then **HTTP 200 ≠ endpoint exists** and the catch-all is immune to header/IP path tricks. Compare the homepage response against a random-path response; if they are effectively identical, do not enter path-guess 200s into the Surface Map as real endpoints.

## After: tag discovery mode

When a Surface Map hypothesis becomes a Finding, tag it `discovery_mode: exploration`. When a pattern/hunter/scanner finds it, tag `discovery_mode: pattern`. Track the exploration:pattern ratio — if pattern dominates, exploration is starved and the streetlight effect has won.

## Next step (mandatory hand-off — do not stop here)

A completed Surface Map **must** flow into a testing phase. "Mapped, therefore done" is not allowed:

```text
bb-surface-mapping → bb-web-vuln-scan → [finding]    → bb-exploit-chain → chain DAG
                                       → [no finding] → mark Exhausted
```

1. Load `bb-web-vuln-scan` — OWASP Top 10 coverage + injection matrix + version→CVE + WAF bypass.
2. On any finding → run `bb-exploit-chain` (the 6-question chain) before moving to the next system.
3. Persist chain results as an Exploit Chain DAG so every path is tracked to ✅ or ❌.

## Cross-References

- `09 - Knowledge Base/Playbook - Recon.md` (the recon floor that feeds this map)
- `docs/architecture-closed-loop.md` (where this gate sits in the 4-ring loop)
- `bb-web-vuln-scan` (the mandatory next gate)
- `bb-dedup-finding` (runs LATER, at Finding creation — not before mapping)
- `bb-scope-safety-check`, `bb-attack-chain-review`, `bb-evidence-readiness`
