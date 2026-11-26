# Reference Card — RL Strategy Selection (Simplified)

> Document-based strategy optimization. Maps target type × approach × historical outcome to recommended hunting strategies. No ML pipeline — structured lookup from accumulated experience.

## Concept

Reinforcement learning selects actions that maximize cumulative reward. This reference card applies the same principle as a lookup table: given a target profile, choose the strategy with the best historical success rate, and update the table when outcomes arrive.

**State** = target profile (type, tech stack, program maturity, attack surface size)
**Action** = hunting strategy (approach, tool chain, focus area)
**Reward** = outcome (finding accepted, bounty, rejected, duplicate, N/A)

## Strategy Selection Table

Look up the target profile → pick the highest-reward strategy → adjust based on personal history.

### By Target Type

| Target Type | Recommended First Strategy | Fallback Strategy | Anti-Pattern |
|-------------|--------------------------|-------------------|-------------|
| **SaaS web app** (multi-tenant) | AuthMatrix (role × endpoint) → IDOR sweep | Business logic chains | Spray-and-pray nuclei — everyone does it |
| **API-only** (REST/GraphQL) | Schema diff (`api_schema_diff.py`) → shadow endpoint hunt | Parameter pollution, mass assignment | Ignoring undocumented endpoints |
| **Mobile app backend** | Certificate pinning bypass → API reverse engineer → AuthMatrix | Hardcoded secrets, debug endpoints | Testing only the documented API |
| **Single-page app** (React/Vue/Angular) | JS source map mining → hidden endpoints → auth bypass | Client-side access control bypass | Assuming client-side checks are server-enforced |
| **Legacy enterprise** (Java/.NET) | Version → CVE precheck → known exploit chains | Deserialization, XXE, SSRF | Skipping version-CVE because "it's patched" |
| **IoT / firmware** | Firmware extraction → hardcoded creds → debug interfaces | Command injection in CGI, UART/JTAG | Treating it like a web app |
| **Cloud-native** (K8s/serverless) | Misconfiguration (S3/GCS/Azure buckets) → SSRF to metadata | Service mesh auth bypass, function injection | Ignoring cloud-specific attack surface |

### By Program Maturity

| Program Maturity | Strategy Modifier | Reasoning |
|-----------------|-------------------|-----------|
| **New program** (< 6 months) | Surface-level vulns still open — cast wide | Low-hanging fruit not yet picked |
| **Mature program** (1-3 years) | Chain attacks, business logic, race conditions | Simple vulns patched; chains remain |
| **Very mature** (3+ years, top researchers active) | Deep business logic, novel attack classes, state-based | Standard approaches exhausted |

### By Attack Surface Size

| Surface Size | Strategy | Time Allocation |
|-------------|----------|----------------|
| **Small** (< 20 endpoints) | Deep dive each endpoint, full verb matrix, parameter fuzz | 80% depth, 20% breadth |
| **Medium** (20-100 endpoints) | Interest-score ranking → top-20 deep dive | 50% depth, 50% breadth |
| **Large** (100+ endpoints) | Automated surface scan → anomaly-driven deep dive | 20% depth, 80% breadth initially, then flip |

## Reward Signal Mapping

Track outcomes to update strategy weights:

| Outcome | Reward | Weight Update |
|---------|--------|---------------|
| **Accepted + bounty** | +3 | Strong signal — increase strategy weight for this target type |
| **Triaged (pending)** | +1 | Positive signal — strategy direction correct |
| **Duplicate** | 0 | Neutral — finding was real but someone else found it faster |
| **N/A (not applicable)** | -1 | Weak negative — reassess impact argument, not necessarily strategy |
| **Informational (won't fix)** | -1 | Reassess severity calibration, not strategy |
| **Not reproducible** | -2 | Evidence quality problem — tighten verification step |

## Personal History Table

Maintain in `workshop/STRATEGY_LOG.md`:

```markdown
## Strategy Log

| Date | Target Type | Strategy | Outcome | Reward | Notes |
|------|------------|----------|---------|--------|-------|
| 2026-11-15 | SaaS web app | AuthMatrix → IDOR | Accepted +$500 | +3 | Horizontal IDOR in user profile API |
| 2026-11-20 | API-only | Schema diff → shadow | Duplicate | 0 | /internal/debug found but already reported |
| 2026-11-25 | Legacy .NET | Version-CVE → deser | N/A | -1 | Deserialization blocked by WAF |
```

### Updating Weights

After every 5 outcomes per target type, review:

1. **Which strategies produced +3 rewards?** → Promote to "Recommended First"
2. **Which strategies produced -1/-2?** → Demote or add conditions
3. **Which target types have no +3?** → Research gap — run `bb-gap-research`

## Decision Flowchart

```
1. Classify target → Target Type table → get recommended strategy
2. Check program maturity → apply modifier
3. Check surface size → adjust depth/breadth ratio
4. Check personal history → if this strategy has -2 on this target type, skip to fallback
5. Execute strategy with surface mapping as the front gate
6. Record outcome in STRATEGY_LOG.md
7. After 5 outcomes per type, review and update weights
```

## Integration Points

- **Session start**: check STRATEGY_LOG.md for prior outcomes on this target type
- **Strategy selection**: this reference card → `bb-surface-mapping` → selected approach
- **Outcome recording**: after triage response → update STRATEGY_LOG.md
- **Retrospective**: `lessons-miner` agent feeds patterns back to this card
- **Knowledge capture**: `bb-knowledge-capture` for novel strategy discoveries

## Cross-References

- `bb-surface-mapping` — front gate before any strategy
- `bb-web-vuln-scan` — OWASP coverage after strategy-directed testing
- `bb-gap-research` — when a target type has no successful strategies
- `bb-knowledge-capture` — capture novel strategy patterns
- `Reference Card - Severity Calibration Anchors` — calibrate impact assessment
- `api_schema_diff.py` — API schema comparison tool
- `bb-auth-matrix` — structured authorization testing
