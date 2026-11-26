# Strategy Optimization — File-Based Learning

Track which strategies work on which target types. Accumulate win/loss records across targets. Use the records to pick better strategies for new engagements.

## Concept

This is a simplified version of reinforcement learning — no ML pipeline, no training loop. Instead: a markdown ledger that records target type × strategy × outcome, and a selection heuristic that queries the ledger when starting a new target.

The feedback loop:
1. Start a target → query the ledger for similar target types → pick highest-ROI strategy
2. Execute the strategy → record outcome
3. Periodically review the ledger → update heuristic weights

## Strategy Ledger

Maintain in `$WORKSHOP_ROOT/STRATEGY_LEDGER.md`:

| Date | Target Type | Strategy | Outcome | Severity | Hours | ROI | Notes |
|------|------------|----------|---------|----------|-------|-----|-------|
| 2026-10-15 | SaaS (B2B) | auth-matrix | finding | High | 4 | High/4=★★ | IDOR in admin API; role enum from JS |
| 2026-10-18 | REST API | api-schema-diff | finding | Medium | 2 | Med/2=★★ | Shadow endpoint, no auth |
| 2026-10-20 | SaaS (B2C) | surface-first | finding | Medium | 6 | Med/6=★ | Took long; surface was huge |
| 2026-10-25 | Mobile app | version-cve | exhausted | — | 3 | 0/3=☆ | All patched; wasted on CVE hunt |
| 2026-11-01 | IoT firmware | firmware-audit | finding | Critical | 8 | Crit/8=★★★ | Hardcoded creds in firmware image |
| 2026-11-10 | GraphQL API | graphql-audit | finding | High | 3 | High/3=★★★ | Introspection + auth bypass chain |

### ROI Calculation

```
ROI = severity_weight / hours
```

| Severity | Weight |
|----------|--------|
| Critical | 4 |
| High | 3 |
| Medium | 2 |
| Low | 1 |
| Exhausted | 0 |

Stars: ★★★ = ROI ≥ 1.0, ★★ = ROI ≥ 0.5, ★ = ROI > 0, ☆ = no finding.

## Strategy Selection Heuristic

When starting a new target:

1. **Query**: filter ledger rows by matching target type
2. **Rank**: sort by ROI descending
3. **Select**: pick the strategy with highest average ROI on similar targets
4. **Fallback**: if no matching target type or < 3 data points, default to `surface-first`
5. **Diversity**: every 5th target, try a strategy with < 3 data points (explore vs exploit)

### Strategy Catalog

| Strategy | Description | Best For |
|----------|-------------|----------|
| `surface-first` | Full surface map before any pattern testing | Unknown targets, large apps |
| `auth-matrix` | Role × endpoint matrix testing | Multi-role SaaS, APIs with auth |
| `version-cve` | Version fingerprint → CVE lookup | Legacy software, known frameworks |
| `business-logic` | Model business flows, test assumptions | Financial, e-commerce, workflows |
| `race-condition` | Concurrency and TOCTOU testing | Payment, inventory, rate-limited APIs |
| `injection-matrix` | Systematic injection per parameter | Input-heavy apps, forms |
| `graphql-audit` | Schema-driven GraphQL testing | GraphQL APIs |
| `api-schema-diff` | Documented vs actual API comparison | Well-documented APIs |
| `firmware-audit` | Binary extraction and analysis | IoT, embedded devices |
| `chain-hunting` | Start from known low-sev, chain upward | Targets with existing findings |

## Strategy Update Protocol

After each target session:

1. Append a row to the Strategy Ledger
2. Record strategy used, outcome, severity, hours, and notes
3. If the wrong strategy was chosen (high effort, no result), note what would have been better

Every 10 entries, review:
- Remove strategies with 0% finding rate across 5+ attempts
- Promote strategies with >60% finding rate to "preferred" for that target type
- Update the heuristic: does the catalog need a new strategy? Does a target type pattern emerge?

## Anti-Patterns

| Anti-Pattern | Why It Fails | Fix |
|-------------|-------------|-----|
| Always `surface-first` | Safe but slow; ignores accumulated knowledge | Query the ledger first |
| Always `version-cve` | Only works on unpatched targets; 0 ROI otherwise | Check target type ROI history |
| Ignoring low-ROI strategies | Some build surface knowledge needed later | Diversity rule: explore every 5th target |
| Over-fitting to one type | "Auth-matrix always works on SaaS" — until it doesn't | Minimum 3 data points before trusting |
| Not recording failures | Only recording wins biases the heuristic | Record every session, including exhausted |

## Integration

- **bb-context-handoff**: include strategy recommendation in HANDOFF notes based on ledger query
- **bb-knowledge-capture**: extract reusable strategy patterns from ledger reviews
- **chain-tracker**: path cost model uses similar ROI weighting for edge prioritization
- **bb-reflexion-retry**: strategy-level reflection — not just "why did this request fail" but "why is this strategy not working on this target type"
