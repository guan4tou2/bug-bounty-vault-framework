---
name: bb-race-condition
description: "Race condition and TOCTOU testing framework. Triggers: 'race condition', 'TOCTOU', 'double spend', 'single packet attack', 'concurrent requests', 'limit bypass', coupon/balance/vote/inventory endpoint discovered."
---

# Bug Bounty — Race Condition Testing

Structured methodology for testing time-of-check-to-time-of-use (TOCTOU) vulnerabilities using single-packet attack techniques.

## Trigger

- State-changing endpoint that enforces a limit (balance, coupon, vote, invitation, quantity)
- Coupon/voucher/credit/balance/inventory/vote endpoint discovered
- Any "apply once" or "limited use" operation
- User says "race condition", "TOCTOU", "double spend", "concurrent", "single packet"

## Phase 1: Identify Candidates

| Category | Example Endpoint | What Breaks |
|----------|-----------------|-------------|
| Balance/credit | Apply coupon, transfer funds, redeem points | Double-spend |
| Inventory | Purchase limited item, claim offer | Oversell |
| Voting/rating | Upvote, like, rate | Multi-vote |
| Invitation/referral | Send invite, claim referral bonus | Multi-claim |
| Account operations | Register with same email, password reset | Duplicate account, token reuse |
| File upload | Upload → process → move | Overwrite, TOCTOU on validation |
| Feature flags | Enable/disable + use simultaneously | State inconsistency |
| Rate limits | Send N requests simultaneously | Bypass rate limiter |

## Phase 2: Technique Selection

### Single-Packet Attack — HTTP/1.1 (last-byte sync)

1. Open N TCP connections to target
2. Send all but the last byte of each request on each connection
3. Send all final bytes simultaneously
4. Synchronizes arrival at the server within microseconds

### Single-Packet Attack — HTTP/2

1. Open one HTTP/2 connection
2. Prepare N requests as HTTP/2 frames
3. Send all frames in a single TCP packet (multiplexing)
4. Tightest possible timing — server processes all from one packet

### Tool Options

| Tool | Technique | Precision | Notes |
|------|-----------|-----------|-------|
| Turbo Intruder (Burp) | Single-packet, connection warming | Highest | Requires Burp Suite Pro |
| `curl --parallel` | HTTP/2 multiplexing | Medium | Quick, scriptable |
| Custom Python (httpx/h2) | Full frame-level control | High | For custom scenarios |
| `fetch()` + `Promise.all` | Browser-level concurrency | Lowest | Last resort |

## Phase 3: Execution Protocol

1. **Baseline**: Send the operation once normally, record state (balance, count, inventory)
2. **Dry run**: Send 2 concurrent identical requests, compare results
3. **Full test**: Send 5 concurrent requests (increase to 10-20 if 5 shows no effect)
4. **Verification**: Check server-side state — response codes alone are insufficient
5. **Variants**:
   - Same operation, same user, concurrent (classic race)
   - Same operation, different users, same resource (contention)
   - Different operations on same resource (read during write)

## Phase 4: Detection & Evidence

| Signal | Interpretation |
|--------|---------------|
| All N requests return 200 with state change | Strong race — server did not serialize |
| N-1 return 200, 1 returns error | Partial race — some requests slip through |
| All return 200 but only 1 state change | Server serialized correctly (not vulnerable) |
| Response time variance < 5ms across N | Requests likely hit the same processing window |

Evidence must include:
- **Pre-state**: value before test (balance, count, inventory)
- **Request timing**: all requests within the same millisecond window
- **All N responses**: status code + relevant body field for each
- **Post-state**: value after test
- **Delta**: expected vs actual (e.g., "balance decreased by $10 once but coupon applied twice")

## Phase 5: Output Format

```markdown
## Race Condition Test — <endpoint>
- Endpoint: <URL + method>
- Category: <balance/inventory/voting/account/...>
- Technique: <single-packet HTTP/1.1 | HTTP/2 multiplexing | other>
- Concurrent requests: <N>
- Pre-state: <value>
- Post-state: <value>
- Expected post-state: <value>
- Delta: <expected - actual>
- Result: vulnerable / not vulnerable / inconclusive
- Kill chain stage: <typically privilege-escalation or impact>
- Severity: <reference Severity Calibration Anchors>
- Evidence: <timing log, response bodies, state proof>
```

## Safety Rules

- Run `bb-scope-safety-check` before testing
- Start with the MINIMUM concurrency (2-5) — do not blast 50+ from the start
- Record pre-state before every test
- If the race creates irreversible state (real money, real purchase): STOP after first successful proof, do NOT repeat
- If no test/sandbox environment: warn user before testing balance/payment operations
- DELETE operations: do NOT test unless explicitly authorized and the resource is test data
- Operation Log: record every race test with timing, concurrency level, and pre/post state

## Cross-References

- `bb-scope-safety-check` — before active testing
- `bb-exploit-chain` — chain race into higher impact
- `bb-evidence-readiness` — evidence quality
- `bb-web-vuln-scan` — standard vuln testing
- `Reference Card - Severity Calibration Anchors` — severity assessment
