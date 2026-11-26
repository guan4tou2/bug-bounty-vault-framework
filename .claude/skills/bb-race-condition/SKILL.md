---
name: bb-race-condition
description: "Use when testing race conditions, TOCTOU, single-packet attacks, or concurrency bugs. Covers limit bypass, state confusion, and check-then-act patterns in rate limits, balance operations, coupon redemption, token consumption, and file processing."
---

# Bug Bounty — Race Condition

Structured race condition and TOCTOU testing. Identifies check-then-act patterns, executes concurrent requests with proper synchronization, and verifies real impact.

## Trigger

- Target has rate limits, balance/credit operations, coupon/voucher redemption
- File upload with server-side processing (rename, move, convert)
- One-time-use tokens (password reset, invite, verification)
- Inventory/stock operations (purchase, reserve, claim)
- State transitions (order status, approval workflows)
- User says "race condition", "concurrency", "single-packet", "limit bypass", "double spend"

## Protocol

### Step 1: Identify Race Windows

Map state-changing operations with check-then-act patterns:

| Operation | Check Phase | Act Phase | Race Window |
|-----------|------------|-----------|-------------|
| Coupon redeem | Is coupon valid + unused? | Mark used + apply discount | Between check and mark |
| Balance transfer | Is balance ≥ amount? | Deduct balance | Between check and deduct |
| Password reset | Is token valid? | Consume token + set password | Between validate and consume |
| File upload | Save to temp → process → move | Processing time | During async processing |
| Rate limit | Count < threshold? | Increment counter | Between count and increment |

### Step 2: Classify Target Type

| Type | Description | Expected Result on Win |
|------|-------------|----------------------|
| Limit overrun | Use N times what should be 1 | Coupon applied 2×, rate limit bypassed |
| State confusion | Get inconsistent state | Partial writes, mixed responses |
| TOCTOU | Bypass check via timing | Token reused, auth check skipped |
| Double spend | Same resource consumed twice | Balance deducted once, credited twice |

### Step 3: Prepare Test

1. Identify the exact HTTP request(s) that trigger the race window
2. Determine the synchronization point — which requests must arrive simultaneously?
3. Prepare N identical requests (start with N=10)
4. Set up monitoring — how to detect a successful race:
   - Response differences (status code, body content, balance value)
   - Side effects (email count, database state, audit log entries)

### Step 4: Choose Synchronization Technique

| Target Protocol | Technique | How |
|----------------|-----------|-----|
| HTTP/2 | Single-packet attack | All requests in one TCP packet — server processes simultaneously |
| HTTP/1.1 | Last-byte sync | Send N requests minus last byte → send all last bytes at once |
| HTTP/1.1 (multi-conn) | Connection pool + barrier | Open N connections → release all simultaneously |
| WebSocket | Burst messages | Send N messages in rapid succession on one connection |

Tools: turbo-intruder (Burp Suite), curl --parallel, Python asyncio + aiohttp, Burp Repeater group send.

### Step 5: Execute

1. Run with N=5 first (minimize risk)
2. Collect ALL responses — status codes, timestamps, response bodies
3. Count successes — did more than 1 succeed when only 1 should?
4. If no race detected at N=5, increase to N=10, then N=20 max

### Step 6: Verify Impact

| Verification | Method | Why |
|-------------|--------|-----|
| Real state change | Check balance/count/status via separate GET | Distinguish server-side vs client-side |
| Not duplicate responses | Different response bodies or database state | Server may return 200 to all but process one |
| Persistent effect | Check after delay (30s, 60s) | Race may be rolled back asynchronously |
| Quantify impact | Calculate exact duplicate amount/count | "Applied 2× instead of 1×" with values |

### Step 7: Evidence Collection

```markdown
## Race Condition Evidence
- Target operation: <what was raced>
- Race window: <check → act description>
- Requests sent: <N> concurrent
- Technique: <single-packet / last-byte sync / other>
- Successful extra operations: <count>
- Impact: <quantified — e.g., "$10 coupon applied 3×, net $20 unearned discount">
- Request/response pairs: <with timestamps showing simultaneity>
```

## Output Format

```markdown
## Race Condition — <target>

### Race Window Analysis
| Operation | Window | Type | Testable? |
|-----------|--------|------|-----------|

### Test Results
| Operation | N | Technique | Wins | Expected | Actual | Impact |
|-----------|---|-----------|------|----------|--------|--------|

### Recommended Findings
1. <finding with quantified impact>
```

## Anti-Patterns

| Anti-Pattern | Why It Fails | Fix |
|-------------|-------------|-----|
| No race window analysis | Sending concurrent requests randomly | Step 1: map check-then-act first |
| N=1000 requests | DoS risk, not race testing | Start N=5, max N=20 |
| No impact verification | Duplicate 200s ≠ duplicate state changes | Step 6: verify server-side state |
| Testing only rate limits | Misses business logic races | Test all state-changing operations |
| Ignoring HTTP version | Wrong sync technique for the protocol | Match technique to HTTP/1.1 vs HTTP/2 |
| Claiming win without quantification | "Race condition exists" is not a finding | Quantify: how many extra? what value? |

## Hard Rules

- Start with small N (5–10) — concurrent requests at scale are indistinguishable from DoS
- Never test financial transactions without explicit scope authorization
- Never test destructive operations (delete, cancel) — only additive ones
- Record every race test in Operation Log with exact N and timestamps
- Run `bb-scope-safety-check` before first race test on any target
- Verify impact is real and persistent, not just duplicate HTTP responses

## Cross-References

- `bb-scope-safety-check` — before any race testing
- `bb-evidence-readiness` — prepare concurrent request evidence
- `bb-exploit-chain` — chain race wins into higher impact
- `bb-counterevidence` — challenge whether race is exploitable in production
- `bb-reflexion-retry` — if race test fails, diagnose before retry
