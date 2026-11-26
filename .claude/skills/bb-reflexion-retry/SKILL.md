---
name: bb-reflexion-retry
description: "Use when a tool call, exploit attempt, or validation step fails — structured reflection before retry instead of blind repetition. Triggers: tool failure, 'retry', 'try again', exploit returned unexpected result, scan error, authentication failure, repeated failure, 'why did that fail'."
---

# Bug Bounty — Reflexion Retry

Structured failure analysis before retry. Prevents wasted tokens on blind repetition by forcing a diagnosis step between attempts.

## Trigger

- Any tool call returns an error or unexpected result
- Exploit attempt fails (wrong status code, no impact, blocked)
- Scan or recon tool exits non-zero
- Authentication or authorization step fails
- User says "try again", "retry", "why did that fail"
- Same action has failed 2+ times

## Protocol

### Step 1: Capture Failure Context

Record before any retry:

```markdown
## Failure Record
- Action: <what was attempted>
- Tool/command: <exact command or tool call>
- Expected result: <what should have happened>
- Actual result: <what happened — exact error, status code, output>
- Attempt number: <N>
```

### Step 2: Diagnose (mandatory — do not skip)

Answer ALL five questions before retrying:

| # | Question | Purpose |
|---|----------|---------|
| 1 | **What failed?** — exact error class (network, auth, input, logic, scope, rate limit, WAF) | Classify the failure mode |
| 2 | **Why did it fail?** — root cause hypothesis (not "it didn't work") | Force causal reasoning |
| 3 | **What assumption was wrong?** — which premise of the attempt was invalid | Expose hidden assumptions |
| 4 | **What changed or what do I know now?** — new information from the failure itself | Extract signal from failure |
| 5 | **What specifically will be different in the next attempt?** — concrete change, not "try harder" | Prevent identical retry |

### Step 3: Classify and Act

| Classification | Action | Example |
|---------------|--------|---------|
| **Same input, same environment** | STOP — identical retry is waste | Repeating the same curl after 403 |
| **Input adjustable** | Modify input based on diagnosis | Change payload encoding, different parameter |
| **Environment changed** | Retry with same input is valid | Token refreshed, rate limit window passed |
| **Wrong tool** | Switch tool or approach | curl → browser, GET → POST, manual → script |
| **Scope/auth issue** | Escalate — do not retry | Out-of-scope, insufficient auth, WAF permanent block |
| **Intermittent** | Retry once, then escalate | Network timeout, server 500 (but only once) |

### Step 4: Execute Modified Attempt

- Apply the specific change identified in Step 2 Q5
- Record the modification in Operation Log
- If this is attempt 3+, consider a fundamentally different approach

### Step 5: Update Knowledge

After success OR final failure:

```markdown
## Reflexion Outcome
- Attempts: <total>
- Root cause: <confirmed cause>
- What worked: <the change that succeeded> OR <why all attempts failed>
- Reusable lesson: <pattern for similar targets — if any>
```

If a reusable pattern emerges, recommend `bb-knowledge-capture`.

## Escalation Rules

| Condition | Action |
|-----------|--------|
| 3 consecutive failures, same error class | Stop retrying. Change approach entirely or park |
| Failure reveals scope issue | Stop. Run `bb-scope-safety-check` |
| Failure reveals service impact | Stop. Run `bb-incident-response` |
| Failure is auth/WAF block | Do not brute-force. Analyze the block mechanism |
| Token budget pressure (< 2M remaining) | Max 1 retry, then park with HANDOFF note |

## Anti-Patterns (what this skill prevents)

| Anti-Pattern | Why It Fails | Reflexion Fix |
|-------------|-------------|---------------|
| Identical retry | Same input + same state = same result | Q5 forces a concrete change |
| "Try harder" | Vague intent, no specific modification | Q3 exposes the wrong assumption |
| Payload spray | Throwing 50 variants without understanding | Q2 forces root cause first |
| Ignoring failure signal | Error messages contain information | Q4 extracts signal from failure |
| Retry loop | 10+ attempts burning tokens | Escalation at attempt 3 |

## Output Format

```markdown
## Reflexion — <action>
- Attempt: <N>
- Failure class: <network|auth|input|logic|scope|rate-limit|WAF|intermittent>
- Root cause: <hypothesis>
- Wrong assumption: <what was invalid>
- New information: <signal from failure>
- Next action: <specific modification> OR <park/escalate — reason>
```

## Cross-References

- `bb-scope-safety-check` — when failure reveals scope issues
- `bb-incident-response` — when failure reveals service impact
- `bb-knowledge-capture` — when failure patterns are reusable
- `bb-context-handoff` — when budget prevents further retry
- `bb-attempt-recorder` — record final negative result
