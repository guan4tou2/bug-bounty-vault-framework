---
type: pattern
title: Pattern - Gopher Scheme SSRF Upgrade Stop-Loss (Python Backend)
tags: [pattern, ssrf, gopher, python, requests, stop-loss, redis, bb-pattern]
status: active
category: ssrf
last_updated: 2026-06-04
---

# Pattern - Gopher Scheme SSRF Upgrade Stop-Loss (Python Backend)

> A stop-loss rule for when you've confirmed blind SSRF and are trying to escalate it into full-read SSRF or Redis injection: Python's `requests` library does not support `gopher://`. Attempting a gopher-scheme escalation against a Python backend will always fail — don't waste time on it.

## Trigger Condition

After confirming blind SSRF, attempting to escalate it into full-read SSRF or Redis injection.

## Stop-Loss Point

- The Python `requests` library does not support `gopher://`
- Once the backend is confirmed to be Python (Django / Flask / FastAPI) → **skip the gopher escalation attempt entirely**

## How to Confirm a Python Backend

- `Server` header
- Stack traces
- Framework fingerprinting

## Alternative Escalation Paths

| Scheme | Use |
|--------|-----|
| `dict://` | Redis interaction |
| `file://` | LFI |
| `http://169.254.169.254/` | cloud metadata |

- If `dict://` also doesn't work → downgrade to blind SSRF and scope the impact to TCP-connectivity-only.

## Recording

Once the backend is confirmed Python, record "gopher:// N/A" in the target's recon notes to avoid retrying it next time.

## Related

- [[Pattern - Blind SSRF Oracle Technique]]
- [[Pattern - SSRF Cloud K8s Attack Chain]]
- [[Pattern - SSRF]]
