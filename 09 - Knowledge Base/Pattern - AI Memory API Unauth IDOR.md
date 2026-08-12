---
type: pattern
title: Pattern - AI Memory API Three-Dimensional Impact Framework
tags: [pattern, ai, llm, memory-api, idor, prompt-injection, pii, dos, bb-pattern]
status: active
category: ai-llm
last_updated: 2026-06-04
---

# Pattern — AI Memory API Three-Dimensional Impact Framework

> Evaluate any memory/history/session endpoint on an AI/LLM SaaS platform along **three independent impact dimensions** — each maps to a separate CVSS metric (I / C / A).

## Trigger Conditions

Any AI/LLM SaaS platform exposing endpoints such as:

```
/memory  /memories  /history  /session
```

## Three Independent Impact Dimensions

| Dimension | CVSS | Attack |
|------|------|------|
| **AI Memory Poisoning** | I:H | Inject malicious memory content so future AI responses are contaminated (a form of indirect prompt injection) |
| **PII Exfiltration** | C:H | Cross-user memory isolation is missing → read another user's session content |
| **Memory Deletion DoS** | A:M | Deleting a user's memory degrades the AI service for that user |

## Test Order (GET-first)

1. `GET /memory` — confirm whether auth is missing or IDOR is present.
2. `GET /memory?user_id=<other>` — attempt cross-user read.
3. Attempt `POST` writes only after understanding the consequences.
4. Attempt `DELETE` only after understanding the consequences — destructive operations require extra caution.

## AI SaaS-Specific Blind Spot

These endpoints are frequently added after the core product ships, so the auth-gate review rate on them is low — making them the easiest thing to miss.

## Reporting

- If all three dimensions share the same root cause, combine them into a single report.
- Score CVSS using the most severe dimension.

## Related Patterns

- [[Pattern - AI LLM MCP Security]]
- [[Pattern - IDOR]]
- [[Pattern - Indirect Prompt Injection via External Data Sources]]
