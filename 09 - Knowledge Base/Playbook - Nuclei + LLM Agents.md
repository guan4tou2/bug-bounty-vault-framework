---
type: playbook
title: "Nuclei + LLM Agents: A Complete Guide"
tags: [nuclei, llm, agent, mcp, automation, devsecops, ai-security]
status: draft
last_updated: 2026-08-12
category: hunting
estimated_time: "15-30 min (evaluation/reading), variable for adoption"
---

# Playbook - Nuclei + LLM Agents: A Complete Guide

> **TL;DR**: Vulnerability scanning is gaining a natural-language layer — from the `-ai` flag that generates templates on the fly, through MCP servers that let an AI agent drive Nuclei directly, to fully autonomous pentesting agents. AI will not replace security engineers, but it will replace security engineers who don't use AI. This playbook maps the four layers of AI-assisted scanning, compares the current tool landscape, and lists the pitfalls to check before adopting any of it into a hunting workflow.
>
> Source: a public write-up by BASHCAT (https://hackmd.io/@BASHCAT/SyePFm5jWe), reorganized here as a methodology reference.

## Scope / When to use

Use this playbook when deciding whether and how to bring AI-assisted scanning (natural-language template generation, MCP-driven agent control of Nuclei, workflow automation, or fully autonomous pentest agents) into a bug-bounty or DevSecOps workflow. It is a methodology and tool-landscape reference, not a live automation dependency — treat every tool and framework listed here as something to evaluate deliberately, not something to wire in by default.

## Phases

### Phase 1: Layer 1 — the `-ai` flag (fastest to adopt)

No YAML required — describe what to scan in natural language:

```bash
# Initialize (requires a ProjectDiscovery API key)
nuclei -auth

# Natural-language scanning
nuclei -ai "check for XSS in query parameters" -u https://target.example.com
nuclei -ai "detect open redirect on login page" -u https://target.example.com
nuclei -ai "find SQL injection in search functionality" -list urls.txt
nuclei -ai "scan for OWASP Top 10 vulnerabilities" -u https://target.example.com
nuclei -ai "check for insecure CORS configuration" -u https://api.example.com
nuclei -ai "detect CVE-2024-XXXX" -u https://target.example.com
```

Flow:
```
natural-language prompt -> ProjectDiscovery AI backend -> generated YAML template -> scan execution -> results
```

Limitations:
- Depends on an external API (the free tier is rate-limited).
- No local-LLM option.
- **AI-generated templates carry a 20-30% false positive/negative rate** — always review manually before relying on a hit.

### Phase 2: Layer 2 — MCP Server (AI agent drives the scanner directly)

Lets Claude/GPT-class agents call Nuclei like a function.

Available Nuclei MCP servers:

| Project | Language | Notable feature |
|---|---|---|
| addcontent/nuclei-mcp | Go | Template management, result caching, concurrent operations |
| crazyMarky/mcp_nuclei_server | Python | Tag filtering, structured JSON output |
| FuzzingLabs/mcp-security-hub | multi-language | **Integrates Nmap + Ghidra + Nuclei + SQLMap + Hashcat** |

Example Claude Desktop configuration:

```json
{
  "mcpServers": {
    "nuclei": {
      "command": "go",
      "args": ["run", "cmd/nuclei-mcp/main.go"]
    }
  }
}
```

Usage — talk to the agent directly in natural language:
```
"Scan example.com, focus on nginx and node.js related vulnerabilities"
```

The agent then: selects relevant tag templates -> runs the scan -> parses the JSON results -> explains the findings in plain language.

FuzzingLabs mcp-security-hub (the most integrated option) triggers a full chain from a single instruction:
```
Nmap port discovery -> service detection -> Nuclei template selection -> execution -> SQLMap deep testing -> consolidated report
```

### Phase 3: Layer 3 — workflow automation (DevSecOps pipeline)

Community n8n-style automation flow:

```
CVE published -> LLM technique extraction -> template generation -> asset scan -> knowledge-base storage -> notify security team
```

ProjectDiscovery's `nuclei-templates-ai` project:
- Monitors new CVE publications.
- AI auto-generates a detection template.
- Community review before merging into the official template repository.
- Compresses CVE-to-detection turnaround to **hours**.

### Phase 4: Layer 4 — autonomous agents (self-directed pentesting)

Define a scope; the agent completes the entire pentest flow on its own:

```yaml
scope:
  targets:
    - example.com
  allowed_tools:
    - nuclei
    - nmap
    - sqlmap
  constraints:
    - no_dos_attacks
    - stay_in_scope
```

Autonomous execution flow:
```
recon -> attack surface discovery -> tool selection -> test execution -> vulnerability verification -> report generation
```

### Phase 5: Compare autonomous pentest agent frameworks

| Tool | Notable feature | Best fit |
|---|---|---|
| **CAI** (Alias Robotics) | Modular, traceable reasoning chain, bug-bounty validated, multi-LLM backend | professional security researchers |
| **PentAGI** | Knowledge-graph memory (Graphiti), cross-task learning, accumulated intelligence | teams running continuous testing |
| **Nebula** | CLI-native, automated recon | analysts who prefer the command line |
| **Strix** | Integrates Nuclei + Caido + Playwright | end-to-end automated testing |
| **HackingBuddyGPT** | Supports **offline/local LLMs** (privacy-first) | internal system testing |
| **PentestGPT** | AI-advisor mode (suggests -> human confirms) | security learners |

CAI highlights: backed by an academic paper (arXiv:2504.06017); validated in real bug-bounty environments; extensible tool chain.

PentAGI highlights: a knowledge graph (Graphiti) that models tool-target-vulnerability semantic relationships; accumulates security intelligence across engagements rather than running one-off scans.

### Phase 6: MCP security-tool hubs and adjacent LLM security tooling

| Tool | Integrates | AI support |
|---|---|---|
| **HexStrike AI** | 150+ tools (nmap/gobuster/nuclei/hashcat/ghidra) | Claude, GPT, Copilot |
| **Pentest-MCP-Server** | Kali Linux Docker + scope management | any MCP-capable AI |
| **FuzzingLabs mcp-security-hub** | Nmap + Nuclei + SQLMap + Ghidra + Hashcat | Claude Desktop |

LLM-specific security testing tools:

| Tool | Purpose |
|---|---|
| **Garak** (NVIDIA) | Tests LLMs for prompt injection, jailbreaks, hallucination vulnerabilities; supports Claude/Llama/Mistral |
| **BurpGPT** | Burp Suite extension using an LLM to analyze passive-scan results and flag logic flaws |

### Phase 7: Pick an adoption path by team size

**Individual / small project (5-minute setup)**
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -auth
nuclei -ai "scan for OWASP Top 10" -u https://myapp.example.com
```
No YAML knowledge required, no MCP server needed.

**Security team / mid-size org (daily automated audits)**
1. Deploy a Nuclei MCP Server.
2. Connect it to Claude Desktop / VS Code.
3. Drive it in natural language: "scan all staging environments, prioritize this month's CVEs."
4. Let the agent auto-classify severity and suggest patch priority.

**Professional security / bug-bounty team (fully autonomous)**
Use a CAI or PentAGI framework plus a HexStrike AI tool hub:
```
agent -> subfinder subdomain enumeration -> naabu port scan -> nuclei vulnerability scan
      -> sqlmap deep verification -> PoC generation -> report
```

## Decision Points

**Pitfalls to check before trusting any AI-assisted scan result**

| Pitfall | Description | Mitigation |
|---|---|---|
| Inaccurate AI templates | 20-30% false positive/negative rate | **all AI-generated templates require manual review** |
| Agent scope drift | agents occasionally exceed intended scope | strictly define `scope.yaml` and run in an isolated environment |
| Privacy exposure | the `-ai` flag sends scan intent to an external API | use an offline-LLM tool (e.g. HackingBuddyGPT) for internal-system testing |
| Tool fragmentation | new tools appear monthly, stability is uneven | prefer tools with organizational backing (ProjectDiscovery/NVIDIA/Alias Robotics) |

**Adoption safety rules (apply before wiring any of this into a live pipeline)**

- Treat `nuclei -ai`, hosted AI template editors/browser extensions, and any cloud API that receives your scan target or vulnerability content as data-exfiltration risk by default — they carry quota and privacy constraints, so only enable them after an explicit, deliberate decision.
- Treat unofficial MCP servers and "kitchen sink" security-tool hubs as architecture references, not something to auto-wrap into your own pipeline without review.
- Canonical template sources: official ProjectDiscovery docs, the official `nuclei-templates` repository, and your own already-reviewed local template set.
- Everything sourced from third parties — AI-generated templates, community mega-collections, templates copied out of blog posts — goes into a quarantine/review queue first. Never point an unreviewed template at production.
- Any self-written template should use `matchers-condition: and` (or an equivalent multi-signal condition) combining status code, content-type, body, and header/title checks, to avoid false positives from SPA fallback pages, WAF/CDN interstitials, or login-only redirects.
- A template match is a signal, not a finding. Every hit still needs bounded manual/browser verification proving concrete impact (exposed sensitive config, a real secret, session/token exposure, cross-tenant data, or account impact) before it is escalated.

**Tiering third-party AI/security tooling before you adopt it**

| Tier | Examples | How to treat it |
|---|---|---|
| Canonical | ProjectDiscovery official docs, official nuclei-templates, your own reviewed local templates | trust as source of truth |
| Review-only corpus | `nuclei-templates-ai`, large community template collections, mobile/vendor-derived template sets | raw material only — every template must be reviewed before use |
| Architecture-only | MCP security hubs, CAI/PentAGI/Strix/Nebula/HexStrike-style frameworks, CI-integrated dashboards | read as design reference; do not wrap into your pipeline by default |
| Explicit-decision-only | `-ai` flags, hosted AI template editors, paid API-backed workflows | only enable after a deliberate, documented decision, given the data-exfiltration/privacy tradeoffs above |

## Expected Outputs

- A decision on which layer(s) of AI-assisted scanning (if any) are appropriate to adopt, and why.
- For any adopted layer, a documented scope/guardrail configuration (allowed tools, no-DoS constraints, isolation boundary).
- A quarantine/review process for any third-party or AI-generated template before it touches production targets.
- A short list of AI-generated "findings" that were manually verified for real impact, versus those discarded as false positives.

## Related

- [[Playbook - API Attack Surface]]
- [[Checklist - XSS Rat 2026]]
- [[Playbook - Recon Methodology]]
