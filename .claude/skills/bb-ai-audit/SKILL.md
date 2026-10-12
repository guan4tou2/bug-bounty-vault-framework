---
name: bb-ai-audit
description: Use when auditing an AI / LLM / agentic / MCP product — prompt injection (direct and indirect), system-prompt extraction, AI memory / skills / history endpoints, MCP server security, insecure output handling, tool-calling over-agency. This is the AI-SPECIFIC audit PROCEDURE (platform layer before model layer → 3-layer Impact Gate → OWASP LLM Top 10 mapping), distinct from generic bb-exploit-chain / bb-attack-chain-review. Triggers: AI / LLM / prompt injection / jailbreak / MCP / agent / RAG / AI SaaS / system prompt.
---

# Bug Bounty — AI / LLM / Agentic Audit (AI-product-specific procedure)

The **single entry point** for auditing an AI product: a repeatable, gated procedure from mapping to a report-ready verdict. This is **not** the generic chaining skill — use `bb-exploit-chain` / `bb-attack-chain-review` for cross-system chaining.

**Core principle: what the model said is not what the system did.**

The biggest source of false positives on LLM targets is treating **model output** as **system behaviour that happened**. "OK, I have emailed the data to attacker@example.com" is generated text, not proof an email was sent. The same goes for "I deleted the record" and "I called the API" — all of it is tokens. This is the same error as reading a success status code as "the query executed", but much deeper here, because models are trained to produce convincing completion narratives. **Every impact claim needs an independent observation outside the model output**: a side channel (a received request / email / DB change), a second account seeing the result, or a tool-call log.

**Second principle: injection success is not impact.** Making the model swear, adopt a persona, or print "HACKED" has impact **None**. Impact requires a downstream capability (Step 3).

## When to trigger

- The target is an AI SaaS / LLM product / agent platform / chatbot / RAG / copilot feature
- An existing product **added** an AI feature (summaries, assistant, smart search) — that layer is the least re-reviewed for auth
- You see an MCP server, tool calling, function calling, or a skill / plugin system
- Path hints: `/skills/` `/agent/` `/memory/` `/history/` `/registry/` `/mcp` `/.well-known/oauth-authorization-server`

## Lifecycle position (run the upstream gates first)

```
bb-version-cve-precheck  (model version, framework version, SDK version are three
                          separate checks — agent frameworks and MCP SDKs have
                          their own CVE lines)
        ▼
bb-surface-mapping       (an AI product's surface = platform endpoints + data
                          sources the model reads + tool inventory)
        ▼
[THIS skill: per-product audit procedure]   ← starts at Step 0
        ▼
Impact Gate (3 layers) → bb-evidence-readiness → bb-attack-chain-review → Finding
```

## Step 0 — Split the two layers; do not mix them (≤5 min)

| Layer | Nature | Reproducibility | Order |
|---|---|---|---|
| **Platform** (endpoints, auth, IDOR, MCP OAuth) | deterministic | 100% reproducible | **first** |
| **Model** (prompt injection, jailbreak, output handling) | probabilistic | needs repeats; may vanish with a model update | second |

Platform first: it is deterministic, its severity is defensible (classic vuln classes), and it often hands you model-layer preconditions (a leaked system prompt tells you which tools to steer toward).

## Step 1 — Platform layer (highest ROI; read-only first)

**Precondition**: obtain any legitimate API key (free / trial tier is fine). The test is the **diff** between "no key" and "with key", not blind unauthenticated requests.

| Endpoint class | Looking for | Hit signal |
|---|---|---|
| `/skills/v1` `/skills/list` | system prompt, tool descriptions, function schemas | response contains `system_prompt` / `instructions` / `parameters`, same structure with and without a key |
| `/memory` `/memories` | cross-user memory read / write | `GET /memory?user_id=<other>` returns someone else's content |
| `/history` `/session` `/file-sessions` | other users' file sessions, presigned URLs | response contains other users' file names or directly downloadable URLs |
| `/registry` `/agent` | agent orchestration, internal topology, cluster info | response leaks internal service names / cluster details |
| `/mcp` `/.well-known/oauth-authorization-server` | open dynamic client registration, consent-vs-token capability gap | unauthenticated `POST /register` returns 201; `tools/list` exceeds the scopes shown on the consent screen |

Deep references:
- Full endpoint list, per-endpoint test commands, root-cause criteria → [[Checklist - AI LLM SaaS Unauthenticated Endpoints]]
- Memory impact in three dimensions (poisoning I:H / PII disclosure C:H / deletion A), one root cause = one report scored on the worst dimension → [[Pattern - AI Memory API Unauth IDOR]]
- MCP OAuth open registration + consent gap → [[Pattern - MCP OAuth Scope Mismatch]]

Hand-offs:
- **Memory / history IDOR → `bb-idor-coverage`** for the full read/write verb matrix (GET + POST/PUT/PATCH/DELETE, cross-tenant). AI memory endpoints are especially easy to stop at GET, but write (poisoning, I:H) is usually the highest-impact dimension.
- **OAuth-core flaws under MCP** (redirect_uri validation, state/nonce, PKCE, token audience, callback binding): MCP is a layer over standard OAuth — test the OAuth itself too, not just MCP-specific behaviour (external skill `jwt-oauth-token-attacks`, see `09 - Knowledge Base/Reference Card - External Skills Catalog.md`).
- `/skills` `/history` `/registry` are object-ID APIs → test object-level and function-level authorization in depth (nested resources, hidden writable fields).

**Writes and deletes: know the consequence first.** `POST /memory` (poisoning) and `DELETE /memory` (availability) are write semantics → pass `bb-scope-safety-check` first. Finish all reads before writes (`AGENTS.md` §6).

## Step 2 — Model layer (direct vs indirect; indirect is worth far more)

**Direct injection** (the attacker talks to the model): impact is usually capped at the attacker's **own session** unless it reaches a downstream capability. Most are Informative.

**Indirect prompt injection** (the attacker poisons a data source the model reads later): **this is where real findings are.** The attacker needs no account, no API key, and no interaction with the victim.

```
attacker-controlled source  →  model reads it  →  model acts
calendar invite / comment / meeting chat / shared document /
whiteboard OCR / MCP server response
```

- Surface identification and known vectors → [[Pattern - Indirect Prompt Injection via External Data Sources]]
- If the target integrates an MCP server with skill / tool execution, always try an injection in the MCP server's response that makes the agent run a skill and reveal its full system prompt (tool list, guardrail rules, secret references).
- Attack-class overview (insecure output handling, ASCII-smuggling exfiltration, system-prompt extraction, RCE via code-capable tools, agentic ASI01–ASI10) and technique list → [[Pattern - AI LLM MCP Security]] § Covered Attack Categories

**Techniques are only the means; Step 3 decides whether there is a finding.**

## Step 3 — Impact Gate (3 layers; all must PASS before opening a Finding)

```
Layer 1 (Injection)   Did the payload actually enter the model's context?
                      (not just the model repeating your words back)
Layer 2 (Capability)  Does the model have a downstream capability? — tool call / API /
                      file access / email / other users' data / output rendered on
                      someone else's screen (XSS / markdown-image exfiltration)
Layer 3 (Observation) Is the impact observed independently of the model output?
                      ← the most common false-positive layer; the core of this skill
Exploitable = L1 × L2 × L3
```

Any BLOCK → record a negative with `bb-attempt-recorder`.

| Acceptable Layer 3 evidence | Not acceptable (just tokens) |
|---|---|
| Your out-of-band listener received a request / DNS query | model says "I sent the request" |
| A second account actually sees the poisoned content | model says "written to another user's memory" |
| Mailbox received the email; DB field changed | model says "email sent" |
| Tool-call log / response shows the tool was actually invoked | model recites the tool schema |
| Real data from another session appears in the response | model invents plausible-looking data (hallucination) |

- **Hallucination can masquerade as a successful data leak.** "Leaked" data may be made up. Verify authenticity (plausible format, matches known values) before claiming C:H. Traditional vuln classes have no equivalent false positive.
- **Reproducibility bar**: a model-layer finding needs at least **3 independent successes** (different sessions, cleared conversation), with model version and time recorded. A single success is weak evidence and likely to fail the vendor's retest.

## Step 4 — Scoring and reporting

- **Map to OWASP LLM Top 10** IDs (prompt injection, insecure output handling, sensitive information disclosure, excessive agency, ...) — reviewers know that vocabulary.
- **CVSS via `bb-cvss-score`**; before any C/I/A = H, run the `cvss-adversary` agent. AI findings are especially prone to over-scoring — "the model might be induced to do X" is not X having happened.
- **Open platform-layer and model-layer Findings separately** (different root causes); multiple impact dimensions of one root cause go into one report.
- Anti-exaggeration (`AGENTS.md` §5): report the rate as observed — "the model invoked the tool in 3 of 5 attempts", not "the model invokes the tool".

## Stop conditions

Any of these → record a negative and move to the next surface:

1. Platform layer is all 401/403 with no diff, and the model has no downstream capability (text-only chat, no tools, output not rendered to others) → impact ceiling is Informative.
2. Injection reaches context but Layer 3 yields no independent observation after 3+ tries → record an Attempt stating which layer blocked.
3. The model layer is hosted by a third-party provider that is not in scope (you would be testing the provider, not the target) → stop; this is a scope question, not a technical one.

## Cross-references

- Upstream: `bb-version-cve-precheck` · `bb-surface-mapping`
- Safety gate: `bb-scope-safety-check` (memory writes / deletes)
- Platform-layer hand-off: `bb-idor-coverage`
- Model-layer hand-off (insecure output handling): output rendered to other users is XSS → external `xss-cross-site-scripting`; markdown-image exfiltration blocked by CSP → external `csp-bypass-advanced`; output flowing into SQL / shell → treat as classic injection (see `09 - Knowledge Base/Reference Card - External Skills Catalog.md`)
- Downstream: `bb-evidence-readiness` → `bb-attack-chain-review` → `bb-submission-readiness`
- Scoring: `bb-cvss-score` + `cvss-adversary` agent
- KB: [[Pattern - AI LLM MCP Security]] · [[Pattern - Indirect Prompt Injection via External Data Sources]] · [[Pattern - AI Memory API Unauth IDOR]] · [[Pattern - MCP OAuth Scope Mismatch]] · [[Checklist - AI LLM SaaS Unauthenticated Endpoints]] · [[Playbook - Nuclei + LLM Agents]]
