---
name: bb-multi-search
description: Use when mid-hunt and need quick ad-hoc research — fans out 4-6 query variations across security sources (NVD, H1, PortSwigger, exploit-db, GitHub) via parallel subagents, deduplicates, and returns a synthesized briefing. Local only, no third-party search API. Triggers: "research this", "any writeups for", "search for", "look this up", "is there prior art".
---

# bb-multi-search — Parallel Multi-Source Security Search

When you hit a question mid-hunt (technique details, CVE specifics, prior art, bypass methods), use this skill for parallel search + synthesis. **Uses only built-in WebSearch/WebFetch — no third-party API calls.**

## Input

User provides one of:
- **query** (required): the research question, in natural language
- **target** (optional): the target being hunted
- **tech** (optional): relevant tech stack (e.g., `Laravel`, `Spring Boot`, `React`)
- **vuln_class** (optional): vulnerability class (e.g., `SSRF`, `IDOR`, `deserialization`)

## Execution

### Step 1 — Query Expansion

Generate 4-6 search queries from different angles, covering these source categories:

| Source Category | Query Template Example |
|----------------|----------------------|
| **CVE/Advisory** | `site:nvd.nist.gov OR site:cve.org "{tech} {vuln_class}"` |
| **Writeup/Blog** | `"{query}" bug bounty writeup OR walkthrough OR POC` |
| **Research** | `site:portswigger.net/research OR site:projectdiscovery.io/blog "{query}"` |
| **HackerOne** | `site:hackerone.com/reports "{query}" OR "{tech}"` |
| **GitHub** | `site:github.com advisory OR security "{tech} {vuln_class}"` |
| **Exploit-DB/PoC** | `site:exploit-db.com OR site:packetstormsecurity.com "{query}"` |

Rules:
- Not every category needs to run — select the 4-6 most relevant based on query nature
- If the query contains a version number, add a precision version search
- If the query contains a CVE ID, pivot to that CVE as the core (NVD + exploit + patch analysis)

### Step 2 — Parallel Dispatch

**Dispatch all subagents in a single message (parallel execution).** Each subagent:

```
Agent({
  description: "Search: <source-category>",
  prompt: `
    Use WebSearch for the following query. Take the top 5-8 results.
    For each promising result, use WebFetch to get a content summary.

    Query: <expanded-query>

    Report format (per result):
    - **Title**: ...
    - **URL**: ...
    - **Date**: ... (if available)
    - **Key finding**: 1-2 sentence summary focused on exploitability / technical detail / version applicability
    - **Relevance**: high/medium/low

    Return only high/medium relevance results. If search yields nothing useful, report "no relevant results."
    Keep report under 200 words.
  `,
  run_in_background: false
})
```

### Step 3 — Synthesize

After all subagents return:

1. **Deduplicate**: merge results when the same article/CVE appears from multiple sources
2. **Rank**: sort by relevance + actionability (has PoC > has technical detail > advisory-only)
3. **Synthesize**: produce a structured briefing

### Output Format

```markdown
## Search Results: {original query}

**Coverage**: {which source categories were searched}

### Key Findings
1. **{title}** — {1-2 sentence key takeaway}
   {URL} | {date}

2. ...

### Actionable Conclusions
- {Concrete suggestions for current hunting work based on search results, 1-3 items}

### Not Covered
- {If an important source category returned nothing, state it explicitly}
```

## Rules

- **GET-first**: WebSearch + WebFetch are read-only; never touch the target
- **Anti-exaggeration**: search results are prior art / reference; they do not mean the target has the same vulnerability
- **Token discipline**: subagent reports capped at 200 words each; main synthesis capped at 500 words. Do not pull full page content into main context
- **No file writes**: this is ad-hoc search; results go directly into the conversation. For persistent research, use the `research` skill
- **No vault mutations**: do not modify RECON_DB / Finding / KB files

## When to Use Which Research Tool

| Need | Tool |
|------|------|
| Full pre-hunt research on disclosed reports for a new target | `disclosed-report-researcher` agent |
| Specific version CVE precheck | `bb-version-cve-precheck` skill |
| Filling a Knowledge Gap Backlog item | `bb-gap-research` skill |
| Deep documented research (output is a file) | `research` skill |
| **Quick mid-hunt question lookup** | **bb-multi-search** (this skill) |
