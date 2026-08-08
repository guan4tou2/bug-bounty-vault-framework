---
fileClass: Playbook
type: playbook
title: Improved End-to-End Hunting Workflow (Closed Loop)
status: active
last_updated: 2026-06-04
tags: [workflow, bbflow, wiki, skills, agents, learning-loop, bb-playbook]
source: internal
added: 2026-06-04
---

# Improved End-to-End Hunting Workflow -- Closed Loop

> Purpose: Chain four loops into a self-correcting closed loop, and convert recurring pain points from real sessions into "entry/exit gates" and "automatic backfill trigger points."
> This document is **proposed** and does not override existing SOPs; see the "Specific Changes to Existing Processes" section at the end for implementation details.
> Alignment with existing naming: skill = `.claude/skills/`, agent = `.claude/agents/`, wiki = `09 - Knowledge Base/wiki/`, bbflow = `$TOOLS_ROOT/bbflow.sh` (VPS required).

---

## 0. Four-Loop Closed Loop Overview (ASCII)

```
            +--------------------------------------------------------------+
            |                    LEARNING LOOP (Loop 4)                      |
            |   session_end -> Lesson / Pattern / Checklist / wiki backfill   |
            |   bb-knowledge-capture (gate, hard block)                      |
            +-------^----------------------------------------------+-------+
                    | backfill (new wiki page / Checklist / Pattern->Hunter) | feed
                    |                                                        v
   +----------------+----------+  read playbook  +------------------------------+
   | Loop 1: LLM WIKI Playbooks | ------------> | Loop 3: Hunting (human-in-loop |
   | 09-KB/wiki/ 56 pages       |               | / LLM)                        |
   | payload / tools / checklist | <------------ | surface-map -> hunt -> verify  |
   +----------------+-----------+  gap report    |           -> report            |
                    | reference commands/templates +------^--------------+--------+
                    v                                    | consume       | produce
   +--------------------------+   candidates.jsonl   +---------------------+
   | Loop 2: bbflow zero-LLM   | -----------------> | Vault: Finding /     |
   | hunters (VPS, cron)        |                    | Submission / FORM    |
   | recon / hunt / flow        | <----------------- | candidate gate       |
   +--------------------------+   scope.yaml / scale | pipeline             |
                                                     +---------------------+
```

Four-loop responsibility boundaries:

| Loop | Owns | Does Not Own | Triggered By |
|------|------|-------------|-------------|
| 1 wiki | Copy-paste commands / payload / checklist / decision trees | Target decisions, raw data | LLM reads, human reads |
| 2 bbflow | CLI runtime, hunters, scope enforcement, machine-readable output | Vault schema, LLM prompts, report text | cron / manual / agent |
| 3 hunting | Candidate verification, PoC, Finding/Submission/FORM | Scan log raw data, tool state beyond reports | LLM + human |
| 4 learning | Lesson / Pattern / Checklist / wiki backfill | Report text, target decisions | session_end gate |

---

## 1. Phase Flow Diagram (Mermaid)

```mermaid
flowchart TD
    A[Session Start] --> A1[check_active_sessions + claim]
    A1 --> A2{target exists?}
    A2 -- no --> A3[init_target.sh<br/>create SCOPE/RECON_DB/Recon note stub]
    A2 -- yes --> A4[session_start_brief.sh<br/>summarize HANDOFF/QUICK_REF/RECON_DB]
    A3 --> B
    A4 --> B

    B{software/firmware/SaaS?}
    B -- yes --> B1[GATE 0g precheck<br/>bb-version-cve-precheck<br/>latest stable / CVE / disclosed]
    B -- no(pure recon) --> C
    B1 --> B2{known CVE / old version?}
    B2 -- yes --> STOP1[Cut losses: record RECON_DB and close]
    B2 -- no --> C

    C[GATE: Disclosed vulnerability exclusion list<br/>read disclosed PDF / FINDINGS_QUICK_REF<br/>build known-vuln exclusion list]
    C --> D[bb-surface-mapping<br/>vuln-agnostic full mapping<br/>RECON_DB Attack Surface Map]
    D --> D1{active scanning needed?}
    D1 -- yes --> E2[Loop 2: bbflow recon/hunt<br/>VPS, scope.yaml, scale 0-4]
    D1 -- no --> E
    E2 --> E[consume candidates.jsonl]

    E[GATE: SPA catch-all exclusion<br/>homepage vs random-404 size diff] --> F{real endpoint?}
    F -- no(catch-all) --> D
    F -- yes --> G[hunt: reference wiki playbooks<br/>per-param OWASP matrix]

    G --> H{candidate found?}
    H -- no --> H1[bb-attempt-recorder<br/>negative result backfill]
    H -- yes --> I[bb-scope-safety-check<br/>GET-first, read vs write distinction]
    I --> J[verify: live re-verify + screenshot on the spot<br/>Playwright MCP]
    J --> K[bb-attack-chain-review<br/>chain first then report]
    K --> L[bb-evidence-readiness]
    L --> M[bb-dedup-finding<br/>check root cause]
    M --> N{duplicate?}
    N -- yes --> H1
    N -- no --> O[create Finding (discovery note)<br/>-> Submission -> FORM]
    O --> P[bb-submission-readiness<br/>format/screenshot/type/VRT/CVSS gate]
    P --> Q[submit / FORM<br/>HITCON type field requires interactive click]

    H1 --> R
    Q --> R[Session End]
    R --> R1[session_end_brief + checklist]
    R1 --> S[GATE: bb-knowledge-capture<br/>six-category backfill + orphan check + wiki gap]
    S --> T[Lesson / Pattern / Checklist / wiki backfill]
    T --> U[git commit specific files + release]
```

---

## 2. Each Phase: Which Skill / Agent / Wiki / bbflow Command to Use

### Phase A -- Session Start (claim + brief)
- **Commands**: `check_active_sessions.sh` -> `claim.sh <scope>` -> `session_start_brief.sh <target> "<kw>" "<host>"`
- **Agent**: `pre-recon` (reads FINDINGS_QUICK_REF + RECON_DB to prevent duplicates)
- **Entry gate**: claim succeeds (prevents parallel session conflicts).
- **Exit gate**: brief has summarized HANDOFF/QUICK_REF/RECON_DB; new target has `init_target.sh` (including Recon note stub).

### Phase B -- Version + CVE Precheck (Section 0g)
- **Skill**: `bb-version-cve-precheck` (canonical SOP, other documents point to it)
- **Wiki**: `40-checklist-new-target.md`
- **Entry gate**: target is software/firmware/native/mobile/SaaS with a specific version or cloud host.
- **Exit gate**: `RECON_DB ## Pre-flight Checks` has latest-stable / NVD-GHSA / disclosed written; old version or CVE hit -> cut losses and close.

### Phase C -- Disclosed Vulnerability Exclusion List (New Gate)
- **Skill**: `bb-dedup-finding` (root-cause comparison)
- **Action**: For competition/platform targets, first download and read all disclosed/fixed report PDFs, build known-vuln exclusion list and write to RECON_DB; for BB targets, equivalent to reading `FINDINGS_QUICK_REF.md`.
- **Exit gate**: exclusion list exists; all subsequent Findings must be checked against this list.

### Phase D -- Exploration-First Surface Mapping
- **Skill**: `bb-surface-mapping` (earliest gate, anti-lamppost-effect)
- **Wiki**: `40-checklist-new-target.md`, `19-subdomain-recon-deep.md`, `84-source-code-review-flow.md`
- **Exit gate**: `RECON_DB ## Attack Surface Map` has vuln-agnostic mapping -- **only then** can pattern/hunter run.

### Phase E2 -- bbflow Zero-LLM Hunters (Loop 2)
- **bbflow** (VPS required, first run `workspace_layout.sh --shell` to get `TOOLS_ROOT`, read `$TOOLS_ROOT/BBFLOW_OPERATIONS.md`):
  - `bbflow recon <target>` -- passive enumeration + alive check
  - `bbflow hunt <target>` -- pattern hunters
  - `bbflow flow <target>` -- full chain
- **Agent**: `bbflow-runner` (parses hits, writes back to RECON_DB, suggests Findings)
- **Input contract**: `scope.yaml` (`schema_version:1` / `in_scope` / `scan_level` / `rate_limit`), scale 0-4 decided by Vault/human.
- **Output contract**: `candidates.jsonl` (includes `dedupe_key` / `confidence` / `vuln_class` / `suggested_skill` / `requires_scope_safety` / `chain_potential`) + `run_manifest.json` + `HUNTERS_REPORT_*.md`.
- **Entry gate**: surface-map complete + scope.yaml exists + scale defined + scope-safety passed.

### Phase E3 -- Prioritize (Breadth -> Depth Bridge; Breadth Feeds Depth)
- **Core principle**: Breadth (bbflow hunters / `Workflow` parallel agents / deepdive leads) **only identifies "where to dig deep," not vulnerabilities**. Determinations are always made during depth (otherwise you replicate noise -- breadth true finding yield is approximately 0).
- **Agent**: `endpoint-interest-scorer` -- ranks bbflow `candidates.jsonl` / recon endpoint lists by **score** (0-100 interest), picks top N for depth.
- **Local breadth tools**: `bbflow-runner` (47 hunters) + **`Workflow` parallel agents** (fan-out as needed, e.g., multiple hosts/surfaces simultaneous recon).
- **Exit gate**: ranked top-N list exists -> only then enter Phase G deep hunting (do not spread effort evenly across everything).

### Phase E -- SPA Catch-All Exclusion (New Gate)
- **Action**: Compare homepage vs random 404 path response size; same size = SPA catch-all, HTTP 200 does not mean real endpoint. Framework-level catchAll (Yii2 / Next.js) is immune to IP/header bypass -- give up early.
- **Wiki**: Suggested new page `42-spa-catchall-and-false-200.md` (see changes list).
- **Exit gate**: every 200-response endpoint entering hunt has passed size-diff check.

### Phase G -- Hunt (Reference Wiki Playbooks)
- **Skill**: `bb-web-vuln-scan` (OWASP full matrix, version->CVE, WAF bypass); `web-hunter` agent (Playwright auto-scan)
- **Wiki playbooks** (reference by vuln class, do not duplicate content):
  - Injection family: `71-xss-deep` `72-sqli-deep` `73-ssti-deep` `74-command-injection` `75-xxe-deep` `76-lfi-path-traversal`
  - Authorization family: `77-idor-bola-bfla` `66-ssrf-deep` `78-open-redirect`
  - Protocol/cache: `60-request-smuggling` `64-cache-poisoning` `68-websocket-cswsh` `70-host-header-crlf`
  - Identity: `16-oauth-attack-chains` `80-mfa-bypass` `83-saml-oidc-attacks` `31-jwt-attack-walkthrough`
  - GraphQL: `17-graphql-deep-attacks`
  - AI/MCP: `81-mcp-server-security` `82-ai-llm-security`
  - WAF: `01-waf-bypass-playbook` `14-waf-bypass-commands`
- **Exit gate**: every param runs through the full matrix (LFI/SSRF/CMDi/SSTI/XXE), not just XSS/SQLi; grep match does not equal exploitable (must verify HTML encoding / boundaries).

### Phase H1 -- Negative Result Backfill
- **Skill**: `bb-attempt-recorder` (false positive / blocked / dead end -> Attempt note, with audit ref).

### Phase I -- Scope Safety (Before Write Operations)
- **Skill**: `bb-scope-safety-check`
- **Rules**: GET-first principle. Before any POST/PUT/DELETE, assess side effects first; clearly distinguish read vs write endpoints; confirm reachability using only GET or TCP connectivity; do not blindly hit write endpoints.

### Phase J -- Verify (Live Re-verify + Screenshot on the Spot)
- **Tools**: Playwright MCP (>> Chrome extension, unrestricted JS / dialog / network interception); WAF -> `cfx` / TLS fingerprint randomization.
- **Exit gate**: screenshot taken at the "first vulnerability confirmation" moment (avoids needs-revalidation blocking on screenshots); `last_verified` uses today's date.

### Phase K/L/M -- Chain -> Evidence -> Dedup
- **Skill**: `bb-attack-chain-review` -> `bb-evidence-readiness` -> `bb-dedup-finding`
- **Agent**: `attack-chain-deep-dive`; **Skill**: `bb-cvss-score` (CVSS scoring)
- **Rules**: Chain first then report; dedup checks root cause (same endpoint read/write or different severity manifestations = one finding).

### Phase O/P/Q -- Finding -> Submission -> FORM -> Submit
- **Agent**: `submit-form` (HITCON/H1/Bugcrowd/Intigriti/TWCERT)
- **Skill**: `bb-form-writer`, `bb-submission-readiness`, `bb-cve-citation`
- **Wiki**: `41-checklist-before-submit.md`, `86-dupe-hunting-report-writing.md`
- **Exit gate**: see "Submission Gate Checklist" below.

### Phase R/S/T -- Session End -> Learning Backfill (Loop 4)
- **Commands**: `session_end_brief.sh` -> `session_end_checklist.sh <target>` (validates Knowledge Capture Gate; incomplete = halt)
- **Skill**: `bb-knowledge-capture` (six-category backfill)
- **Agent**: `vault-sync` (commit dirty files, update Kanban + QUICK_REF)
- **Exit gate**: six-category backfill judgment complete + orphan count verified + wiki gap reported + graph tool update scheduled.

---

## 3. Entry / Exit Gate Summary

| # | Gate | Entry Condition | Exit Condition (PASS) | Corresponding Pain Point |
|---|------|-----------------|----------------------|-------------------------|
| G0 | claim | Session start | claim succeeds, no parallel conflicts | Parallel session commit conflicts |
| G0g | version+CVE precheck | Has specific version/cloud host | RECON_DB Pre-flight four-point complete (including LTS/EOL/Beta/SaaS boundaries) | Collision, old version high collision rate |
| GEX | disclosed exclusion list | Competition/platform target | Read all disclosed PDFs / QUICK_REF, built exclusion list | Duplicate hunting without reading PDFs |
| GSM | surface-map | Precheck passed | RECON_DB Attack Surface Map exists | Lamppost effect |
| GSP | SPA catch-all | Got 200 endpoints | size-diff confirms real endpoint | Source map false 200, framework catchAll bypass ineffective |
| GSS | scope-safety | Before write operations/scanning | GET-first passed, write endpoint side effects assessed | Accidental write endpoint trigger during testing |
| GEV | evidence | Before creating Finding | Screenshot taken on the spot, Discovery Log five-column, audit ref | needs-revalidation blocking screenshot |
| GDD | dedup | Before new Finding/FORM | root-cause comparison non-duplicate, QUICK_REF read | Subagent not reading QUICK_REF causing duplicates |
| GSR | submission-readiness | Before Submission/FORM ready | All submission gate checklist items passed | Submission pipeline pain points recurring |
| GKC | knowledge-capture | Session end | Six-category backfill + orphan=0 + wiki gap reported | Knowledge not flowing back to Vault |

### Submission Gate Checklist (GSR Expanded, Hard Blocks)
1. **Three-question check**: What can the attacker obtain / Is this default behavior / What remains after removing theoretical elements.
2. **Dedup**: root-cause comparison + QUICK_REF; CVE citations must verify exact pattern (`bb-cve-citation`) -- if unverifiable, do not cite.
3. **HITCON FORM**: type field uses only canonical names (check Reference Card, no numeric IDs / English parentheses / invented names); platform value fixed to `HITCON`; YAML timestamps quoted; type/detection system fields require Playwright interactive clicks, cannot curl POST strings.
4. **Bugcrowd VRT**: select the most precise subcategory, do not select parent categories that auto-escalate severity; CVSS v3.1 vector + CWE must be correctly filled, do not rely on VRT auto-severity.
5. **Text cleanup**: grep for `[screenshot #N]` placeholders + internal IDs -> vendor-facing version must be clean.
6. **Format**: code fences in even count (`grep -c '```'` check even); URLs copyable not embedded in screenshots; payloads in code blocks; steps numbered; PDF includes screenshots and size within platform limits.
7. **Severity self-check**: prod vs dev clearly stated and used to justify; UA filtering / bot detection / "could theoretically" / pure old version = kill immediately, do not submit.
8. **State sync**: immediately after submission, backfill ZD/report number to QUICK_REF + SUBMISSION_PLAN + Kanban (all three, do not defer to next session).

---

## 4. Learning Backfill Trigger Points (Loop 4 -- When to Backfill Which Category)

| Trigger Event (During Session) | Backfill Category | Destination | Skill |
|-------------------------------|-------------------|-------------|-------|
| New attack technique succeeds | Pattern / wiki playbook | `09-KB/Patterns/` + `wiki/` | bb-knowledge-capture |
| Failure/dead end/false positive | Lesson + Attempt | `Lessons Learned.md` | bb-attempt-recorder |
| New tool usage/flag | wiki tool page | `wiki/20-3x-tool-*.md` | bb-knowledge-capture |
| Triage reply (N/A/Dup/Accepted) | Lesson + Triage sync | `Lessons Learned.md` + Kanban | bb-triage-response |
| Same pattern hits >=3 times | Pattern -> bbflow Hunter | `Pattern Automation Backlog` + bbflow | Automation threshold |
| Submission gate repeatedly hits same pitfall | Checklist | `09-KB/Checklist - *.md` | bb-knowledge-capture |
| Recurring decision uncertainty (report or split?) | Decision tree Lesson | `Lessons Learned.md` | bb-knowledge-capture |
| Wiki reference discovers missing page | wiki gap report | New wiki page stub | bb-knowledge-capture |

**Mandatory trigger point**: `session_end_checklist.sh` at close-out asks item by item "new technique / failure lesson / tool usage / triage lesson -- needs backfill?" and halts if not completed (this is the key to converting the "knowledge not flowing back" pain point into a hard gate).

---

## 5. Specific Changes to Existing Processes (Pragmatic, Actionable)

> Ordering: hard-block gates first (prevent known pain points from recurring), then wiki/Checklist page additions (fill external research gaps), then tooling enhancements.

### A. Automation Scripts (automation/) -- Hard-Block Gates
1. **`automation/check_spa_catchall.sh` (new)**: Takes a host, curls the homepage and a random 404 path, compares body sizes; same size outputs `[CATCHALL]`. Called at the beginning of `bb-surface-mapping` and `bb-web-vuln-scan` flows. Addresses pain point: source map false 200 / Yii2/Next.js catchAll.
2. **`automation/session_end_checklist.sh` (modified)**: Add Knowledge-Capture interactive checkpoint (six categories y/n each), FAIL if unfilled; fix findings count comparison -- only compare QUICK_REF "Findings" column vs Target frontmatter `findings_total`, exclude submissions/attempts (eliminates 83 vs 67 false positive).
3. **`automation/init_target.sh` (modified)**: Auto-generate Recon note stub when creating target (eliminates session-end warning "cannot find Recon note"), and create SUBMISSION_PLAN stub.
4. **`automation/lint_hitcon_form_types.py` (expanded)**: Type field allowlist validation -- reject entries containing numeric IDs, English parentheses, non-canonical names; platform must be `HITCON`; YAML time values must be quoted. Hooked to pre-commit.
5. **`automation/presubmit_text_clean.sh` (new)**: grep for `[screenshot #` placeholders, internal ID regex, odd code fence count (`grep -c '```'`); any hit = FAIL. Called by `bb-submission-readiness`.
6. **`automation/backfill_finding_stubs.sh` (existing, made mandatory)**: Enforced at both session-end checklist and "after report creation" points; orphan>0 = FAIL (eliminates orphan duplicate hunting).

### B. Skill Changes
7. **`bb-version-cve-precheck/SKILL.md` (set as canonical)**: Change duplicated version->CVE SOP in `bb-web-vuln-scan` and AGENTS.md Section 0g to pointers to this skill (eliminates ambiguity from three copies with different phase numbering); add EMBA 2.0 SBOM+CVE triage flow, incomplete patch diff (SHA256 tree -> BinDiff/Ghidra) as sub-steps.
8. **`bb-scope-safety-check/SKILL.md` (addition)**: Add explicit "read vs write endpoint distinction" step -- confirm reachability with GET or TCP; write endpoints must list side effects before confirmation.
9. **`bb-dedup-finding/SKILL.md` (addition)**: For competition/platform targets, add "read disclosed PDFs to build exclusion list" as prerequisite step.
10. **`bb-knowledge-capture/SKILL.md` (addition)**: Close-out six-category question templates + wiki gap report field.
11. **Subagent prompt templates (existing, made mandatory)**: All output-producing subagent prompts must append rules template, explicitly stating "read `FINDINGS_QUICK_REF.md` before creating a Finding," "use full skill paths or paste SKILL.md content (subagents do not inherit the registry, automation/ paths must be verified to exist)," "for large files use grep to locate line numbers + offset/limit reads."

### C. New Wiki Playbook Pages (Fill External Research R1-R9 Gaps)
12. **`42-spa-catchall-and-false-200.md` (new)**: size-diff determination, framework catchAll (Yii2/Next.js) immune to IP/header bypass quick-abandon criteria.
13. **`81-mcp-server-security.md` (addition)**: Tool Description Poisoning / rug pull, Elicitation Fallback Bypass, CurXecute (`.cursor/mcp.json` write-in RCE, CVE-2025-54135), Cross-Agent Privilege Escalation (`.mcp.json`/`CLAUDE.md`/`AGENTS.md` write-in), EchoLeak four-layer bypass, ServiceNow second-order injection, MCP Spotlighting/destructiveHint audit checklist.
14. **`82-ai-llm-security.md` (addition)**: Unicode invisible character (U+E0000-U+E007F) detection regex, EchoLeak-type RAG exfiltration checklist (classifier bypass / reference-style markdown / CSP proxy allowlist / auto-fetch image).
15. **Electron app (existing Patterns) Checklist additions**: contextBridge prohibit passing VideoFrame/MessagePort (CVE-2026-34780), V8 snapshot integrity != ASAR fuse (CVE-2025-55305), `spread...webPreferences` grep (CVE-2026-34769), `npx @electron/fuses read` factory fuse check, client-server `%2f` decode divergence, iframe must add HTML sandbox. Framing always as "arbitrary local program leverages IPC bridge to achieve RCE" not "local privilege escalation."
16. **`66-ssrf-deep.md` (addition)**: IMDSv2 PUT-then-GET token chain, double-URL-encode `==` padding bypass, scheme omission to bypass IP blocklist, DNS rebinding + file import, Azure DevOps endpointproxy + CRLF->`Metadata:True`; cloud metadata (AWS/GCP/Azure) bypass payload table.
17. **`83-saml-oidc-attacks.md` (addition)**: SP-side SAML 13-item verification checklist, CVE-2024-45409 DigestValue smuggling, CVE-2025-25291/25292 dual-parser wrapping, Silver SAML, nOAuth mutable email, Google hd/sub binding, OAuth state-missing CSRF (CVE-2025-65107); OAuth grant-type x state/PKCE/nonce/aud matrix.
18. **`77-idor-bola-bfla.md` (addition)**: Action-Level BOLA (test all four methods GET/POST/PUT/DELETE), Object Rebinding (client supplies owner_id/tenant_id), GraphQL Global ID base64 decode+increment, vertical BOLA, chained ID harvesting, error-response UUID leak; dedup rule addition "own object is info disclosure not BOLA."
19. **`17-graphql-deep-attacks.md` (addition)**: alias-batching rate-limit/2FA bypass, field-suggestion enumeration (Clairvoyance), non-JSON content-type CSRF, unauth mutation enumeration.
20. **`68-websocket-cswsh.md` (addition)**: browser-matrix decision tree (Chrome exploitable / Firefox TCP / Safari ITP / private-IP always exploitable), GraphQL-over-WS bidirectional reads.
21. **`60-request-smuggling.md` (addition)**: TE.0 variant (`Via: 1.1 google` fingerprint), CVE-2025-55315 chunk-extension lone-LF (Kestrel); cache deception vs poisoning distinction checklist.
22. **`19-subdomain-recon-deep.md` / `20-tool-katana.md` (addition)**: subfinder->httpx(-mc)->nuclei pipeline, `katana -jc -jsl/-hl -xhr/-iqp/-tlsi` flags, `gf+waybackurls+qsreplace+httpx` confirmed open-redirect pipeline, `katana -sr` raw response evidence collection.
23. **`86-dupe-hunting-report-writing.md` (addition)**: dual reproduction steps (triager version + customer version), single-fix test (dedup dispute), context-specific impact table (prod/dev x data volume x state-changing), two-week follow-up cadence, title embed timestamp/provenance.
24. **Firmware wiki (new `87-firmware-rooting-and-patchdiff.md`)**: OWASP FSTM Stage 8/9 runtime attach (gdb-multiarch+Frida MIPS/ARM), Qiling+NVRAM emulation, Lua bytecode normalizer, chacha20/AES GPL-source decryption flow, CGI query-string unbounded read grep (CVE-2024-41592 GetCGI pattern), UPnP AddPortMapping checklist (CVE-2026-3870/3871).

### D. New Checklists (Fill Actionable Matrix Gaps)
25. **`Checklist - Pre-Submit Triple-Check` (new)**: scope confirmation + SSL/WHOIS verification + qualifying vuln class, three-step gate before submission.
26. **`Checklist - ACBreaker Auth-Bypass Mutation` (new)**: 17 HTTP mutation operators as standard auth bypass test matrix.
27. **`Playbook - Dispute Duplicate Ruling` (new)**: single-fix test / requires different code change / cite Bugcrowd three principles or Intigriti single-fix.

### E. Document Deduplication / Consistency
28. Unify the version-to-CVE SOP scattered across `bb-web-vuln-scan` / `bb-version-cve-precheck` / AGENTS.md Section 0g to point to `bb-version-cve-precheck` (canonical); change others to pointers.
29. Embedded third-party git repos always `.gitignore` excluded, not tracked via gitlink (eliminates object corruption); before commit run `git status` to confirm staging, prohibit `git add -A`, use only `git add <specific files>`.
30. VPS rules written into AGENTS.md VPS section: remote-vps user `opc`, dangerous operations always on primary VPS, secondary for VPN only; eliminates repeatedly connecting to wrong account.

---

## 6. Relationship to Existing SOPs (Does Not Replace, Only Strengthens)

- This document is the **execution-perspective supplement** to `Reference Card - Workflow State Machine and Gates`: the state machine defines states, this document adds "which skill/wiki/bbflow to use at each state + pain-point-matched gates."
- The candidate lifecycle gates (surface-map -> scope-safety -> chain -> evidence -> dedup -> submission -> KB) fully follow the existing flow; no parallel processes were added.
- After all new wiki/Checklist pages go live, run `bash automation/lint_workspace_skills.sh` + `audit_workspace.sh meta`, and schedule graph tool update (KB snapshot increment).
