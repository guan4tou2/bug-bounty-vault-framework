---
type: wiki-index
status: active
last-updated: 2026-08-12
---

# Bug Bounty Arsenal — Wiki

> This wiki is a **complete operating manual for bbflow + the full toolchain**. Every document is self-contained and actionable without external references.
> Designed as a low-noise bug hunting workflow for sites behind WAFs / firewalls (government, financial, telecom).

## Flow (read in order)

| # | Document | Description |
|---|------|------|
| **00** | [bbflow Complete Operating Flow](00-bbflow-complete-flow.md) | End-to-end init → recon → hunt → report, usage for every subcommand |
| **01** | [WAF / Firewall Bypass Playbook](01-waf-bypass-playbook.md) | How to operate behind government sites, Cloudflare, Akamai, Imperva |
| **02** | [Government Sites / Low-Severity Bounty Quick Wins](02-gov-site-quick-wins.md) | Common easy wins on government engagements, each tagged with ROI |
| **03** | [xray Rules Localization Reference](03-xray-rules-reference.md) | ChaitinTech/xray stable rule mapping — which ones you can reproduce with curl |

## Attack Command Quick Reference

| # | Document | Description |
|---|------|------|
| **14** | [WAF Bypass Command Set](14-waf-bypass-commands.md) | 15+ automated + manual WAF bypasses (header/path/method/smuggling/origin) |
| **15** | [Nuclei Full Attack-Template Coverage](15-nuclei-attack-templates.md) | Commands for each class: XSS/SQLi/SSRF/LFI/RCE/Redirect/SSTI/XXE/Takeover |
| **16** | [OAuth 2.0 / OIDC Attack Chains](16-oauth-attack-chains.md) | 12 techniques: redirect_uri bypass / PKCE / scope escalation / MCP scope / JWT alg / jku |
| **17** | [GraphQL Deep Attacks](17-graphql-deep-attacks.md) | 10 techniques: introspection / integer IDOR / alias overload / unauth mutation / DoS |
| **18** | [Payload Cheatsheet](18-payload-cheatsheet.md) | XSS polyglot / SQLi / SSTI (Jinja2/Twig/Freemarker/Velocity/ERB) / LFI / CmdInj / SSRF / XXE / NoSQLi |

## Advanced Attack Walkthroughs

| # | Document | Description |
|---|------|------|
| **19** | [Subdomain Recon Deep Dive](19-subdomain-recon-deep.md) | Full chain: passive + active + permutation + 3rd-party + ASN |
| **31** | [JWT Attack Walkthrough](31-jwt-attack-walkthrough.md) | alg:none / HS256 brute-force / alg confusion / kid/jku injection + jwt_tool |
| **32** | [Cloud Key / Credential Abuse](32-cloud-key-abuse.md) | AWS/GCP/Azure + SaaS key validation discipline (list-only, never modify) |
| **33** | [Nuclei Custom Template Authoring](33-nuclei-custom-templates.md) | matchers/extractors/payloads/headless/DSL + hands-on examples |

## High-Payout, High-Frequency Attacks

| # | Document | Description |
|---|------|------|
| **60** | [HTTP Request Smuggling](60-request-smuggling.md) | CL.TE / TE.CL / TE.TE / H2.CL / H2.TE + smuggler.py + Burp workflow |
| **61** | [Race Condition / Single-Packet Attack](61-race-condition.md) | TOCTOU + Turbo Intruder + 8 classic patterns (coupon/MFA/withdraw/...) |
| **62** | [File Upload Exploitation](62-file-upload-exploitation.md) | ext/MIME/magic/SVG/ZIP slip/polyglot + shells per language + ImageMagick/Ghostscript |
| **63** | [Prototype Pollution](63-prototype-pollution.md) | Client-side gadgets + server-side via lodash/merge + DOM Invader + CVE table |
| **64** | [Web Cache Poisoning / Deception](64-cache-poisoning.md) | Unkeyed header / Param Miner / cache-key testing + Omer Gil deception |

## OWASP Top 10 Deep Attacks

| # | Document | Description |
|---|------|------|
| **65** | [CSRF Complete Guide](65-csrf-deep.md) | 2026 SameSite landscape + JSON CSRF (text/plain trick) + referer bypass + 2FA/email-change chain |
| **66** | [SSRF Deep Dive](66-ssrf-deep.md) | Cloud metadata (AWS/GCP/Azure/K8s) + gopher→Redis RCE + DNS rebinding + SSRFmap/Gopherus |
| **67** | [Insecure Deserialization](67-deserialization.md) | Java ysoserial + PHP phpggc(phar) + .NET ysoserial.net + Python pickle + Node.js |
| **68** | [WebSocket / CSWSH](68-websocket-cswsh.md) | Origin-check bypass + CSWSH hijack + subscription IDOR + message-layer injection |
| **69** | [Mass Assignment & HPP](69-mass-assignment-hpp.md) | role/isAdmin self-privilege-escalation + HPP WAF bypass + gotchas per framework (Rails/Django/Spring/Laravel) |
| **70** | [Host Header + CRLF Injection](70-host-header-crlf.md) | Password reset poisoning (ATO chain) + X-Forwarded-Host + CRLF response splitting |

## Classic Top 10, Deep Dive

| # | Document | Description |
|---|------|------|
| **71** | [XSS Deep Dive](71-xss-deep.md) | DOM sink catalog + postMessage XSS + CSP bypass + Mutation XSS (DOMPurify CVEs) + Trusted Types bypass + CSTI per framework + blind XSS |
| **72** | [SQLi Deep Dive](72-sqli-deep.md) | 2nd-order + per-DB OOB + calibrated blind timing + stacked-query support table + NoSQLi (Mongo/ES/GraphQL) + WAF bypass |
| **73** | [SSTI Deep Dive](73-ssti-deep.md) | Differential fingerprinting probe table + RCE gadgets for 9 engines (Jinja2/Twig/Freemarker/Velocity/Thymeleaf/ERB/EJS/Handlebars/Smarty) + sandbox escape |
| **74** | [Command Injection Deep Dive](74-command-injection.md) | Sinks per language + Unix/Windows syntax + filter bypass (${IFS}/quoting/encoding) + blind OOB + argv injection |
| **75** | [XXE Deep Dive](75-xxe-deep.md) | Blind + external DTD + parameter-entity exfil + Java jar:// + full PHP wrapper set + XInclude + SVG/DOCX/EPUB/SOAP + defensive config |
| **76** | [LFI / Path Traversal](76-lfi-path-traversal.md) | PHP wrappers (filter/input/data/zip/phar) + log poisoning (apache/ssh/session) + K8s pod token + prefix-check bypass |

## API / Business Logic

| # | Document | Description |
|---|------|------|
| **77** | [IDOR / BOLA / BFLA](77-idor-bola-bfla.md) | OWASP API #1+#5+#3 + UUID v1 time attack + GraphQL alias batching + node interface + Autorize/AuthMatrix |
| **78** | [Open Redirect: 30+ Bypasses + Attack Chains](78-open-redirect.md) | 30+ bypasses grouped by defense type + scheme bypass + URL parser inconsistency (Orange Tsai) + OAuth code-theft chain |
| **79** | [Subdomain / Cloud Takeover](79-subdomain-cloud-takeover.md) | can-i-take-over-xyz reference + S3/Azure/Heroku/GitHub Pages + apex-session-scope high-trust chain |
| **80** | [MFA / 2FA Bypass Handbook](80-mfa-bypass.md) | Rate-limit misses / race conditions / response manipulation / backup-code enumeration / push bombing / trust-cookie / SSO bypass |

## 2026's Hot New Attack Surfaces

| # | Document | Description |
|---|------|------|
| **81** | [MCP Server Security](81-mcp-server-security.md) | MCP OAuth scope mismatch + tool injection + indirect prompt injection + BOLA + transport |
| **82** | [AI / LLM Security](82-ai-llm-security.md) | OWASP LLM Top 10 + direct/indirect injection + output handling + jailbreaks + RAG poisoning |
| **83** | [SAML / OIDC Attacks](83-saml-oidc-attacks.md) | 8 XSW variants + signature stripping + comment truncation + OIDC alg/kid/JWKS/state/nonce/PKCE |

## Operational (Workflow and Deep Tool Usage)

| # | Document | Description |
|---|------|------|
| **84** | [Source Code Review Flow](84-source-code-review-flow.md) | Regex + sinks + framework files per language + semgrep/ast-grep + 2-hour hunt checklist |
| **85** | [Burp Pro Advanced Usage](85-burp-pro-advanced.md) | Collaborator + Turbo Intruder + Logger++ + BCheck + Bambda + DOM Invader + Match&Replace + Session handling |
| **86** | [Dupe Hunting + Report Writing](86-dupe-hunting-report-writing.md) | Dupe search across 3 platforms + VRT reality check + report structure + avoiding overclaiming/N/A + follow-up discipline |
| **87** | [Finding Lifecycle State Machine](87-finding-lifecycle-state-machine.md) | Reference card for valid state transitions — what a finding can do next, whether it's submit-ready |
| **88** | [TWCERT Firmware Report Writing Rules](88-twcert-firmware-report-rules.md) | Reference card for TWCERT firmware report writing conventions layered on top of field definitions |

## Hunters (bbflow built-in hunters explained)

| # | Hunter | Purpose | Document |
|---|--------|------|------|
| 10 | `config-leak` | xray-style config leaks (.git/.env/actuator/swagger/100+ paths) | [Details](10-hunter-config-leak.md) |
| 11 | `weak-login` | Single-probe default-creds check for common admin interfaces (nacos/druid/grafana/...) | [Details](11-hunter-weak-login.md) |
| 12 | `backup-files` | Backup / dump files (zip/tar.gz/sql/bak) | [Details](12-hunter-backup-files.md) |
| 13 | `crawl-chain` | katana+gau+paramspider → uro+gf → arjun → nuclei DAST → dalfox | [Details](13-hunter-crawl-chain.md) |
| 14 | `waf-bypass` | 15+ automated WAF bypasses (header/path/method/origin IP) | [Command set](14-waf-bypass-commands.md) |
| 15 | `nuclei-deep` | Extended coverage across 18 attack-surface categories (XSS/SQLi/SSRF/LFI/RCE/SSTI/XXE/...) | [Command set](15-nuclei-attack-templates.md) |
| — | Other existing hunters | envdata / sourcemap / js-secrets / cors / graphql / userenum / ... | See `hunters/README.md` |

## Tools (individual tool manuals)

**Recon / liveness detection**

| # | Tool | Purpose | Document |
|---|------|------|------|
| 20 | `katana` | Modern JS-aware crawler (SPA-friendly) | [Details](20-tool-katana.md) |
| 21 | `gau` | Historical URLs (wayback + commoncrawl + otx + urlscan) | [Details](21-tool-gau.md) |
| 22 | `subfinder` + `httpx` | Subdomain enumeration + liveness | [Details](22-tool-subfinder-httpx.md) |

**Discovery / Fuzzing**

| # | Tool | Purpose | Document |
|---|------|------|------|
| 23 | `arjun` | Hidden HTTP parameter discovery | [Details](23-tool-arjun.md) |
| 24 | `nuclei` | YAML-based template scanner (incl. DAST) | [Details](24-tool-nuclei.md) |
| 25 | `dalfox` | Dedicated XSS scanner | [Details](25-tool-dalfox.md) |
| 26 | `ffuf` + `feroxbuster` | Directory / file fuzzing | [Details](26-tool-ffuf.md) |

**Secrets / Source**

| # | Tool | Purpose | Document |
|---|------|------|------|
| 27 | `trufflehog` + `gitleaks` | 100+ secret detectors | [Details](27-tool-trufflehog.md) |
| 28 | `git-dumper` + `GitTools` + `GitHack` | `.git/` leak recovery | [Details](28-tool-git-dumper.md) |

**SQL Injection / Manual Testing**

| # | Tool | Purpose | Document |
|---|------|------|------|
| 29 | `sqlmap` | Automated SQL injection (B/U/T/E/S/Q + tamper + WAF bypass) | [Details](29-tool-sqlmap.md) |
| 30 | Burp Suite / Caido | Manual intercept / Repeater / MITM | [Details](30-tool-burp-caido.md) |

## Checklists (work through and check off)

| # | Checklist | Purpose |
|---|-----------|------|
| 40 | [New Target Assessment Checklist](40-checklist-new-target.md) | Lay out the full attack surface within 24 hours |
| 41 | [Pre-Submission Final Checklist](41-checklist-before-submit.md) | Avoid low-quality rejections (VRT classification, overclaiming, dupes) |

## FAQ

- **Q: WAF is blocking my scan — what now?** → See [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md) + [14-waf-bypass-commands.md](14-waf-bypass-commands.md)
- **Q: Default Nuclei templates aren't finding anything?** → See [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) (18 category walkthroughs) + [24-tool-nuclei.md](24-tool-nuclei.md) + [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md)
- **Q: Which bugs are easiest to land on government sites?** → See [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md)
- **Q: How do I configure a gau API key?** → See [21-tool-gau.md](21-tool-gau.md) § "Config file"
- **Q: Found a SQLi and want to dump the DB?** → See [29-tool-sqlmap.md](29-tool-sqlmap.md)
- **Q: What should I hit in the first 24h on a new target?** → See [40-checklist-new-target.md](40-checklist-new-target.md) (10 stages)
- **Q: How do I test OAuth/SSO?** → [16-oauth-attack-chains.md](16-oauth-attack-chains.md) (12 attack classes + PoCs)
- **Q: What should I test on a GraphQL endpoint?** → [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md) (introspection → IDOR → alias overload)
- **Q: Need a payload pocket reference for manual testing?** → [18-payload-cheatsheet.md](18-payload-cheatsheet.md) (XSS/SQLi/SSTI/LFI/CmdInj/SSRF/XXE)
- **Q: subfinder coverage isn't good enough?** → [19-subdomain-recon-deep.md](19-subdomain-recon-deep.md) (5 layers: passive + active + permutation + ASN)
- **Q: Found a JWT — how do I attack it?** → [31-jwt-attack-walkthrough.md](31-jwt-attack-walkthrough.md) (12 implementation flaws + jwt_tool commands)
- **Q: Found an AWS/GCP key — how do I validate it without crossing a line?** → [32-cloud-key-abuse.md](32-cloud-key-abuse.md) (safety principles + SaaS key reference table)
- **Q: Want to write a custom Nuclei template?** → [33-nuclei-custom-templates.md](33-nuclei-custom-templates.md) (matchers/extractors/DSL fully explained + 4 worked examples)
- **Q: Suspect desync / abnormal backend parsing?** → [60-request-smuggling.md](60-request-smuggling.md) (CL.TE/TE.CL/H2, all variants)
- **Q: Business logic looks race-able?** → [61-race-condition.md](61-race-condition.md) (single-packet attack + 8 patterns)
- **Q: Found an upload endpoint — how do I attack it?** → [62-file-upload-exploitation.md](62-file-upload-exploitation.md) (ext/MIME/SVG/ZIP slip, all bypasses)
- **Q: Seeing lodash.merge / Object.assign on user input?** → [63-prototype-pollution.md](63-prototype-pollution.md) (client + server PP)
- **Q: There's a CDN — can reflected XSS become stored?** → [64-cache-poisoning.md](64-cache-poisoning.md) (unkeyed headers + deception)
- **Q: Is CSRF still exploitable with SameSite=Lax?** → [65-csrf-deep.md](65-csrf-deep.md) (2-second window + text/plain JSON CSRF + method override)
- **Q: There's a webhook/url parameter — can I get SSRF?** → [66-ssrf-deep.md](66-ssrf-deep.md) (IMDS + gopher Redis RCE + DNS rebinding)
- **Q: Seeing aced0005 / unserialize / pickle?** → [67-deserialization.md](67-deserialization.md) (ysoserial/phpggc across all languages)
- **Q: Found a wss:// WebSocket endpoint?** → [68-websocket-cswsh.md](68-websocket-cswsh.md) (missing Origin check → hijack)
- **Q: Registration/profile update has a role field?** → [69-mass-assignment-hpp.md](69-mass-assignment-hpp.md) (isAdmin:true direct privilege escalation)
- **Q: Password reset link contains evil.com?** → [70-host-header-crlf.md](70-host-header-crlf.md) (X-Forwarded-Host ATO)
- **Q: Advanced XSS (CSP/DOM/mXSS/Trusted Types)?** → [71-xss-deep.md](71-xss-deep.md)
- **Q: Blind/OOB SQLi or NoSQLi?** → [72-sqli-deep.md](72-sqli-deep.md)
- **Q: Seeing `${}` `{{}}` `<%%>` `${{}}` — suspected SSTI?** → [73-ssti-deep.md](73-ssti-deep.md) (RCE gadgets for 9 engines)
- **Q: How do I catch blind command injection?** → [74-command-injection.md](74-command-injection.md) (interactsh OOB)
- **Q: How do I attack an XML endpoint with XXE?** → [75-xxe-deep.md](75-xxe-deep.md)
- **Q: `?file=` parameter looks LFI-able?** → [76-lfi-path-traversal.md](76-lfi-path-traversal.md)
- **Q: How do I test IDOR systematically?** → [77-idor-bola-bfla.md](77-idor-bola-bfla.md)
- **Q: How do I escalate an open redirect to P2+?** → [78-open-redirect.md](78-open-redirect.md) (OAuth chain)
- **Q: Found a dangling CNAME?** → [79-subdomain-cloud-takeover.md](79-subdomain-cloud-takeover.md)
- **Q: Want to bypass 2FA / test MFA strength?** → [80-mfa-bypass.md](80-mfa-bypass.md)
- **Q: Found an MCP server endpoint?** → [81-mcp-server-security.md](81-mcp-server-security.md)
- **Q: Testing an LLM chatbot / code assistant?** → [82-ai-llm-security.md](82-ai-llm-security.md)
- **Q: How do I test SAML / OIDC SSO?** → [83-saml-oidc-attacks.md](83-saml-oidc-attacks.md)
- **Q: Got source code — how do I find a bug in 2 hours?** → [84-source-code-review-flow.md](84-source-code-review-flow.md)
- **Q: Want to level up Burp Pro usage?** → [85-burp-pro-advanced.md](85-burp-pro-advanced.md)
- **Q: What's the workflow to avoid dupes/N/A?** → [86-dupe-hunting-report-writing.md](86-dupe-hunting-report-writing.md)
- **Q: Is this finding ready to submit / what state is it in?** → [87-finding-lifecycle-state-machine.md](87-finding-lifecycle-state-machine.md)
- **Q: Writing a TWCERT firmware report?** → [88-twcert-firmware-report-rules.md](88-twcert-firmware-report-rules.md)

## Related Resources

- `bbflow.sh` — orchestrator for all hunters (repo root)
- `hunters/` — individual hunter source code
- `configs/gau.toml` — gau config file
- Optional: pair this wiki with your own Pattern / Playbook notes
