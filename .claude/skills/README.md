# Workspace Skills Registry

This registry keeps Claude workspace skills discoverable and reviewable. Each skill lives in `.claude/skills/<name>/SKILL.md`, uses search-optimized frontmatter, and is referenced from `CLAUDE.md`.

| Skill | Trigger | Path |
|---|---|---|
| `bb-version-cve-precheck` | Software / firmware / SaaS analysis before hands-on work; latest version and CVE/advisory pre-checks | `.claude/skills/bb-version-cve-precheck/SKILL.md` |
| `bb-tool-setup` | Tool layer (Ring 2) not yet established; first hunter/scanner run, bbflow/scanner not found, or no candidates.jsonl produced | `.claude/skills/bb-tool-setup/SKILL.md` |
| `bb-surface-mapping` | Start of any target, after recon and before any pattern/hunter/scan; vuln-agnostic full attack-surface mapping (anti-streetlight FRONT gate) | `.claude/skills/bb-surface-mapping/SKILL.md` |
| `bb-web-vuln-scan` | Testing a web target's endpoints/params; OWASP Top 10 coverage, injection matrix, version→CVE, WAF bypass (runs after surface mapping) | `.claude/skills/bb-web-vuln-scan/SKILL.md` |
| `bb-dedup-finding` | Opening a new Finding/FORM or deciding whether evidence is a duplicate | `.claude/skills/bb-dedup-finding/SKILL.md` |
| `bb-cve-citation` | Writing CVE, NVD, GHSA, vendor advisory, disclosed report, or prior disclosure references | `.claude/skills/bb-cve-citation/SKILL.md` |
| `bb-form-writer` | Creating or editing platform-neutral disclosure forms, submission bundles, and report packages | `.claude/skills/bb-form-writer/SKILL.md` |
| `bb-context-handoff` | Context-low checkpoint, handoff, takeover, or long-session continuation | `.claude/skills/bb-context-handoff/SKILL.md` |
| `bb-triage-response` | Accepted / Duplicate / N/A / Informative / Triaged / Resolved platform replies | `.claude/skills/bb-triage-response/SKILL.md` |
| `bb-incident-response` | Sustained 5xx, service impact, vendor downtime notice, or unintended impact | `.claude/skills/bb-incident-response/SKILL.md` |
| `bb-scope-safety-check` | Live verification, scan, payload, write method, bbflow / Osmedeus / Nuclei / BBOT safety gate | `.claude/skills/bb-scope-safety-check/SKILL.md` |
| `bb-exploit-chain` | A vuln/leak was found; run the 6-question chain before moving to the next system (escalate, don't stop at exposure) | `.claude/skills/bb-exploit-chain/SKILL.md` |
| `bb-attack-chain-review` | Finding candidate or observation may chain into higher impact | `.claude/skills/bb-attack-chain-review/SKILL.md` |
| `bb-evidence-readiness` | Finding / Submission / FORM evidence completeness and reproducibility review | `.claude/skills/bb-evidence-readiness/SKILL.md` |
| `bb-attempt-recorder` | Failed hypothesis, false positive, blocked test, or useful negative result | `.claude/skills/bb-attempt-recorder/SKILL.md` |
| `bb-submission-readiness` | Final gate before Submission / FORM creation or ready_to_submit status | `.claude/skills/bb-submission-readiness/SKILL.md` |
| `bb-knowledge-capture` | Reusable learning from finding candidate, attempt, chain review, tool result, or triage reply | `.claude/skills/bb-knowledge-capture/SKILL.md` |

## Maintenance

- Keep frontmatter to exactly `name` and `description`.
- Make `description` start with `Use when` and describe triggers only.
- Add the skill to this registry and `CLAUDE.md` in the same change.
- Regenerate the Codex/Gemini mirrors with `python3 automation/sync_codex_skills.py`.
- Verify with `pytest tests/test_public_skeleton.py -q`.
