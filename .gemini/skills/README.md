# Gemini CLI Skills Mirror

These are Gemini CLI-compatible wrappers for the canonical Claude workspace skills and agent prompts.

Canonical sources:

- `.claude/skills/*/SKILL.md`
- `.claude/agents/*.md`

Generated wrappers:

| Skill | Path |
|---|---|
| `bb-agent-prompts` | `.gemini/skills/bb-agent-prompts/SKILL.md` |
| `bb-attack-chain-review` | `.gemini/skills/bb-attack-chain-review/SKILL.md` |
| `bb-attempt-recorder` | `.gemini/skills/bb-attempt-recorder/SKILL.md` |
| `bb-context-handoff` | `.gemini/skills/bb-context-handoff/SKILL.md` |
| `bb-cve-citation` | `.gemini/skills/bb-cve-citation/SKILL.md` |
| `bb-dedup-finding` | `.gemini/skills/bb-dedup-finding/SKILL.md` |
| `bb-evidence-readiness` | `.gemini/skills/bb-evidence-readiness/SKILL.md` |
| `bb-form-writer` | `.gemini/skills/bb-form-writer/SKILL.md` |
| `bb-incident-response` | `.gemini/skills/bb-incident-response/SKILL.md` |
| `bb-knowledge-capture` | `.gemini/skills/bb-knowledge-capture/SKILL.md` |
| `bb-scope-safety-check` | `.gemini/skills/bb-scope-safety-check/SKILL.md` |
| `bb-submission-readiness` | `.gemini/skills/bb-submission-readiness/SKILL.md` |
| `bb-triage-response` | `.gemini/skills/bb-triage-response/SKILL.md` |
| `bb-version-cve-precheck` | `.gemini/skills/bb-version-cve-precheck/SKILL.md` |

## Install for Gemini CLI

Gemini CLI loads user skills from `~/.gemini/skills`. To link these repo wrappers into the local Gemini skill directory:

```bash
bash automation/install_gemini_skills.sh
```

To verify without writing:

```bash
python3 automation/sync_codex_skills.py --check
bash automation/install_gemini_skills.sh --check
```

Do not edit generated wrappers by hand. Update `.claude/skills` or `.claude/agents`, then run:

```bash
python3 automation/sync_codex_skills.py
```
