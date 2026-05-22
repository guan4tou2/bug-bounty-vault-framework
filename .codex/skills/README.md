# Codex Skills Mirror

These are Codex-compatible wrappers for the canonical Claude workspace skills and agent prompts.

Canonical sources:

- `.claude/skills/*/SKILL.md`
- `.claude/agents/*.md`

Generated wrappers:

| Skill | Path |
|---|---|
| `bb-agent-prompts` | `.codex/skills/bb-agent-prompts/SKILL.md` |
| `bb-context-handoff` | `.codex/skills/bb-context-handoff/SKILL.md` |
| `bb-cve-citation` | `.codex/skills/bb-cve-citation/SKILL.md` |
| `bb-dedup-finding` | `.codex/skills/bb-dedup-finding/SKILL.md` |
| `bb-hitcon-form` | `.codex/skills/bb-hitcon-form/SKILL.md` |
| `bb-incident-response` | `.codex/skills/bb-incident-response/SKILL.md` |
| `bb-triage-response` | `.codex/skills/bb-triage-response/SKILL.md` |
| `bb-version-cve-precheck` | `.codex/skills/bb-version-cve-precheck/SKILL.md` |

## Install for Codex

Codex loads user skills from `~/.codex/skills`. To link these repo wrappers into the local Codex skill directory:

```bash
bash automation/install_codex_skills.sh
```

To verify without writing:

```bash
python3 automation/sync_codex_skills.py --check
bash automation/install_codex_skills.sh --check
```

Do not edit generated wrappers by hand. Update `.claude/skills` or `.claude/agents`, then run:

```bash
python3 automation/sync_codex_skills.py
```
