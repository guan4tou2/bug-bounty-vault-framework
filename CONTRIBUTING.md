# Contributing

Thanks for improving the Bug Bounty Vault Framework. This repo is a **public seed** — a clean, private-data-free starting point that people clone and grow into their own private vault. Contributions should keep it that way.

## Ground rules

1. **No private data, ever.** No real targets, hosts, IPs, emails, credentials, tokens, screenshots, scan output, or author-specific tooling/paths. Use `example.com`, `<target>`, and `ACME-001`-style placeholders.
2. **English content.** Prose, headings, and template labels are English. Short non-English *utterance-trigger aliases* in a skill's `description` line are fine (they help non-English users trigger the skill), but bodies stay English.
3. **The repo root is the vault root.** Never hard-code a private vault's own directory name as a path prefix, and don't reference private auto-memory files or bespoke personal tooling. Use vault-root-relative paths. (The test suite enforces a denylist of known private-infra strings — see `test_no_private_infrastructure_path_patterns`.)
4. **Tests must pass.** Run the suite before opening a PR (see below). CI runs it on every push/PR.

## Setup

```bash
git clone https://github.com/guan4tou2/bug-bounty-vault-framework.git
cd bug-bounty-vault-framework
python -m pip install pytest pyyaml
```

## Run the checks

```bash
python -m pytest tests/ -q                       # structure, parity, safety, link & frontmatter integrity
python3 automation/check_vault.py                # vault health
python3 automation/sync_codex_skills.py --check  # Codex/Gemini mirrors in sync
python3 _automation/lint_frontmatter.py --all    # frontmatter schema (Findings/Attempts/Submissions/Recon)
```

## Adding content

### A Knowledge Base Pattern

Copy the shape of `09 - Knowledge Base/Pattern - IDOR.md`. Frontmatter must include `type: pattern`. Use P1-P5 in the severity guide (not Critical/High). Link related notes with `[[wikilinks]]` that resolve to existing notes.

### A Playbook / Checklist / Reference Card

Use `type: reference` with the matching `category:` (`playbook` / `checklist`). Keep frontmatter valid YAML — no Templater `<% %>` tokens in committed seed files.

### A skill or agent

Edit the **source of truth** under `.claude/skills/` or `.claude/agents/`. Then regenerate the mirrors:

```bash
python3 automation/sync_codex_skills.py
```

Never hand-edit files under `.codex/skills/` or `.gemini/skills/` — they are generated.

### A template or example note

Findings, Attempts, Submissions, and Recon notes are schema-validated by `_automation/lint_frontmatter.py`. If you add example notes under `01 - Targets/_example/`, run the linter and make sure they pass.

## Frontmatter schema

The single source of truth is `_automation/lint_frontmatter.py` plus the `07 - Templates/` files. `STRUCTURE.md` §6 and `VAULT_QUICK.md` document it; if they ever disagree, the linter and templates win.

## Commit style

- Small, focused commits with a clear subject line.
- Run the checks above before pushing.
- Don't commit anything under `workspace/` — it is gitignored runtime scratch.

## Reporting a problem

Open an issue describing what's wrong (a broken link, a stale doc, a failing check on a fresh clone). If you found it via a failing test, include the test name.
