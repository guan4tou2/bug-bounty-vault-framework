# Agents Quick Path

This is the token-light entrypoint for public-safe LLM work in this framework.

## Read First

1. `README.md`
2. `docs/workflow.md`
3. `docs/public-safety.md`
4. `docs/architecture.md`

Read deeper files only when the task requires them:

- New private vault: `docs/fresh-start.md`
- Session lifecycle: `docs/session-lifecycle.md`
- Preflight gates: `docs/preflight-checks.md`
- Evidence gates: `docs/evidence-model.md`
- Obsidian setup: `docs/obsidian-setup.md`
- LLM Wiki rules: `docs/llm-wiki-framework.md`
- Prompt, agent, and skill model: `docs/prompting-model.md`
- bbflow contract: `bbflow/README.md`

## Public-Safe Rules

- Authorized scope is mandatory before any security research workflow.
- Keep `workspace/` for runtime artifacts, but do not commit runtime contents.
- Use `bbflow/` as a framework contract, not as an installed scanner runtime.
- Keep Knowledge Capture generic: Pattern, Playbook, Checklist, Reference Card.
- Do not copy private runtime data, target data, secrets, screenshots, logs, or raw tool output into this public seed.

## Useful Commands

```bash
python3 scripts/verify_public_skeleton.py
python3 scripts/validate_scope_file.py bbflow/scope.example.yaml
python3 scripts/check_vault.py
python3 scripts/new_note.py --type target --target sample-target --program sample-program
python3 scripts/bootstrap_private_vault.py ../my-private-vault
```

Session lifecycle commands are for an adopted private vault:

```bash
python3 scripts/start_session.py --target sample-target --program sample-program --scope-file bbflow/scope.example.yaml
python3 scripts/end_session.py --target sample-target --summary "framework dry run" --knowledge-capture "none"
python3 scripts/check_private_vault.py --path .
```
