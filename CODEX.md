# Codex Instructions

Codex-specific entrypoint for this public-safe framework.

Read `AGENTS_QUICK.md` first, then follow `AGENTS.md`.

## Operating Mode

- Prefer small, verifiable edits.
- Use tests when changing scripts or framework contracts.
- Keep `workspace/` runtime contents out of git.
- Treat `bbflow/` as a framework-only boundary.
- Require Authorized scope before any workflow that resembles active research.
- Preserve Knowledge Capture as sanitized Pattern, Playbook, Checklist, or Reference Card updates.

## Verification

Before claiming public-safe changes are ready, run:

```bash
python3 scripts/verify_public_skeleton.py
python3 -m pytest tests/test_public_skeleton.py -q
```

