# Claude Instructions

Claude-specific entrypoint for this public-safe framework.

Read `AGENTS_QUICK.md` first, then follow `AGENTS.md`.

## Operating Mode

- Treat this repository as an Obsidian vault root seed.
- Keep `workspace/` as ignored runtime space.
- Treat `bbflow/` as an automation contract, not a scanner implementation.
- Require Authorized scope for security research workflow tasks.
- Keep Knowledge Capture generic and sanitized.

## When Creating Notes

Use:

```bash
python3 scripts/new_note.py --type <target|recon-note|finding|review-note|submission|form|scope> --target <name> --program <name>
```

Do not create platform-specific templates or private report formats in this public repository.

