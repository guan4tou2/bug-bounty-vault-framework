# Workspace Scaffold

This directory is the runtime workspace scaffold for a private vault created from this public seed.

The repository is designed to be opened as an Obsidian vault root. The `workspace/` folder stays inside that vault root so notes, prompts, hooks, bbflow contracts, and temporary runtime paths share one predictable layout.

Runtime contents are not synced back to this public repository. After adoption, this area is owned by the private operator.

Suggested use:

- `workshop/` for per-target scratch notes, raw recon output, and temporary proof material.
- `tools/` for local tool checkouts or wrappers, including a private bbflow runtime.
- `reports/` for private working copies before final review.
- `logs/` for local automation, hook, and session logs.

Keep this scaffold generic:

- Do not commit real target data.
- Do not commit credentials, cookies, tokens, screenshots, or raw responses.
- Do not commit scanner output or generated reports.
- Do not sync runtime output back to the public seed.

