# Safety Boundary

This framework deliberately avoids operational automation content.

## Excluded Content

- No bundled scanners.
- No evasion guidance.
- No target-specific templates.
- No exploit payload collections.
- No live target examples.
- No credentials, cookies, tokens, or raw logs.

## Required Runtime Checks

Any private implementation should enforce:

1. Scope file exists.
2. Allowed assets are explicit.
3. Disallowed assets are honored.
4. Output directory is ignored by git.
5. Active checks require explicit approval.
6. Knowledge capture removes target-specific details before public reuse.

## Public Boundary

The public framework defines contracts. Private repositories provide tools, commands, profiles, and lessons.
