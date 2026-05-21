# Public Safety

This repository is safe to publish because it contains only generic architecture, workflow, SOP, and empty templates.

## Never Commit

- real target data
- real reports
- raw scan output
- proof-of-concept bundles
- credentials
- cookies or tokens
- internal paths
- screenshots with private data
- private knowledge-base notes

## Keep Public

- architecture diagrams
- lifecycle descriptions
- empty templates
- validation scripts
- public-safe terminology

## Verification

Run:

```bash
python3 scripts/verify_public_skeleton.py
python3 -m pytest tests/test_public_skeleton.py -q
```

The verifier checks for forbidden operational directories and common sensitive strings.
