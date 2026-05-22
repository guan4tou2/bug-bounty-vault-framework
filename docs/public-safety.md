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
- empty `workspace/` scaffold files

## Verification

The verifier protects this public skeleton. It is not responsible for validating an adopter's private runtime, private workspace, or future execution data.
It does, however, reject runtime files accidentally left under the public `workspace/` scaffold.

Run:

```bash
python3 automation/check_vault.py
python3 -m pytest tests/test_public_skeleton.py -q
```

The verifier checks for forbidden operational directories and common sensitive strings.
