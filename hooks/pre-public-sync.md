# Pre-Public Sync

## Purpose

Protect the public seed from receiving private runtime data.

## Trigger

Before proposing changes from a private vault back to a public seed or shared framework.

## Inputs

- Changed files.
- Proposed public update summary.
- Sanitization checklist.

## Stop conditions

- Change contains real target names, accounts, domains, tokens, raw output, screenshots, or private queue state.
- Change adds destination-specific templates.
- Change adds tool profiles, hunter logic, payloads, or private lessons.
- Change weakens scope, safety, or evidence gates.

## Output

Return `safe for public`, `needs sanitization`, or `private only`, with a concise reason.
