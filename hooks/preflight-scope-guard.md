# Preflight Scope Guard

## Purpose

Block workflow execution until authorization and scope are explicit.

## Trigger

Before creating target notes, running automation, reviewing candidates, or generating downstream handoff text.

## Inputs

- Scope note or scope file.
- Requested target placeholder.
- Requested action category.
- Safety level.

## Stop conditions

- Scope is absent, stale, or ambiguous.
- Requested asset is not explicitly allowed.
- Requested action exceeds the declared safety level.
- Output location is not an ignored private workspace.

## Output

Return `pass`, `blocked`, or `needs clarification`, plus the reason and the next safe action.
