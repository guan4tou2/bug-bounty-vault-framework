# Flow

This is a minimal automation lifecycle. Each gate can be implemented by any private toolchain.

## Gate 0 - Intent

Define the purpose of the run and the question it should answer.

## Gate 1 - Scope Guard

Load `scope.example.yaml` or a private scope file. Stop if scope is missing, unclear, expired, or incompatible with the requested action.

## Gate 2 - Plan

Choose the lowest-risk allowed checks. Prefer read-only or passive steps before active automation.

## Gate 3 - Run

Run private tooling in an ignored workspace. Do not write raw output into the vault.

## Gate 4 - Review

Convert tool output into candidates. Mark each item with review status, duplicate risk, and evidence quality.

## Gate 5 - Knowledge Capture

Promote only reusable, sanitized lessons into Pattern, Playbook, Checklist, or Reference Card notes.

## Close-Out

Record run summary, output paths, blocked items, and learning updates.
