---
type: reference
category: checklist
tags: [checklist, target-selection, pre-screen, roi, account, scope]
added: 2026-10-12
---

# Checklist — Target Feasibility Pre-Screen

> **Guiding principle:** Spend two minutes on this before deep work. The recurring waste is discovering, several sessions in, that you cannot get an account, the reward for this finding class is zero, KYC is required, or the rules forbid the class you are hunting. Feasibility is a **target-selection filter**, not an obstacle to stumble on halfway through.

---

## Confirm before deep work (any failure → switch targets or adjust the investment)

- [ ] **Accounts obtainable?** Is registration open, or does it need an invitation / business verification? Is the authenticated surface the main battlefield? (If production returns 401 everywhere, no account roughly halves the reachable surface.)
- [ ] **Disposable / test mailbox accepted?** Test one registration with a test address up front instead of hitting the block on each sub-product in turn.
- [ ] **KYC or real-identity verification required?** Finance and wallet products often gate features behind KYC. Treat it as a high barrier and decide whether it is worth it.
- [ ] **Reward tier for the classes you expect?** Read the scope and reward table: if your likely findings land in a zero-reward tier, skip the deep dive.
- [ ] **Program status and reachability?** Still active? Private-only? Has the disclosure channel moved? Any geographic restriction on rewards or participation that applies to you?
- [ ] **Meta-rules read in full?** Scoring, review, and merge rules (e.g. "findings on the same system are merged into one") must be read **before** starting, not after several reports are out.
- [ ] **Dedup / prior work checked?** Run `bb-dedup-finding` and the `disclosed-report-researcher` agent; see [[Checklist - Disclosed Findings Pre-Read Gate]].

## Decision rules

A failed item does not automatically mean abandon — it means **know the cost before committing**:

- No account obtainable **and** the authenticated surface is the main battlefield → park the target with a "needs account" note in its HANDOFF.
- Zero reward / no-bounty disclosure program **and** you have hit the ceiling → extract the methodology lessons, then park.
- KYC or geographic restriction → evaluate ROI; usually move to a rewarded target.

Record the parking reason so the target is not re-opened blindly later.

## Related

- [[Checklist - Recon Floor]]
- [[Reference Card - Version and CVE Precheck]]
