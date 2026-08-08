---
type: checklist
title: Fresh Clone Acceptance
last_updated: 2026-05-22
tags: [bootstrap, fresh-clone, acceptance, vault, checklist]
source: internal
added: 2026-05-22
---

# Checklist - Fresh Clone Acceptance

> Goal: within 15 minutes, a fresh clone can open the Vault, read rules, run governance tests, and start a compliant session without raw workspace data.

---

## Acceptance Checklist

- [ ] `git clone https://github.com/<your-github-user>/bug-bounty-vault "bug-bounty-vault"` succeeds.
- [ ] `.workspace_root` points to an external `.vault-workspace` path.
- [ ] Obsidian opens without EACCES.
- [ ] `bash automation/check_portable_layout.sh` reports `vault-root`.
- [ ] `bash automation/test_profiles.sh bootstrap` passes.
- [ ] `bash automation/test_profiles.sh governance` passes.
- [ ] Codex skills are installed or checked with `bash automation/install_codex_skills.sh --check`.
- [ ] `VAULT_QUICK.md` points to active SOP.
- [ ] `bbflow optional`: bbflow is cloned or explicitly deferred.
- [ ] `VPS optional`: SSH / Docker compose / cron are configured only if scan execution is needed.
- [ ] No raw `workspace/`, `rootfs/`, `scan_results/`, or tool output is tracked.

---

## Failure Handling

| Failure | Action |
|---|---|
| Obsidian EACCES | move raw workspace outside Vault; keep `.workspace_root` pointer |
| skill check fails | run `python3 automation/sync_codex_skills.py --check` then install wrappers |
| governance profile fails | fix SOP / docs drift before target work |
| bbflow missing | continue Vault-only workflow; mark bbflow optional until installed |
| VPS missing | do not run scans; use read-only Vault / local planning only |

---

## Related Notes

- [[Reference Card - New Environment Bootstrap]]
- [[Reference Card - LLM Wiki Operating Model]]
- [[Reference Card - Obsidian UX Contract]]
