---
kanban-plugin: board
fileClass: Kanban
target: "[[Target - _example]]"
last_updated: "2026-01-02"
---

## 🔍 Recon

- [x] Subdomain / host enumeration
- [x] Content discovery (api.example.com)
- [ ] Sweep remaining `/{id}` routes (e.g. /api/v1/profile)

## 🎯 Hunting

- [ ] Test `/api/v1/profile` for IDOR
- [x] GraphQL introspection (negative — see Attempt)

## 📝 Verified — Needs Report

- [ ] ACME-001 — IDOR invoice read (Finding done, Submission draft ready)

## 📤 Submitted — Waiting

- (none yet)

## ✅ Triaged / Closed

- (none yet)

%% kanban:settings
```
{"kanban-plugin":"board"}
```
%%
