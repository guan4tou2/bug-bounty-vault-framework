---
kanban-plugin: board
fileClass: Kanban
target: "[[]]"
last_updated: <% tp.date.now("YYYY-MM-DD") %>
---

## 🔍 Recon

- [ ] Subdomain / host enumeration
- [ ] JS / source map analysis
- [ ] API spec / Swagger discovery
- [ ] Authenticated attack surface inventory

## 🎯 Hunting (active findings)

- [ ] <active hunting direction>

## ✅ Verified (PoC done, not yet reported)

- [ ] [[Finding - <target> - ...]]

## 📤 Reported (submitted, awaiting triage)

- [ ] [[Submission - <target> - ...]]

## 🏁 Triaged (closed)

- [ ] [[Submission - <target> - ...]] ✅ Accepted P3
- [ ] [[Submission - <target> - ...]] ❌ N/A

## 🚫 Killed Attempts

- [ ] [[Attempt - <target> - ...]]

## 💡 Ideas (parked)

- [ ] <future angle to explore>

%% kanban:settings
```
{"kanban-plugin":"board","new-note-folder":"01 - Targets/<target>","show-checkboxes":true,"date-trigger":"@","time-trigger":"@@"}
```
%%
