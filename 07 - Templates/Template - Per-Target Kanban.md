---
kanban-plugin: board
fileClass: Kanban
target: "[[]]"
last_updated: <% tp.date.now("YYYY-MM-DD") %>
---

## 🔍 Recon

- [ ] 主子網域列舉
- [ ] JS / source map 分析
- [ ] API spec / Swagger 找
- [ ] 認證後攻擊面盤點

## 🎯 Hunting (active findings)

- [ ] <填入正在挖的方向>

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

- [ ] <未來可試的角度>

%% kanban:settings
```
{"kanban-plugin":"board","new-note-folder":"01 - Targets/<target>","show-checkboxes":true,"date-trigger":"@","time-trigger":"@@"}
```
%%
