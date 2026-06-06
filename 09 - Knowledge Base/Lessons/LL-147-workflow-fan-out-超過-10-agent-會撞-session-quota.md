---
type: lesson
id: "147"
title: "Workflow fan-out 超過 10 agent 會撞 session quota 看起來像 schema bug"
tags:
  - bb-lesson
  - workflow
  - orchestration
  - quota
last_updated: 2026-06-04
---

# 教訓 #147. Workflow fan-out 超過 10 agent 會撞 session quota 看起來像 schema bug

## TL;DR
2026-06-04 跑 `bb-session-learning` workflow(42 miner + 9 researcher = 51 agent 同時 fan out)→ 全部 7 個 parallel 階段失敗,錯誤訊息:`agent({schema}): subagent completed without calling StructuredOutput (after 2 in-conversation nudges)`。**第一直覺去動 schema,完全是錯的方向**:讀 subagent jsonl 看到 agent 最後一句是 `You've hit your session limit · resets 12:10am (Asia/Taipei)`,根本沒在 reasoning,只是 quota 撞牆。

## 觀察
- harness 把 quota error 字串當「assistant 回了 text」處理 → 兩次 nudge → 放棄 → 報 schema 錯
- 51 agent 在毫秒級 dispatch,瞬間吃光 1 個 rolling window
- 重試的 `wf_f5cddef3` 也敗

## 規則
1. **agent 並行上限 ≤ 10**(經驗值);超過要分輪
2. **任何 workflow 動手前讀 `budget.remaining()`**,動態 scale fleet size
3. **看到 StructuredOutput 失敗,先 grep agent jsonl 找 "session limit" / "rate limit"**,不要先怪 schema
4. 大量 mine 工作 → 拆 phase:phase 1 mine(N agent)、phase 2 dedup(barrier)、phase 3 synthesize(少 agent)

## 反例 — 同 session 成功的 workflow
- `bb-deepread-writeups`(11 agent,1 篇 1 個)— ✅
- `bb-session-learning-batch2`(6 curator)— ✅
- `bb-session-learning`(51 agent)— ❌

差距就在「並行數」。

## Related
- [[Playbook - Reusable Workflows]] §0 — 共用注意事項
- 教訓 #143 — LLM 二次審查 100% pass-rate 是設計缺陷(同個層面:用 LLM 的姿勢決定可不可靠)
