# ASG 受阻研究與小型工作卡

產品狀態由 EFSM 表達；研究受阻、候選影響與驗證由 ASG 表達。兩者互相引用，
不因產品走到 revoked 就認定權限撤銷有效，也不因 blocked 就記為 refuted。

`blocked_research.py` 使用同一 ledger，保存受阻原因、正常對照、原因解釋、
精確證據與適用條件、單一條件替代假設、逐次 TEST／CONTROL、排除範圍與恢復條件。
`hunt_autodrive` 的失敗／受阻回傳會自動擷取為待診斷紀錄；沒有完整環境或原始證據時，
保存 evidence gap，不能推測是 WAF 或判成陰性。受阻中的原動作不自動重跑。
原始 worker failure envelope 權限為 0600；它只證明 worker 回報失敗，不證明目標防護原因。

## 程式控制的轉換

| 證據／條件 | 排入的下一步 |
|---|---|
| 缺正常對照或正常操作失敗 | `establish_normal_control`：建立／修復正常對照 |
| 正常對照成功，但原因仍不明 | `discriminate_obstruction`：區分競爭解釋 |
| 原因有依據、對照正常、存在未試替代假設 | 單一條件的有限比較 |
| 原本行為與影響已觀察且正常 CONTROL 有效 | 原主張的獨立驗證；不自封 Finding |
| 執行故障、失去確認或證據改變 | 執行對帳／修復／複驗，不盲目重試 |
| 缺資料、缺授權、成本或停止條件 | 保存 waiting、未試理由與恢復條件 |
| scope、平台禁止、人工審批、安全閘 | 回到原授權途徑，禁止替代路徑繞過 |

替代假設最多三條，依低影響及資訊價值排序；重複的相同條件比較被拒絕。
相同證據與分類不能靠改寫理由重跑，也不能另取 obstruction ID 重設同一 hypothesis 的預算。
最後一次未成功比較耗盡預算後，程式直接保存 exhausted／waiting 與恢復條件；
失敗的工具執行同樣消耗比較額度，恢復不會歸零。新的正常 CONTROL 失敗時，先修復對照。
每筆 attempt 要有不同的、當前有效的原始 TEST／CONTROL artifact，HTTP 回應變化
不能單獨標成 behavior_observed。這個標記仍是待驗觀察，所有函式均不建立 verdict。
等待中的研究要有新證據與前提差異才可 resume；保留舊歷史及已消耗的預算。
授權限制不能重新分類成 WAF 來啟動 bypass。

## 工作卡、工具與回寫

`next_work.py` 的前三項附帶 `work_card`，參考資料只列出、不自動載入整份 Skill。
受阻卡包含問題、必要事實與原始引用、缺口、下一步、理由、剩餘比較預算、
成功／失敗／停止條件及恢復條件。其他既有工作種類保留各自的結果契約，
通用卡不捏造尚未取得的 facts。

`work_cards.apply` 重新計算 canonical state fingerprint，拒絕舊卡、修改過的卡、
錯誤分支或非排定 alternative 的結果。完成結果寫回相同 ledger，再導出下一張卡。
`work_cards.execute_alternative` 接入既有 `execute_command`：

- 呼叫端必須持有現有 writer lock、原授權與 ready comparison hypothesis。
- argv Adapter 一次只容許一個參數差異、每操作最多 120 秒；先執行 CONTROL。
- 原 program gate、scope 參照、程序生命週期與原始輸出仍有效；gate 拒絕回寫安全閘受阻。
- 執行設定綁定卡版本；完成的步驟只在回執與檔案 hash 相符時接續，不重做副作用。
- 失敗或未知停止狀態先對帳。輸出由呼叫端的 artifact interpreter 解讀，再核對結果契約。

這是受控執行 Adapter，不是任意命令的自動授權器，也不是所有 GUI／工具的通用 interpreter。
既有 worker 仍只做原派工的兩個動作；替代假設由 Harness 另行排入，不在 worker 私自擴張。
上述分流、重複檢查與預算停止已有行為測試，因此共用受阻 prompt 縮為四行核心職責；
沒有先刪除授權與證據標準，也未將 prompt bytes 的下降宣稱為整體任務 token 成效。

```sh
python3 automation/blocked_research.py TARGET view
python3 automation/blocked_research.py TARGET record --input OBSTRUCTION.json
python3 automation/work_cards.py TARGET --input CARD_RESULT.json
python3 automation/work_cards.py TARGET --explore --input EXPLORATION_PROPOSAL.json
```

結果檔為 `{ "card": <當前卡>, "operation": "diagnose|propose|attempt|close|resume", "payload": {...} }`。
低階 CLI 同樣使用 lock／guarded_save 與相同資料檢查。exploration proposal 保存新的研究問題、
理由、前提及原始證據，交回既有規劃；不自動成為 ready hypothesis，避免鎖死於已知路徑。
快照與 handoff 顯示受阻紀錄；Obsidian 繼續讀既有 ASG 投影。

驗收涵蓋可觀察替代路徑、無法繼續、不得繞過的授權限制、舊卡、缺對照、重複／預算、
回應變化冒充成功、真實本機子程序與 gate 拒絕。尚未量測完整任務 token 或漏測率，
因此沒有先刪除現有核心規範，也沒有宣稱工作卡已帶來總成本下降。

## Continuation and production dispatch

Successful alternatives now enter `request_validation` then
`perform_independent_validation`. A separately identified executor must produce
fresh TEST/CONTROL artifacts distinct from the producer's evidence. Results are
`supported`, `not_supported` or `needs_evidence`; none sets a Finding to verified.
Missing evidence can park the work, and bounded repeated validation cannot loop
forever. Waiting work with stale evidence resumes only with fresh evidence and an
explicit changed condition; its previous comparison budget remains consumed.

`next_work` partitions ready, waiting and human work before selecting three ready
cards. Waiting parent hypotheses cannot re-enter through legacy path/intent views.
Exploration proposals receive explicit adopt/reject review. Adoption creates a
normal hypothesis preserving prerequisites; it does not authorize execution.

`work_dispatch.run_ready` is called by the existing `run_hunt` and `hunt_live`
entry points when `work_config` is supplied, and by this CLI:

```sh
python3 automation/work_dispatch.py TARGET --config PRIVATE_ROUTING.json
```

Operator configuration has `workers`, `bindings` and private `output_dir` fields.
Supported capability/adapter pairs are:

| Capability | Adapter |
|---|---|
| `obstruction-analysis`, `exploration-review`, `reassessment-analysis` | `analysis` |
| `controlled-comparison` | `argv-comparison` |
| `independent-verification` | `argv-verification` |
| `evidence-revalidation` | `artifact-refresh` |

Each worker declares an `actor`. Analysis additionally declares a configured `model`,
`processing_location`, and `allowed_locations`, consistent with the canonical
model-processing policy. Analysis cannot run commands or independently verify itself.
A validation request is a deterministic built-in transition requiring no model.

Execution bindings are keyed by `OBSTRUCTION_ID/ALTERNATIVE_ID` for comparisons,
and `OBSTRUCTION_ID` for verification. They declare a ready comparison `hypothesis`,
`scope_ref`, `risk`, `test_argv`, `control_argv`, and explicit JSON outcome `checks`.
Checks `normal`, `behavior`, `impact` (and optional `rejection`) each contain `field`
and literal `equals`. Exactly one argv argument may differ in an alternative test.
Normal success alone or changed HTTP responses cannot establish impact. Predicates
are operator configuration, not model-generated facts or a universal semantic oracle.

For `artifact-refresh`, a binding supplies fresh `evidence`, `changed_condition` and
`recovery`; it can restore stale waiting work without a model or a tool invocation.
All actual tool actions retain scope/policy/risk checks, operation timeouts and their
original approval path. Unknown effects prevent takeover. Work records, owner,
heartbeats and private result receipts are saved before accepting results. Missing
adapters appear in the human/waiting queue instead of occupying ready slots.

After confirming underlying command stop/effects, settle an interrupted work with:

```sh
python3 automation/work_dispatch.py TARGET --settle-work WORK_ID --receipt LOCAL_RECEIPT --effects effects-checked --state failed
```

Settlement records failure/cancellation, not research success, and does not auto-replay
a possibly executed action. Failed/invalid results remain available for inspection.
Other generic work-card types still require their native adapters. See
[reassessment](reassessment.md) for event-driven plan review and its limits.
