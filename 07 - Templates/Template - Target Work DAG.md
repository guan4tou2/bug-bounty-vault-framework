---
type: target-subpage
subpage: target-work-dag
target: "[[Target - {{name}}]]"
last_updated: "{{date}}"
---

# {{name}} — Target Work DAG

> 用於 recon / validation / decision gates / pentest route / exploit-chain bridge 的效果優先 DAG。
> **何時用：多 surface、多入口、多驗證分支、或 session 之間容易忘記下一步時。單一 request / 單一 finding 可跳過。**
> **Automation contract：只維護四欄表格 `from | edge | to | status`；第 4 欄 `status` 有 `⏳` 才會被 `automation/dag_gaps.sh` 視為未測 edge。**
> **優先序：先提升挖洞 / 滲透能力（coverage、可利用路徑、證據品質、stop condition），再順手節省 token。**

狀態標記：✅ covered / ❌ dead end / ⏳ pending / 🔴 confirmed high ROI / ⚠️ stopped by safety or scope

## 使用規則

- DAG 會隨發現動態增長：新 surface、新能力、新 evidence、新阻擋條件都可以追加成 edge。
- 不為了簡短刪掉高 impact / 高不確定性的 edge；先保留攻擊決策價值，再控制敘述長度。
- 每個 session 從最高 ROI / 最能解除不確定性的 `⏳` edge 開始；若同時有多條，最多挑 3 條 active edge，除非明確拆給 parallel agents。
- 測完就直接改 row status，不另外寫長篇敘述。
- 新線索先進 DAG；證據、raw response、audit ref 再寫 RECON_DB / Finding。
- Mermaid 只在 final report 或需要給人類 review 時 render，平時不畫圖。
- 開 session 先跑 `bash automation/dag_gaps.sh <target>`；只看 recon 可加 `--kind recon`。

## Recon DAG

> 目標：避免只追最亮的線索；把 discovery method 和 surface coverage 留成可接續 edge。

| from（seed/source） | edge（discovery method） | to（surface/asset） | status |
|---|---|---|---|
| Program scope | CT / subfinder / ASN | host inventory | ✅ |
| host inventory | alt-port sweep | unknown service list | ⏳ |
| unknown service list | tech fingerprint | stack-specific test plan | ⏳ |

## Validation DAG

> 目標：把「可疑」拆成可證偽條件，避免重複看同一段證據。

| from（signal） | edge（success criterion） | to（evidence/decision） | status |
|---|---|---|---|
| login redirect candidate | valid account confirms post-login redirect | open redirect evidence | ⏳ |
| source map endpoint | extracts API route and parameter | validation request list | ✅ |
| SSRF parameter | internal metadata response | confirmed SSRF | ❌ |

## Decision Gate DAG

> 目標：把「下一步怎麼選」寫成可驗證分岔。這是決策樹的功能，但仍放在 DAG 中，因為多條路徑會 merge、共享 evidence、跨 session 累積。

| from（current state） | edge（decision condition） | to（next route / stop condition） | status |
|---|---|---|---|
| unknown web stack | fingerprint identifies WordPress | WP route / generic web route | ⏳ |
| candidate finding | evidence meets reproducibility + impact bar | Finding / Attempt | ⏳ |
| exposed version | current vendor advisory covers root cause | abort-known / proceed-zero-day | ⏳ |
| write-capable endpoint | scope and safety allow mutation test | VPS verification / stop at read-only evidence | ⚠️ |

## Pentest Route DAG

> 目標：追蹤從目前 access / capability 到下一個 foothold 的路徑，不只追單一漏洞類型。

| from（access/capability） | edge（action） | to（next foothold/decision） | status |
|---|---|---|---|
| read-only account | enumerate tenant IDs | IDOR candidate list | ⏳ |
| exposed admin page | 401/403 bypass matrix | authenticated-only route map | ⏳ |
| upload feature | extension / MIME / transform tests | upload-to-execution decision | ⚠️ |

## Exploit-chain Bridge

> 找到可串的 finding / data 後，搬到 `Template - Exploit Chain DAG` 做正式 chain 追蹤。

| from（finding/data） | edge（exploit） | to（capability） | status |
|---|---|---|---|
| leaked internal endpoint | IDOR | other user's data | ⏳ |
| leaked version | CVE / advisory precheck | known-N-day decision | ⏳ |

## Subagent 委派（node → worker）— 控 token / 防 session 過長

> DAG 讓「主 loop = orchestrator + judge，node = 拋棄式 worker」這個分工自然成立。
> 探索噪音（大 response、整段源碼、fuzz 輸出、payload 嘗試）關進 subagent 的 context，
> 主 loop 只看回傳的 `status` + evidence 路徑 → context 不脹、compaction 砍掉也能從 DAG 重建。

- **何時委派**：edge 探索**verbose 且自足**（審一個 module、跑一次完整 exploit、fuzz 一個 param）→ 派 subagent。**trivial 檢查**主 loop 自己做，spawn 成本 > 任務。
- **委派什麼**：依層級注入 convention（見 AGENTS.md「Subagent Convention Injection」，subagent 不繼承 CLAUDE.md/AGENTS）。
- **回傳什麼**：只回 `edge status + evidence 檔路徑 + 1-2 行理由`，**不回 raw transcript**；PoC/evidence 寫 `workspace/workshop/<target>/poc/`，回路徑不 inline。
- **判斷留中央**：worker **採集證據**，主 loop（或專責 verify subagent）**做判斷**（reproducibility / anti-exaggeration / dedup 需全局視角）。
- **adaptive 不是 fan-out**：edge 邊挖邊長 → 主 loop 互動式派 subagent；只有已知批次（測這 N 個端點）才用 deterministic workflow。
- **跨 node nuance 進 Carry-state**（下方），別塞進 4 欄表也別只留在 worker context。

## Carry-state ledger（跨 node 必須保留的 nuance + evidence 路徑）

> 只記「下個 node 會用到、但塞進 status 欄太長」的東西。空著代表沒有跨 node 依賴。

- （append…）

## Automation

```bash
bash automation/dag_gaps.sh <target>
bash automation/dag_gaps.sh <target> --kind recon
bash automation/dag_gaps.sh <target> --kind validation
bash automation/dag_gaps.sh <target> --kind decision
bash automation/dag_gaps.sh <target> --kind pentest
bash automation/dag_gaps.sh <target> --kind chain
bash automation/dag_gaps.sh <target> --count
```
