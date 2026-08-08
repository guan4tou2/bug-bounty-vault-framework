---
title: Diagram - Target Work DAG Lifecycle
tags: [reference-card, dag, diagram]
type: reference-card
last_updated: {{date}}
---

# Diagram — Target Work DAG Lifecycle

> [!info] All targets must have a DAG (mandatory)
> The DAG is a record, not a driver. Even a single finding / small target should have one — track coverage and chaining possibilities.

Visualizes the complete recon→exploit→submission lifecycle of the "effectiveness-first DAG", connecting the 5 lanes from [[Template - Target Work DAG]]
(Recon / Validation / Decision-Gate / Pentest-Route / Exploit-chain-Bridge) with [[Template - Exploit Chain DAG]]
into a single diagram. **The Decision-Gate lane uses decision diamonds** — the decision-tree functionality has been merged into the DAG (multi-path merge, shared evidence, cross-session accumulation),
so there is no separate decision tree. Skill gates (surface-mapping / exploit-chain 6Q / dedup / submission-readiness) are attached as dashed annotations at the corresponding handoff points.

```mermaid
flowchart TD
    %% ===== Skill gates (annotations) =====
    G_SURF(["gate: bb-surface-mapping<br/>vuln-agnostic surface mapping"]):::gate
    G_6Q(["gate: bb-exploit-chain 6Q<br/>6 questions before chaining"]):::gate
    G_DEDUP(["gate: bb-dedup-finding<br/>root-cause dedup"]):::gate
    G_SUB(["gate: bb-submission-readiness"]):::gate

    %% ===== Lane 1: Recon =====
    subgraph RECON["1 - Recon DAG"]
        direction TB
        R_scope[Program scope]
        R_hosts[host inventory]
        R_svc[unknown service list]
        R_plan[stack-specific test plan]
        R_scope -->|CT / subfinder / ASN| R_hosts
        R_hosts -->|alt-port sweep| R_svc
        R_svc -->|tech fingerprint| R_plan
    end

    %% ===== Lane 2: Validation =====
    subgraph VALID["2 - Validation DAG"]
        direction TB
        V_lr[login redirect candidate]
        V_ore[open redirect evidence]
        V_sm[source map endpoint]
        V_vrl[validation request list]
        V_ssrf[SSRF parameter]
        V_csr[confirmed SSRF]
        V_lr -->|valid account confirms redirect| V_ore
        V_sm -->|extract API route + param| V_vrl
        V_ssrf -->|internal metadata response| V_csr
    end

    %% ===== Lane 3: Decision-Gate (diamonds) =====
    subgraph DECIDE["3 - Decision-Gate DAG (decision tree functionality)"]
        direction TB
        D_stack{"unknown web stack:<br/>fingerprint = WordPress?"}
        D_stack -->|yes| D_wp[WP route]
        D_stack -->|no| D_gen[generic web route]
        D_cand{"candidate meets<br/>repro + impact bar?"}
        D_cand -->|yes| D_find[Finding]
        D_cand -->|no| D_att["Attempt / stop"]
        D_ver{"vendor advisory<br/>covers root cause?"}
        D_ver -->|yes| D_abort[abort-known N-day]
        D_ver -->|no| D_zero[proceed zero-day]
        D_mut{"scope + safety<br/>allow mutation?"}
        D_mut -->|yes| D_vps[VPS verification]
        D_mut -->|no| D_ro[stop at read-only evidence]
    end

    %% ===== Lane 4: Pentest-Route =====
    subgraph PENTEST["4 - Pentest-Route DAG"]
        direction TB
        P_ro[read-only account]
        P_idor[IDOR candidate list]
        P_adm[exposed admin page]
        P_map[authenticated route map]
        P_upl[upload feature]
        P_upx[upload-to-execution decision]
        P_ro -->|enumerate tenant IDs| P_idor
        P_adm -->|401/403 bypass matrix| P_map
        P_upl -->|ext / MIME / transform tests| P_upx
    end

    %% ===== Lane 5: Exploit-chain Bridge =====
    subgraph BRIDGE["5 - Exploit-chain Bridge"]
        direction TB
        B_ep[leaked internal endpoint]
        B_data[other user's data]
        B_ver[leaked version]
        B_nday[known-N-day decision]
        B_ep -->|IDOR| B_data
        B_ver -->|CVE / advisory precheck| B_nday
    end

    %% ===== Exploit Chain DAG (Template - Exploit Chain DAG) =====
    subgraph CHAIN["Exploit Chain DAG (A->B->C)"]
        direction TB
        C_f["F: finding / state"]
        C_d["D: leaked data"]
        C_e{"E: exploit?<br/>IDOR / SSRF / RCE"}
        C_cap[higher capability]
        C_f -->|leak| C_d
        C_d -->|"edge = exploit"| C_e
        C_e -->|chain depth| C_cap
    end

    %% ===== Submission =====
    SUB[["Submission / FORM"]]:::submit

    %% ===== Hand-off edges between lanes =====
    R_plan ==> V_lr
    R_plan ==> V_sm
    V_ore ==> D_cand
    V_csr ==> D_cand
    V_vrl ==> D_stack
    D_wp ==> P_adm
    D_gen ==> P_ro
    D_zero ==> P_upl
    P_idor ==> B_ep
    P_map ==> B_ep
    D_ver -.feeds.-> B_ver
    B_data ==> C_f
    B_nday ==> C_e
    C_cap ==> SUB
    D_find ==> SUB

    %% ===== Gate attach points (dashed) =====
    G_SURF -.pre-gate.-> RECON
    G_6Q -.before chaining.-> BRIDGE
    G_6Q -.before chaining.-> CHAIN
    G_DEDUP -.before Finding.-> D_find
    G_SUB -.before submission.-> SUB

    classDef gate fill:#fff3cd,stroke:#d39e00,color:#663c00,stroke-dasharray:4 3;
    classDef submit fill:#d1e7dd,stroke:#0f5132,color:#0f5132;
```

## Legend

| Shape / Edge | Meaning |
|---|---|
| `[rectangle]` | State / asset / evidence node (lane's `from`/`to`) |
| `{diamond}` | Decision-Gate fork — decision tree's verifiable condition (`edge = decision condition`) |
| `[[double-frame]]` | Terminal: Submission / FORM |
| `([rounded dashed])` | Skill gate annotation (not data flow, attached at handoff point) |
| `==>` thick solid | Hand-off between lanes (evidence / path selection) |
| `-->` thin solid | Intra-lane edge (discovery / criterion / action / exploit) |
| `-.->` dashed | Gate mount point / auxiliary feed |

**Lane mapping**: 1 Recon = surface coverage; 2 Validation = decompose suspicions into falsifiable conditions; 3 Decision-Gate = choose next step (decision tree function, kept in DAG because paths merge/share evidence/accumulate across sessions); 4 Pentest-Route = from access to foothold; 5 Bridge = move chainable findings into formal chain tracking.

## Using with `dag_gaps.sh`

This diagram is the **structure** (which lanes exist, how they connect); each actual target instantiates it as an edge-list table (`| from | edge | to | status |`) in files containing `DAG` in the filename under `01 - Targets/<target>/`. `dag_gaps.sh` reads only the `status` column and extracts remaining **`⏳` edges** — those are the work items you haven't completed in that lane. **`--kind` values map 1:1 to the lanes in this diagram**:

```bash
bash automation/dag_gaps.sh <target> --kind recon       # lane 1 Recon
bash automation/dag_gaps.sh <target> --kind validation  # lane 2 Validation
bash automation/dag_gaps.sh <target> --kind decision    # lane 3 Decision-Gate
bash automation/dag_gaps.sh <target> --kind pentest     # lane 4 Pentest-Route
bash automation/dag_gaps.sh <target> --kind chain       # Exploit Chain DAG
bash automation/dag_gaps.sh <target>                    # --kind all (all files with DAG)
bash automation/dag_gaps.sh <target> --count            # numbers only: use as gate / exit criterion
bash automation/chain_gaps.sh <target>                  # = --kind chain backwards-compat shortcut
```

**Closed-loop usage**:
1. Following [[Template - Target Work DAG]], create edge-list in the target directory (each edge in this diagram = one row, status starts as `⏳`).
2. Resolve each `⏳` into `✅` (confirmed) or `❌` (disproved/abandoned) — **this diagram tells you "which edges exist", `dag_gaps.sh` tells you "which remain undone"**.
3. `dag_gaps.sh <target> --kind <lane> --count` reaches zero = that lane is complete (aligns with `bb-web-vuln-scan` skill's exit criterion "all ⏳ → ✅/❌").
4. Cross-session: HANDOFF carries only the `dag_gaps.sh` `⏳` summary, not the full table; the next session sees at a glance what edges remain, avoiding duplicate work.

> Note: all targets must have a DAG (mandatory). **The DAG only records, it does not drive** — stop-loss and risk decisions are still the operator's judgment, not `dag_gaps.sh` output.

## Source

- [[Template - Target Work DAG]] — 5 lane edge-list (Automation: `automation/dag_gaps.sh`)
- [[Template - Exploit Chain DAG]] — candidate→chain→exploit (A→B→C emergence)
