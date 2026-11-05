#!/usr/bin/env python3
"""capability_view.py — ASG 能力的單一視圖工具（三模式）。

2026-09-23 收斂：本檔取代 capability_posture.sh（權限階梯）＋ asg_derive_chains.py（攻擊鏈衍生），
並吸收 capability_brief.sh 的核心（capability_state + 來源顯示）。三者本是同一件事的不同視圖
（都從 ASG 讀能力），拆成三支是工具增生。使用 asg.read_state：有 ledger 就直接讀 ledger，只有未遷移 target 才讀 legacy YAML。

模式：
  --brief   (預設) capability_state 現況 + 來源 finding（session-start pin）
  --ladder  權限階梯投影（階 0-7；bb-web-foothold）——「我們站到第幾階」
  --chains  從能力 DAG 定點衍生所有可走攻擊鏈（paths 該有的樣子：投影非手寫）
  --dead-ends  列出 ASG 中所有已終止的 paths（dead_end/withdrawn/...）
  --paths   列出所有 paths 的名字和 status 摘要（emoji 分類）

能力來源：ledger capsule 的有效能力；legacy YAML 只在尚未有 ledger 時使用。
起始 seed（--chains）= INIT + capability_state 已確立能力（含假設帳號 = assumed breach）。

用法：python3 automation/capability_view.py <target> [--brief|--ladder|--chains|--dead-ends|--paths] [--unreached]
"""
import os, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path(os.environ.get("VAULT_ROOT") or Path(__file__).resolve().parents[1])
TARGETS = ROOT / "01 - Targets"
INIT = {"P:net=external", "P:auth=anonymous", "P:net=on-path", "P:net=lan-adjacent"}
CAP_RE = re.compile(r'P:[a-z-]+=[A-Za-z0-9_.:,=-]+')

# Status → emoji 正規化（legacy 值映射到 canonical emoji）
_STATUS_EMOJI = {
    # ✅ live-verified 群組
    "live-verified": "✅", "asan-verified": "✅", "validated": "✅", "proven": "✅",
    # 🔬 code-confirmed 群組
    "code-confirmed": "🔬", "source-confirmed": "🔬", "build-verified": "🔬",
    # ❌ dead_end 群組
    "dead_end": "❌", "withdrawn": "❌", "endpoint_unreachable": "❌", "scope_exhausted": "❌",
    # ❓ hypothesis 群組
    "hypothesis": "❓", "pending": "❓", "confirmed": "✅",
    "blocked": "⛔", "disputed": "⚖️", "needs_evidence": "📎",
    # ⚠️ partial 群組
    "partial": "⚠️", "downgraded": "⚠️", "not_applicable": "⚠️",
    "platform_not_applicable": "⚠️",
    # 🔧 fixed_upstream
    "fixed_upstream": "🔧",
}
_DEAD_STATUSES = {"dead_end", "withdrawn", "endpoint_unreachable", "scope_exhausted", "downgraded"}


def _emoji(status: str) -> str:
    return _STATUS_EMOJI.get(status, "·")


# 權限階梯（對映 bb-web-foothold）：(階, 名稱, regex)
RUNGS = [
    (0, "外部可見",   r'P:net=|P:auth=anonymous'),
    (1, "識別資訊",   r'P:data=|P:access=|P:read=|P:source=|P:enum='),
    (2, "憑證材料",   r'P:cred=|P:token=|P:key=|P:secret=|P:apim-token='),
    (3, "已認證存取", r'P:auth=[a-z0-9-]+-authenticated|P:session='),
    (4, "跨身分提權", r'P:auth=victim|P:auth=[a-z0-9-]*admin|P:role=|P:impersonate='),
    (5, "執行權",     r'P:exec=|P:compute=|P:rce=|P:js-exec=|P:file-write=|P:file-delete='),
    (6, "內網可達",   r'P:net=internal|P:pivot=|P:metadata=|P:reach='),
    (7, "達成目標",   r'P:objective=|P:cj='),
]


def load(md: Path):
    from asg import read_state
    state = read_state(md.parent)
    cs = [(str(c["cap"]), str(c.get("source", "initial")), c.get("state", "confirmed"))
          for c in state["capability_state"] if isinstance(c, dict) and c.get("cap")]
    # A migrated target never unions stale Markdown or declared Finding provides.
    findings = [dict(f) for f in state["findings"] if isinstance(f, dict) and f.get("id")]
    return cs, [], findings, state["paths"], state["recon_dimensions"]


def all_caps(cs, cg, findings):
    caps = {c for c, _, state in cs if state == "confirmed"} | set(cg)
    for f in findings:
        if f.get("status") not in ("withdrawn", "dead_end", "hypothesis", "tested", "disputed"):
            caps |= set(f.get("provides") or [])
    return caps


def mode_brief(cs, cg, findings, paths, rdims, focus=None):
    print("## 📌 Capability State + 來源")
    seen = set()
    for cap, src, state in cs:
        if focus and focus not in cap:
            continue
        tag = "" if state == "confirmed" else f"  [{state}]"
        print(f"  {cap:42s} (from: {src}){tag}")
        seen.add(cap)
    extra = [c for c in cg if c not in seen]
    if extra:
        print("  — 另有 ledger 投影（### Capabilities CG）獨有：")
        for c in sorted(extra):
            print(f"  {c}")
    # dead-end 計數 + pending recon_dimensions 計數
    dead_count = sum(1 for p in paths if p.get("status", "") in _DEAD_STATUSES)
    pending_rdims = sum(1 for d in rdims if d.get("status", "") in ("pending", "partial"))
    if paths:
        print(f"\n  ❌ Dead ends: {dead_count}/{len(paths)} paths")
    if rdims:
        print(f"  ❓ Pending recon dimensions: {pending_rdims}/{len(rdims)}")


def mode_dead_ends(paths):
    dead = [p for p in paths if p.get("status", "") in _DEAD_STATUSES]
    print(f"## ❌ Dead Ends (不再追蹤)  [{len(dead)}/{len(paths)}]")
    if not dead:
        print("  (無)")
        return
    for p in dead:
        name = p["name"]
        status = p.get("status", "unknown")
        print(f"  {name:50s} [{status}]")


def mode_paths(paths):
    print(f"## 🛤 Paths Summary  [{len(paths)} total]")
    if not paths:
        print("  (無 paths)")
        return
    for p in paths:
        name = p["name"]
        status = p.get("status", "unknown")
        emoji = _emoji(status)
        print(f"  {emoji} {name:50s} [{status}]")
    # 統計
    counts: dict[str, int] = {}
    for p in paths:
        e = _emoji(p.get("status", "unknown"))
        counts[e] = counts.get(e, 0) + 1
    parts = []
    for e, label in [("✅", "verified"), ("🔬", "confirmed"), ("❌", "dead"),
                     ("❓", "hypothesis"), ("⚠️", "partial/downgraded"), ("🔧", "fixed")]:
        if counts.get(e):
            parts.append(f"{e} {counts[e]} {label}")
    if parts:
        print(f"\n  統計: {' | '.join(parts)}")


def mode_ladder(cs, cg, findings):
    caps = all_caps(cs, cg, findings)
    nprov = sum(1 for f in findings if f.get("provides"))
    print(f"  Findings {len(findings)}｜有 provides {nprov}｜cap {len(caps)}\n")
    top = None
    for n, name, pat in RUNGS:
        hit = sorted(c for c in caps if re.search(pat, c))
        if hit:
            print(f"  階 {n}  {name:10s} ✅  {' '.join(hit)}")
            top = (n, name)
        else:
            print(f"  階 {n}  {name:10s} ·")
    if top:
        n, name = top
        hint = {2: "最短路徑是憑證重用（VPN/SSO/郵件），優先於繼續挖",
                5: "已達執行權 —— 直接評估階 6（內網可達）",
                6: "停止 web 層列舉，轉 offensive-active-directory / offensive-cloud"}.get(n, "")
        print(f"\n  🔺 最高階：階 {n} {name}" + (f" —— {hint}" if hint else ""))


def mode_chains(cs, cg, findings, show_unreached):
    pending_proof = [f for f in findings if f.get("capability_status", f.get("status")) not in
                     {"confirmed", "validated", "live-verified", "code-confirmed", "proven"}]
    findings = [f for f in findings if f not in pending_proof]
    print(f"  待確認／失效 finding：{len(pending_proof)}（不算已取得能力）")
    seed = [c for c, _, state in cs if state == "confirmed"]
    avail = set(INIT) | set(seed)
    prov = {f["id"]: list(f.get("provides") or []) for f in findings}
    req = {f["id"]: list(f.get("requires") or []) for f in findings}
    pending = {f["id"] for f in findings}
    order = []
    changed = True
    while changed:
        changed = False
        for fid in sorted(pending):
            if all(r in avail for r in req[fid]):
                nc = [c for c in prov[fid] if c not in avail]
                avail.update(prov[fid]); order.append((fid, nc, list(req[fid])))
                pending.discard(fid); changed = True
    chained = [(f, nc, rq) for f, nc, rq in order if any(r not in INIT for r in rq)]
    entry = [f for f, nc, rq in order if all(r in INIT for r in rq)]
    print(f"  入口點（requires 僅初始能力）：{len(entry)}")
    print(f"  衍生攻擊鏈（透過上游能力解鎖）：{len(chained)}")
    for fid, nc, rq in chained:
        up = [r for r in rq if r not in INIT]
        print(f"     {fid}  ← 需 {up}  → 解鎖 {nc or '(終端)'}")
    unreach = [(f, [r for r in req[f] if r not in avail]) for f in sorted(pending)]
    if unreach:
        print(f"  ⚠ 不可走 finding：{len(unreach)}（requires 有一項無人 provide＝缺上游/前沿）")
        if show_unreached:
            for fid, miss in unreach:
                print(f"     {fid}  缺 {miss}")
    elif findings:
        print("  ✅ 已確認 finding 的前提可滿足")
    else:
        print("  尚無有效 confirmed finding；不宣稱可組裝攻擊鏈")


def to_json(target, cs, cg, findings, paths, rdims):
    """Machine-readable projection for downstream tooling (contract: capability_view
    --json is the ladder/chain source). Read-only: derived from the ASG projection."""
    import re as _re
    caps = sorted(all_caps(cs, cg, findings))
    ladder = []
    for tier, label, rx in RUNGS:
        reached = sorted(c for c in caps if _re.search(rx, c))
        ladder.append({"tier": tier, "label": label, "reached": reached, "count": len(reached)})
    highest = max((t["tier"] for t in ladder if t["reached"]), default=-1)
    TERMINAL = {"dead_end", "fixed_upstream", "not_applicable", "live-verified",
                "code-confirmed", "withdrawn", "downgraded", "confirmed"}
    chains = [{"name": p.get("name"), "status": p.get("status", ""),
               "findings": p.get("findings") or []} for p in paths]
    blocked = sum(1 for c in chains if str(c["status"]).lower() not in TERMINAL)
    missing = [f.get("id") for f in findings if not (f.get("provides") or f.get("requires"))]
    return {
        "target": target,
        "capabilities": caps,
        "capability_state": [{"cap": c, "source": s, "state": st} for c, s, st in cs],
        "ladder": ladder,
        "highest_rung": highest,
        "chains": chains,
        "unlocked": len(chains) - blocked,
        "blocked": blocked,
        "findings": [{"id": f.get("id"), "status": f.get("status", ""),
                      "capability_status": f.get("capability_status", f.get("status", "")),
                      "provides": f.get("provides") or [], "requires": f.get("requires") or [],
                      "poc_ref": f.get("poc_ref") or ""}
                     for f in findings],
        # reuse index: capability → the PoC that achieves it (join provides × poc_ref).
        # Consult this before researching/writing a PoC — don't re-derive what exists.
        "reuse": sorted({(cap, f["poc_ref"]) for f in findings if f.get("poc_ref")
                         for cap in (f.get("provides") or [])} |
                        {("(finding)" + f["id"], f["poc_ref"]) for f in findings
                         if f.get("poc_ref") and not (f.get("provides"))}),
        "missing_capabilities": missing,
        "recon_dimensions": [{"dim": d.get("dim"), "status": d.get("status", "")} for d in rdims],
    }


def main():
    args = sys.argv[1:]
    mode = "brief"; show_unreached = False; target = None; focus = None
    for a in args:
        if a in ("--brief", "--ladder", "--chains"): mode = a[2:]
        elif a == "--json": mode = "json"
        elif a == "--dead-ends": mode = "dead-ends"
        elif a == "--paths": mode = "paths"
        elif a == "--unreached": show_unreached = True
        elif a == "--focus": focus = "__NEXT__"
        elif focus == "__NEXT__": focus = a
        else: target = a
    if not target:
        sys.exit("用法：python3 automation/capability_view.py <target> [--brief|--ladder|--chains|--dead-ends|--paths] [--unreached]")
    md = None
    for tdir in TARGETS.iterdir():
        if tdir.is_dir() and tdir.name == target:
            cand = tdir / f"Attack Surface Graph - {target}.md"
            if cand.exists() or (tdir / ".state/asg-events.jsonl").exists(): md = cand
            break
    if not md:
        sys.exit(f"⚠ 找不到 {target} 的 ASG（先跑 bb-surface-mapping）")
    cs, cg, findings, paths, rdims = load(md)
    if mode == "json":
        import json as _json
        print(_json.dumps(to_json(target, cs, cg, findings, paths, rdims), ensure_ascii=False, indent=1))
        return
    title = {"brief": "Capability Brief", "ladder": "權限態勢", "chains": "攻擊鏈衍生",
             "dead-ends": "Dead Ends", "paths": "Paths Summary"}[mode]
    print("=" * 60)
    print(f"  {title} — {target}")
    print("=" * 60)
    if mode == "brief":
        mode_brief(cs, cg, findings, paths, rdims,
                   focus if focus not in (None, "__NEXT__") else None)
    elif mode == "ladder": mode_ladder(cs, cg, findings)
    elif mode == "chains": mode_chains(cs, cg, findings, show_unreached)
    elif mode == "dead-ends": mode_dead_ends(paths)
    elif mode == "paths": mode_paths(paths)
    print("=" * 60)


if __name__ == "__main__":
    main()
