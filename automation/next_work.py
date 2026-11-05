#!/usr/bin/env python3
"""next_work.py — write <target>/next_work.json: the top 1–3 next actions, projected
from the ledger/ASG. hunt_run and downstream readers READ this; nobody hand-writes next_work.

It is a PROJECTION (read-only derivation), never a writable to-do source — that would be
the fifth next_work the UX contract forbids. Priority:
  1. CORE recon floor still pending (can't exploit before recon is done)
  2. an unlock-ready chain (a path with findings that isn't terminal yet)
  3. an untested high-value surface
  4. recommended recon dimensions

Usage: next_work.py <target>   (writes 01 - Targets/<target>/next_work.json, prints it)
Called by asg.py project so the projection refreshes with the rest.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import recon_dimensions_lib as rdl  # noqa: E402
from ledger_reader import LedgerReadError

VAULT = Path(os.environ.get("VAULT_ROOT") or Path(__file__).resolve().parents[1])
TARGETS = VAULT / "01 - Targets"      # override hook (tests may monkeypatch this)
_DEFAULT_TARGETS = TARGETS


def _targets() -> Path:
    """Targets root. If TARGETS was overridden, honour it; otherwise stay aligned
    with asg.vault_root() so a single source of truth drives both modules under
    test and at runtime."""
    if TARGETS != _DEFAULT_TARGETS:
        return TARGETS
    import asg
    return asg.vault_root() / "01 - Targets"


def _redact_label(name) -> str:
    """Mask sensitive terms in a surface label before it goes into next_work.json / chat.
    The ledger keeps the full label (a human reads the file); the projection shown to the
    session is redacted so a leaky label (JWT/CVE/api-key…) doesn't inject exploit detail
    into context and sensitize the safety classifier. Single source of the pattern:
    check_leaky_labels.LEAK."""
    try:
        import check_leaky_labels as cll
        return cll.LEAK.sub("[·]", str(name))
    except LedgerReadError:
        raise
    except Exception:
        return str(name)


def _asg_md(target: str):
    tdir = _targets() / target
    for p in sorted(tdir.glob("Attack Surface Graph*.md")):
        try:
            t = p.read_text(encoding="utf-8")
        except OSError:
            continue
        if "generated_from: .state/asg-events.jsonl" in t[:1000]:
            continue
        return p, t
    return None, ""


def compute(target: str) -> dict:
    items = []
    import asg
    state = asg.read_state(_targets() / target)
    g = state
    rd = state["recon_dimensions"]
    paths = [p for p in state["paths"] if isinstance(p, dict) and p.get("name")]
    research = state.get("research", {})
    rsummary = research.get("summary", {})
    rnodes = {n["ref"]: n for n in research.get("nodes", [])}
    for ref in rsummary.get("running_intents", []):
        items.append({"kind": "research-resume", "ref": ref, "action": f"接續研究工作：{_redact_label(rnodes[ref]['text'])}",
                      "detail": "工作已領取；先查進度與已有輸出，避免重複執行", "priority": 0})
    for ref in sorted(rsummary.get("ready_intents", []), key=lambda r: (-rnodes[r].get("priority", 5), r)):
        node = rnodes[ref]
        items.append({"kind": "research-intent", "ref": ref, "action": f"推進意圖：{_redact_label(node['text'])}",
                      "detail": f"goals={node.get('goals', [])}; parents={node.get('parents', [])}; hypothesis={node.get('hypothesis', '')}",
                      "priority": 1})
    if not rsummary.get("ready_intents") and not rsummary.get("running_intents"):
        for ref in rsummary.get("open_goals", []):
            items.append({"kind": "goal-review", "ref": ref, "action": f"補齊目標驗收：{_redact_label(rnodes[ref]['text'])}",
                          "detail": "依驗收條件補研究／證據；沒有待辦不代表目標達成", "priority": 2})

    # profile-aware: recon floor only applies to web-facing shapes (web/apk).
    osint_applies = True
    try:
        import genesis_lib
        osint_applies = genesis_lib.normalize_genesis(state["genesis"]).get("osint_applies", True)
    except LedgerReadError:
        raise
    except Exception:
        pass

    # 1. CORE recon floor pending (web/apk only)
    if osint_applies:
        for dim, st in rdl.floor_pending(rd, rdl.CORE):
            items.append({"kind": "recon-floor", "action": f"完成 recon floor：{dim}",
                          "detail": f"status={st or 'untested'}", "skill": rdl.SKILL_MAP.get(dim, ""),
                          "priority": 1})

    # 1b. in-scope hosts that have never become a surface. Ranked above individual
    # untested surfaces on purpose: a host with no surfaces is not "tested and clean",
    # it is upstream of the surface list entirely, and nothing below can surface it.
    # The ledger cannot propose work for assets it was never told about, so without
    # this the worklist looks complete while whole hosts sit outside it (某 target:
    # 96 recorded surfaces read as the full attack surface while 29 in-scope hosts had
    # none at all; mining six of them produced 7,700+ endpoints).
    try:
        import scope_coverage
        sc = scope_coverage.gap(target)
        if sc.get("applicable") and sc.get("untouched_hosts"):
            untouched = sc["untouched_hosts"]
            for h in untouched[:10]:
                items.append({"kind": "scope-host",
                              "action": f"測繪未觸碰的 in-scope host：{h}",
                              "detail": f"scope 內 {sc['scope_hosts']} 個 host，"
                                        f"{len(untouched)} 個還沒有任何攻擊面",
                              "skill": "bb-surface-mapping", "priority": 2})
            if len(untouched) > 10:
                items.append({"kind": "scope-host",
                              "action": f"另有 {len(untouched) - 10} 個 in-scope host 未觸碰",
                              "detail": "python3 automation/scope_coverage.py "
                                        f"{sc['target']} --limit 0",
                              "skill": "bb-surface-mapping", "priority": 2})
    except LedgerReadError:
        raise
    except Exception:
        pass

    # 2. unlock-ready chains: a path with findings that is not terminal
    TERMINAL = {"dead_end", "fixed_upstream", "not_applicable", "live-verified",
                "code-confirmed", "withdrawn", "downgraded", "confirmed"}
    for p in paths:
        st = str(p.get("status", "")).lower()
        if st not in TERMINAL and (p.get("findings")):
            items.append({"kind": "chain", "action": f"推進攻擊鏈：{p.get('name')}",
                          "detail": f"status={st or 'hypothesis'}", "skill": "bb-exploit-chain",
                          "priority": 2})
        elif state["source"] == "ledger" and st not in TERMINAL:
            action = {"needs_evidence": "補齊可解析證據", "disputed": "釐清互相矛盾的證據",
                      "blocked": "解除前置條件"}.get(st, "推進假設")
            items.append({"kind": "hypothesis", "action": f"{action}：{p['name']}",
                          "detail": f"status={st}", "skill": "bb-evidence-readiness" if st in
                          ("needs_evidence", "disputed") else "bb-exploit-chain", "priority": 2})

    # 2.5 human-go queue: write/service-impact actions the auto loop deferred. These are
    # the "队列给人" — a human authorizes (or declines) them; surfacing here is what makes
    # downstream readers's morning dashboard show the pending-authorization work, not just findings.
    try:
        import asg
        for q in asg.needs_human_go_queue(target):
            items.append({"kind": "human-go",
                          "action": f"授權待決（{q['risk']}）：{q['action']}",
                          "detail": f"hyp={q['hyp_id']} surface={q.get('surface') or '—'}；只讀環已跑完這條，等你放行/駁回",
                          "skill": "bb-scope-safety-check", "priority": 2})
    except LedgerReadError:
        raise
    except Exception:
        pass

    # 2b. capability lateral sweep —— 拿到新能力時，先橫向掃完同信任邊界的未測面，
    # 再去下一個新主機。
    #
    # 為什麼排在未測面（priority 3）之前：某 target 最值錢的那條鏈是
    # 公開設定檔 → app token → 偽造簽章 → 認證後的大量資料端點，全部發生在**同一個
    # 信任邊界內**。而當時的派工把「下一個未測面」與「下一個未測主機」混在同一層，
    # 於是拿到 token 之後常常跑去掃新的子網域，token 能解鎖的既有端點反而擱著。
    # 一個新能力會讓一整排既有的面從「進不去」變成「進得去」，那是最高報酬的一步。
    try:
        import asg as _asg
        caps = {c["cap"]: c.get("source", "?") for c in state["capability_state"]
                if isinstance(c, dict) and c.get("state", "confirmed") == "confirmed"}
        if caps:
            st_map = _asg.surface_state(target)
            # 「端點型」的面才吃得到能力；只知道存在的主機名要先測繪，那是另一回事
            endpointish = [n for n, v in st_map.items()
                           if v == "untested" and ("/" in n or n.lower().startswith(("get ", "post ")))]
            if endpointish:
                cap_list = "、".join(sorted(caps)[:3]) + ("…" if len(caps) > 3 else "")
                items.append({
                    "kind": "capability-sweep",
                    "action": f"用既有能力橫向掃未測端點（{len(endpointish)} 個）",
                    "detail": (f"已持有：{cap_list}（來自 {', '.join(sorted(set(caps.values()))[:3])}）。"
                               "先把這些面用現有憑證重跑一輪，再去下一個新主機——"
                               "一個新能力會讓一整排面從進不去變成進得去。"),
                    "skill": "bb-exploit-chain", "priority": 2})
    except LedgerReadError:
        raise
    except Exception:
        pass

    # 2c. exact unlocks —— 被擋的面（add-surface --blocked-by <cap>）等的能力現在已持有。
    # 比 2b 的「橫向掃」更準：不是猜哪些端點吃得到能力，而是面自己宣告了缺什麼。
    # 排在最前面（priority 1、rank 最小）：這是已知的門，鑰匙已在手上。
    try:
        import asg as _asg
        for surf, needed in sorted(_asg.surfaces_unlockable(target, state=state).items()):
            items.append({
                "kind": "capability-unlock",
                "action": f"重測被擋的面：{_redact_label(surf)}",
                "detail": f"它等待的能力 {', '.join(needed)} 已持有；用同一能力重跑，結果寫回 ledger。",
                "skill": "bb-exploit-chain", "priority": 1})
    except LedgerReadError:
        raise
    except Exception:
        pass

    # 3. untested surfaces (from ledger surface_state). A surface whose label matches a
    # technique pack gets that pack's SPECIFIC skill + its first must-test as the hint —
    # this is the 「面→技法→能力→下一跳」wiring (retriever), so the item points at the
    # dangerous-op procedure instead of a generic "go map it". Non-matching (e.g. firmware
    # code-sink) surfaces keep bb-surface-mapping — no false web-pack injection.
    try:
        import asg
        import technique_pack as tp
        packs = tp.load_packs()
        st_map = asg.surface_state(target)
        for name, s in list(st_map.items()):
            if s != "untested":
                continue
            best = tp.retrieve(name, packs)          # match on the REAL label
            shown = _redact_label(name)              # but emit a redacted one (context hygiene)
            if best:
                hint = best["must_test"][0] if best["must_test"] else best["summary"][:80]
                items.append({"kind": "surface", "action": f"測未測面：{shown}",
                              "detail": f"技法包 {best['skill']}：{hint}",
                              "skill": best["skill"], "priority": 3})
            else:
                items.append({"kind": "surface", "action": f"測未測面：{shown}",
                              "detail": "untested", "skill": "bb-surface-mapping", "priority": 3})
    except LedgerReadError:
        raise
    except Exception:
        pass

    # 4. recommended recon dims (web/apk only)
    core = set(rdl.CORE)
    for dim, st in (rdl.floor_pending(rd) if osint_applies else []):
        if dim not in core:
            items.append({"kind": "recon-recommended", "action": f"建議補 recon：{dim}",
                          "detail": f"status={st or 'untested'}", "skill": rdl.SKILL_MAP.get(dim, ""),
                          "priority": 4})

    # 同一個 priority 內的次序也要講清楚，不能靠插入順序：
    # capability-sweep 必須排在 scope-host 之前——「用現有憑證把既有的面重跑一輪」
    # 的報酬高於「再去測繪一個只知道存在的新主機」。某 target 最值錢的那條鏈全部發生在
    # 同一個信任邊界內，而當時兩者混在同一層，於是拿到 token 之後常跑去掃新子網域。
    KIND_RANK = {"capability-unlock": -1, "research-intent": 0, "capability-sweep": 0, "scope-host": 1}
    items.sort(key=lambda x: (x["priority"], KIND_RANK.get(x["kind"], 5)))
    return {"target": target, "generated_from": state["source"],
            "event_cursor": state["event_cursor"],
            "note": "projection only — do NOT hand-edit; hunt_run/downstream readers read this",
            "next_work": items[:3], "items": items[:3], "total_candidates": len(items)}


def write_human_go(target: str) -> Path:
    """Write <target>/needs_human_go.json — the FULL human-authorization queue (uncapped),
    so downstream readers can render one Accept/Decline row per deferred write action. next_work.json only
    carries the top few mixed items; this file is the dedicated queue the buttons act on."""
    out = _targets() / target / "needs_human_go.json"
    queue = []
    try:
        import asg
        queue = asg.needs_human_go_queue(target)
    except LedgerReadError:
        raise
    except Exception:
        pass
    data = {"target": target, "generated_from": ".state/asg-events.jsonl (needs_human_go events)",
            "note": "projection only — Accept/Decline via bb_authorize.py, never hand-edit",
            "queue": queue, "count": len(queue)}
    try:
        out.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    except OSError:
        pass
    return out


def write(target: str) -> Path:
    data = compute(target)
    out = _targets() / target / "next_work.json"
    try:
        out.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    except OSError:
        pass
    write_human_go(target)
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    target = sys.argv[1]
    if not (_targets() / target).is_dir():
        print(f"⚠ no target dir: {target}", file=sys.stderr)
        return 2
    data = compute(target)
    write(target)
    print(json.dumps(data, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
