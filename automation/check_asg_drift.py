#!/usr/bin/env python3
"""Check current ledger links and projection freshness, never stale YAML membership.
Legacy YAML remains readable when no ledger exists; migration is opt-in.
"""
from pathlib import Path
import argparse
import json
import sys
import asg
from asg_checks import finding_docs
from ledger_reader import LedgerReadError


def drift(target):
    state = asg.read_state(target)
    ids = {f["id"] for f in state["findings"] if f.get("id")}
    node_ids = {str(n.get(k)) for n in state["nodes"] if isinstance(n, dict)
                for k in ("id", "name", "identifier", "label") if n.get(k)}
    dangling = sorted({str(n) for f in state["findings"] for n in f.get("resolves") or [] if str(n) not in node_ids})
    stale = []
    if state["source"] == "ledger":
        md = asg.markdown_path(target)
        text = md.read_text(encoding="utf-8") if md.exists() else ""
        generated = asg._render_generated(target, state=state)
        start, end = text.find(asg.GEN_START), text.find(asg.GEN_END)
        actual = text[start+len(asg.GEN_START):end].strip() if start >= 0 and end > start else None
        if actual != generated.strip():
            stale.append("Markdown generated block")
        snapshot = asg.snapshot_path(target)
        try:
            data = json.loads(snapshot.read_text(encoding="utf-8")) if snapshot.exists() else {}
        except (ValueError, OSError):
            data = {}
        if data.get("event_cursor") != state["event_cursor"] or data.get("capabilities") != state["capsule"]["capabilities"]:
            stale.append("JSON snapshot")
    return {"source": state["source"], "event_cursor": state["event_cursor"],
            "counts": {"nodes": len(state["nodes"]), "findings": len(ids), "caps": len(state["capability_state"]), "events": state["event_cursor"]},
            "missing_nodes": dangling, "missing_findings": sorted(set(finding_docs(target)) - ids),
            "missing_caps": [], "orphan_surfaces": [], "orphan_closed": [],
            # 分開報，因為這兩類要做的事完全不同（2026-10-10）：
            #   _real      某個 CONFIRMED 判決引用的 artifact 解析不到 → capability 不授予
            #              → chain 算不出來。這是要修的。
            #   _migrated  evidence 是遷移工具填的 "migrated:initial" 佔位符，本來就不是
            #              路徑，永遠解析不到。修不動，也不該讓 drift 永遠紅。
            # 混在一起報的後果：全域 126 筆看不出哪 64 筆可行動，於是一筆都沒人動。
            **_split_rejected(sorted(state["capsule"]["evidence_rejected"])),
            "stale_projections": stale}


def _split_rejected(rejected):
    migrated = [h for h in rejected if str(h).startswith("migrated:")]
    real = [h for h in rejected if not str(h).startswith("migrated:")]
    return {"evidence_rejected": rejected,          # 保留原 key 供既有讀取方
            "evidence_rejected_real": real,
            "evidence_rejected_migrated": migrated}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    root = asg.vault_root() / asg.TARGETS_DIRNAME
    targets = [args.target] if args.target else sorted(p.name for p in root.iterdir() if p.is_dir() and
              ((p / ".state/asg-events.jsonl").exists() or (p / f"Attack Surface Graph - {p.name}.md").exists()))
    results, errors = {}, {}
    for target in targets:
        try:
            results[target] = drift(target)
        except (LedgerReadError, ValueError, OSError) as exc:
            errors[target] = str(exc)
    if args.json:
        print(json.dumps({"reports": results, "errors": errors}, ensure_ascii=False, indent=2))
    else:
        for target, report in results.items():
            print(f"{target} — source={report['source']} events={report['event_cursor']} findings={report['counts']['findings']}")
            for key, label in [("missing_nodes", "不存在的 surface reference"), ("missing_findings", "文件未入帳"),
                               ("evidence_rejected_real", "宣稱 confirmed 但證據指不到（要修）"),
                               ("evidence_rejected_migrated", "遷移佔位符 migrated:initial（非真失效，不列入 drift）"),
                               ("stale_projections", "過期投影（asg.py project 更新）")]:
                # 每項截到 70 字：TP-Link 有 12 個 hypothesis 的「名字」是整段分析敘述
                # （數百字的 BSS 佈局推導、PSIRT 撤回理由…），原樣印出來會把整份報告
                # 洗掉，其他 target 的問題就看不見了。完整內容用 --json 取。
                items = [s if len(s) <= 70 else s[:70] + "…" for s in report[key][:12]]
                print(f"  {label}: {len(report[key])}" + (f" — {', '.join(items)}" if items else ""))
        for target, message in errors.items():
            print(f"ERROR {target}: {message}", file=sys.stderr)
    # 遷移佔位符不列入 drift：它修不動，留著只會讓這支永遠非 0，
    # 而一個永遠紅的檢查等於沒有檢查。
    return 2 if errors else int(any(r[k] for r in results.values() for k in
                                   ("missing_nodes", "missing_findings",
                                    "evidence_rejected_real", "stale_projections")))


if __name__ == "__main__":
    raise SystemExit(main())
