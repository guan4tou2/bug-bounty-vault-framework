#!/usr/bin/env python3
"""scope_coverage.py — in-scope hosts that have never become attack surface.

Why this exists (2026-10-01):
    A hunt declared "unauth 挖完了" after testing every surface the ledger knew
    about. The ledger knew about 96. The program's scope listed 51 domains, of
    which 19 had ever appeared as a surface. Mining the bundles of six of the
    untouched hosts produced 7,700+ endpoints and two high-value leads (ISV
    credential search/export, invoice PII) that had been sitting in the gap.

    Nothing was broken in the usual sense. Every coverage number in the system was
    computed against a denominator the system had chosen for itself: coverage is
    `settled / recorded surfaces`, and recon dimensions are a per-target boolean
    that reads `done` after one host out of fifty-three. Test everything you wrote
    down and you reach 100%, which then reads as "finished".

    A bug-bounty program hands us the one denominator we do not get to choose: the
    scope. This compares it against the surfaces the ledger actually holds. An
    in-scope host with zero surfaces has not been partially covered — it has not
    been started, and no amount of depth on the other hosts changes that.

Lineage: this restores what the retired Target Work DAG's "Recon DAG" section did
    (`discovery method × surface` rows carrying ⏳, surfaced each session by
    `dag_gaps.sh`). That was retired in 2026-09 on the measurement "全 vault
    `to == 另一列 from` = 0 → 平表不是圖" — true, but the value was never the
    graph. It was the pending-work inventory, and a flat table is the right shape
    for one. See [[Decision - ASG-CGT-DAG Consolidation 2026-09-28]] §8.1.

Reads only. Prints a report; `--json` for consumers.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import asg  # noqa: E402

# A hostname inside scope prose. Deliberately conservative: at least two labels and
# a TLD of 2+ alpha chars, so version strings and file names do not become "hosts".
_HOST = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", re.I)

# Sections after which domains are no longer in scope. Matched on the heading text.
_STOP_HEADINGS = re.compile(
    r"^#{1,6}\s*.*(out[- ]of[- ]scope|\boos\b|removed from|不在範圍|排除|禁止)", re.I)
# The section a scope file may provide explicitly for tooling.
_FLAT_HEADING = re.compile(r"^#{1,6}\s*.*flat domain list", re.I)
_INSCOPE_HEADING = re.compile(r"^#{1,6}\s*.*(in[- ]scope|scope assets)", re.I)

_NOISE = {"example.com", "example.org", "github.com", "nvd.nist.gov"}


def scope_path(target: str | Path) -> Path:
    return asg.target_dir(target) / "SCOPE.md"


def scope_hosts(target: str | Path) -> list[str]:
    """In-scope hostnames, newest-first precedence: an explicit flat list wins.

    Parsing stops at an out-of-scope / removed heading, so a host the program
    forbids can never be proposed as unfinished work.
    """
    p = scope_path(target)
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()

    flat: list[str] = []
    collecting = in_fence = False
    for ln in lines:
        if _STOP_HEADINGS.match(ln):
            break
        if _FLAT_HEADING.match(ln):
            collecting, in_fence = True, False
            continue
        if collecting and ln.strip().startswith("```"):
            if in_fence:
                break            # end of the fenced flat list
            in_fence = True
            continue
        if collecting and in_fence:
            m = _HOST.search(ln)
            if m:
                flat.append(m.group(1).lower())
    if flat:
        return sorted(set(flat) - _NOISE)

    # Fallback: harvest hostnames from the in-scope section's tables/bullets.
    out: list[str] = []
    active = False
    for ln in lines:
        if _STOP_HEADINGS.match(ln):
            break
        if ln.startswith("#"):
            active = bool(_INSCOPE_HEADING.match(ln)) or active and not ln.startswith("## ")
        if active:
            out.extend(m.lower() for m in _HOST.findall(ln))
    return sorted(set(out) - _NOISE)


def surfaced_hosts(target: str | Path, hosts: list[str]) -> dict:
    """host -> how many ledger surfaces mention it.

    Substring match on the surface label, because labels are free-form codenames
    (`host:isv.example.com (apex)`, `ep-isv-credential-search`). Over-counting is
    the safe direction: it can only shrink the reported gap, never invent one.
    """
    labels = list(asg.surface_state(target).keys())
    joined = [l.lower() for l in labels]
    return {h: sum(1 for l in joined if h in l) for h in hosts}


def gap(target: str | Path) -> dict:
    """Scope-vs-surface gap, plus whether the comparison means anything here.

    `applicable` is the important field. The comparison only carries information
    when this target's surfaces are host-scoped, and three populations are not:
    targets with no ledger yet (nothing to compare against), desktop/firmware
    targets whose surfaces are named `preload-bridge` / `ipc-handlers-main`, and
    targets whose labels follow some other convention. Reporting 0% for those
    would be a gate firing where it has no meaning — noise that teaches people to
    ignore it, which is worse than having no gate at all.
    """
    hosts = scope_hosts(target)
    try:
        surfaces = asg.surface_state(target)
    except Exception:
        surfaces = {}
    counts = surfaced_hosts(target, hosts) if hosts else {}
    untouched = sorted(h for h, n in counts.items() if n == 0)
    matched = len(hosts) - len(untouched)

    if not hosts:
        applicable, reason = False, "SCOPE.md 沒有可解析的域名清單"
    elif not surfaces:
        applicable, reason = False, "此 target 還沒有 ledger surface 事件（尚未遷移/尚未開始）"
    elif matched == 0:
        applicable, reason = False, (
            "有 surface 但沒有一個 label 提到 scope 域名 —— 此 target 的攻擊面不是 host 導向"
            "（桌面/韌體），或 label 慣例不同。本檢查不適用，不代表未覆蓋")
    else:
        applicable, reason = True, ""

    return {
        "target": asg._basename(target),
        "scope_file": str(scope_path(target)),
        "applicable": applicable,
        "not_applicable_reason": reason,
        "scope_hosts": len(hosts),
        "surfaces_total": len(surfaces),
        "hosts_with_surface": matched,
        "untouched_hosts": untouched if applicable else [],
        "coverage": round(matched / len(hosts), 3) if hosts else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="in-scope hosts with no attack surface yet")
    ap.add_argument("target")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=20, help="hosts to list (0 = all)")
    a = ap.parse_args()

    try:
        g = gap(a.target)
    except ValueError as e:
        print(f"[error] {e}", file=sys.stderr)
        return 2

    if a.json:
        print(json.dumps(g, ensure_ascii=False, indent=2))
        return 0

    if not g["applicable"]:
        print(f"{g['target']}: 本檢查不適用 —— {g['not_applicable_reason']}。")
        return 0

    n = len(g["untouched_hosts"])
    print(f"=== {g['target']} scope 覆蓋 ===")
    print(f"  scope 內 host:        {g['scope_hosts']}")
    print(f"  已有 surface 的 host: {g['hosts_with_surface']}  ({g['coverage']:.0%})")
    print(f"  從未成為攻擊面:       {n}")
    if n:
        show = g["untouched_hosts"] if a.limit == 0 else g["untouched_hosts"][:a.limit]
        print("\n  未觸碰（這些不是「測過但沒洞」，是連一個面都還沒記）：")
        for h in show:
            print(f"    - {h}")
        if len(show) < n:
            print(f"    … 另外 {n - len(show)} 個（--limit 0 看全部）")
        print("\n  每個 host 至少跑一次測繪再談收尾："
              "\n    bundle/JS 端點萃取 → python3 automation/asg.py add-surface <target> "
              "\"<面>\" --type <node_type>"
              "\n    型別決定能不能取到必測包；分不出來寫 --type unknown，它會被 "
              "asg.py status 的 surfaces_untyped 算著")
    return 0


if __name__ == "__main__":
    sys.exit(main())
