#!/usr/bin/env python3
"""coverage_matrix.py — the surface × risk_area coverage matrix.

Why this exists (2026-11-28):
    `scope_coverage.py` fixed the host denominator (in-scope hosts that never
    became a surface). `surface_state()` fixes the surface denominator (a surface
    tested or not). Neither answers the SECOND dimension: a surface may be settled
    for XSS and never touched for IDOR. The ledger already carries the signal —
    0/113 finding events once carried `vuln_class`, but a `finding` event DOES
    carry `vuln_class` + `resolves` now (see MPO-001: vuln_class=xss,
    resolves=[param-mpo-tblid]) — yet nothing projected it as a (surface × class)
    grid, so "which class is still untested on this surface" was invisible.

    Ported concept (data model only, not code) from ARTEX-CC's `record_coverage`
    (surface × risk_area × outcome ledger, AGPL-3.0; https://artex-cc.com). ARTEX
    enforces an outcome enum and treats an ABSENT cell as the frontier — the empty
    row is where the next intent comes from. This reuses that semantics on top of
    the existing ASG event ledger instead of a PostgreSQL table: a new append-only
    `coverage` event kind, projected read-only here.

Lineage: complements MANDATORY_WORKERS `verb-matrix` (GET+write verbs per node);
    verb-matrix is a per-finding gate, this is a per-target 2-D map.

Reads only (default + show). `record` is the single write path and goes through
    asg.append_event like every other ledger write. `--json` for consumers.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import asg  # noqa: E402
from evidence_refs import finding_records  # noqa: E402

# ARTEX-CC coverage outcome enum (coverage_ledger CHECK), plus the implicit empty
# cell "" = not tested. Last write wins per (surface, risk_area), exactly as the
# ARTEX ledger's UNIQUE(task_id, surface, risk_area) row does.
OUTCOMES = ("reported", "no_issue_found", "ruled_out", "not_applicable",
            "needs_follow_up")

# One-char glyph per cell state for the text grid. Empty cell is a blank — the
# frontier, read exactly as ARTEX reads its empty row.
GLYPH = {
    "reported": "R",
    "no_issue_found": ".",
    "ruled_out": "x",
    "not_applicable": "-",
    "needs_follow_up": "?",
    "": " ",
}

# A small standard column set, added only with --standard, so a fresh target still
# shows the classes worth asking about even before any event names them.
STANDARD_RISKS = ("idor", "xss", "sqli", "ssrf", "auth", "info-disclosure",
                  "csrf", "rce", "open-redirect", "business-logic")


def _events(target: str | Path) -> list[dict]:
    led = asg.ledger_path(target)
    if not led.exists():
        return []
    from ledger_reader import read_ledger_events
    return list(read_ledger_events(led))


def _coverage_events(events: list[dict]) -> dict[tuple[str, str], dict]:
    """Latest explicit coverage verdict per (surface, risk_area). Last write wins."""
    cells: dict[tuple[str, str], dict] = {}
    for e in events:
        if e.get("type") != "coverage":
            continue
        surface = str(e.get("surface", "")).strip()
        risk = asg.canonical_vuln_class(str(e.get("risk_area", "")))
        if not surface or not risk:
            continue
        cells[(surface, risk)] = {
            "outcome": str(e.get("outcome", "")).strip(),
            "reason": e.get("reason", ""),
            "cites": e.get("cites", ""),
            "at": e.get("at", ""),
            "owner": e.get("owner", ""),
        }
    return cells


def _finding_cells(events: list[dict]) -> dict[tuple[str, str], str]:
    """Implicit `reported` cells: a finding with vuln_class resolving a surface."""
    cells: dict[tuple[str, str], str] = {}
    for rec in finding_records(events).values():
        vc = asg.canonical_vuln_class(str(rec.get("vuln_class", "")))
        if not vc:
            continue
        for surface in rec.get("resolves", []) or []:
            cells[(str(surface), vc)] = rec.get("id", "")
    return cells


def matrix(target: str | Path, *, standard: bool = False) -> dict:
    """Build the surface × risk_area grid from the ledger. Pure projection."""
    events = _events(target)
    surfaces = sorted(asg.surface_state(target).keys())
    cov = _coverage_events(events)
    fnd = _finding_cells(events)

    # Columns = every risk_area that any signal mentions, plus the standard set on
    # request. Rows = every surface, plus any surface a coverage event names that
    # the surface projection has not yet registered.
    risks: set[str] = {r for (_, r) in cov} | {r for (_, r) in fnd}
    if standard:
        risks |= {asg.canonical_vuln_class(r) for r in STANDARD_RISKS}
    extra_rows = {s for (s, _) in cov} | {s for (s, _) in fnd}
    all_rows = sorted(set(surfaces) | extra_rows)
    cols = sorted(risks)

    grid: dict[str, dict[str, dict]] = {}
    empty = tested = reported = 0
    for s in all_rows:
        grid[s] = {}
        for r in cols:
            if (s, r) in cov:
                cell = dict(cov[(s, r)])
            elif (s, r) in fnd:
                cell = {"outcome": "reported", "reason": "",
                        "cites": f"finding:{fnd[(s, r)]}", "at": "", "owner": ""}
            else:
                cell = {"outcome": "", "reason": "", "cites": "", "at": "", "owner": ""}
            grid[s][r] = cell
            if cell["outcome"] == "":
                empty += 1
            else:
                tested += 1
                if cell["outcome"] == "reported":
                    reported += 1

    return {
        "target": asg._basename(target),
        "surfaces": all_rows,
        "risks": cols,
        "grid": grid,
        "totals": {"cells": len(all_rows) * len(cols), "tested": tested,
                   "empty": empty, "reported": reported},
    }


def record(target: str | Path, surface: str, risk_area: str, outcome: str, *,
           reason: str = "", cites: str = "", owner: str | None = None) -> dict:
    """Append one coverage verdict. The single write path (via asg.append_event).

    ARTEX requires a reason for `ruled_out` / `not_applicable` and evidence for
    `no_issue_found`; this mirrors that as a refusal, so an absent-finding cell is
    never read as a clean target without a stated basis.
    """
    outcome = outcome.strip()
    if outcome not in OUTCOMES:
        raise SystemExit(f"outcome must be one of {OUTCOMES}, got {outcome!r}")
    risk = asg.canonical_vuln_class(risk_area)
    if not surface.strip():
        raise SystemExit("surface is required")
    if not risk:
        raise SystemExit("risk_area is required")
    if outcome in ("ruled_out", "not_applicable") and not reason.strip():
        raise SystemExit(f"{outcome} requires --reason (why this surface/class does not apply)")
    if outcome == "no_issue_found" and not (cites.strip() or reason.strip()):
        raise SystemExit("no_issue_found requires --cites (a fact/traffic/finding id) or --reason")
    asg.append_event(target, "coverage", owner=owner, surface=surface.strip(),
                     risk_area=risk, outcome=outcome, reason=reason.strip(),
                     cites=cites.strip())
    return {"recorded": {"surface": surface.strip(), "risk_area": risk,
                         "outcome": outcome}}


def _render(m: dict) -> str:
    rows, cols, grid = m["surfaces"], m["risks"], m["grid"]
    if not rows:
        return f"{m['target']}: no surfaces in ledger."
    if not cols:
        return (f"{m['target']}: {len(rows)} surfaces, no risk_area signal yet. "
                f"Run with --standard to show the standard class columns, or "
                f"`record` a coverage verdict.")
    # Width: surface label clipped, one char per risk column.
    w = min(max((len(s) for s in rows), default=8), 44)
    head = " " * (w + 2) + " ".join(c[:3].ljust(3) for c in cols)
    lines = [head]
    for s in rows:
        label = (s[:w - 1] + "…") if len(s) > w else s.ljust(w)
        cells = " ".join(GLYPH.get(grid[s][c]["outcome"], "?").center(3) for c in cols)
        lines.append(f"{label}  {cells}")
    t = m["totals"]
    legend = "  ".join(f"{g}={o}" for o, g in
                       [(o, GLYPH[o]) for o in OUTCOMES] + [("not tested", "·")])
    lines.append("")
    lines.append(f"cells {t['cells']}  tested {t['tested']}  "
                 f"empty/frontier {t['empty']}  reported {t['reported']}")
    lines.append(legend.replace("' '", "·"))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")

    show = sub.add_parser("show", help="print the matrix (default)")
    show.add_argument("target")
    show.add_argument("--standard", action="store_true",
                      help="add the standard OWASP-ish risk columns")
    show.add_argument("--json", action="store_true")

    rec = sub.add_parser("record", help="append one coverage verdict")
    rec.add_argument("target")
    rec.add_argument("surface")
    rec.add_argument("risk_area")
    rec.add_argument("outcome", choices=OUTCOMES)
    rec.add_argument("--reason", default="")
    rec.add_argument("--cites", default="", help="fact/traffic/finding id backing the verdict")
    rec.add_argument("--owner", default=None)
    rec.add_argument("--json", action="store_true")

    # Bare `coverage_matrix.py <target>` == show.
    argv = sys.argv[1:]
    if argv and argv[0] not in ("show", "record", "-h", "--help"):
        argv = ["show"] + argv
    args = ap.parse_args(argv)

    if args.cmd == "record":
        out = record(args.target, args.surface, args.risk_area, args.outcome,
                     reason=args.reason, cites=args.cites, owner=args.owner)
        print(json.dumps(out, ensure_ascii=False) if args.json else
              f"recorded: {out['recorded']}")
        return 0

    m = matrix(args.target, standard=getattr(args, "standard", False))
    print(json.dumps(m, ensure_ascii=False, indent=2) if args.json else _render(m))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
