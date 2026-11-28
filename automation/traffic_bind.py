#!/usr/bin/env python3
"""traffic_bind.py — search captured traffic and bind an exchange to a Finding.

Why this exists (2026-11-28):
    The MITM capture (`mitm_mcp_traffic.db`, table `flows`) holds request/response
    pairs, but nothing linked a specific exchange to a specific Finding as its
    proof. Evidence lived as prose in the Finding doc; the raw exchange that proved
    it was not addressable. A reviewer could not jump from "IDOR on /api/users" to
    the exact 200 response that showed another tenant's data.

    Ported concept (data model only, not code) from ARTEX-CC's `bind_finding_traffic`
    + `traffic_search` + `traffic_get` (AGPL-3.0; https://artex-cc.com). ARTEX keeps
    a `finding_traffic_bindings` row (finding_id, snapshot_id, role, note, position)
    where role is one of baseline / proof / verification / supporting. This reuses
    that semantics on top of the existing ASG ledger instead of a PostgreSQL table:
    a binding is an append-only `traffic_binding` event on the TARGET's ledger.

    One deliberate divergence from ARTEX: ARTEX stores only the snapshot_id as a
    bare text id with no foreign key, so a binding breaks if traffic is pruned.
    Here the binding PINS a snapshot of the flow's method/url/status/size at bind
    time, so the Finding keeps a durable record even after the flows DB is cleared.

Reads the flows DB read-only for `search`/`get`. `bind` is a ledger write via
    asg.append_event. `list` reads the ledger. `--json` for consumers.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import asg  # noqa: E402
from evidence_refs import finding_records  # noqa: E402

# ARTEX-CC binding roles (finding_traffic_bindings.role enum).
ROLES = ("baseline", "proof", "verification", "supporting")

GET_CLIP = 32 * 1024  # ARTEX traffic_get clips each side at 32 KiB.


def traffic_db() -> Path:
    """Resolve the flows DB: $BB_TRAFFIC_DB, else known locations under the root."""
    env = os.environ.get("BB_TRAFFIC_DB")
    if env:
        return Path(env).expanduser()
    root = asg.vault_root()
    for cand in (root / "mitm_mcp_traffic.db",
                 root.parent / "mitm_mcp_traffic.db",
                 Path.cwd() / "mitm_mcp_traffic.db"):
        if cand.exists():
            return cand
    return root / "mitm_mcp_traffic.db"


def _conn() -> sqlite3.Connection:
    db = traffic_db()
    if not db.exists():
        raise SystemExit(f"traffic DB not found: {db} (set $BB_TRAFFIC_DB)")
    # Read-only URI so a search can never mutate the capture.
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    c.row_factory = sqlite3.Row
    return c


def search(*, host: str = "", contains: str = "", url: str = "", method: str = "",
           status: int | None = None, limit: int = 20) -> list[dict]:
    """Filter flows. `contains` matches request+response headers and bodies."""
    where, params = [], []
    if host:
        where.append("url LIKE ?"); params.append(f"%{host}%")
    if url:
        where.append("url LIKE ?"); params.append(f"%{url}%")
    if method:
        where.append("UPPER(method)=?"); params.append(method.upper())
    if status is not None:
        where.append("status_code=?"); params.append(status)
    if contains:
        where.append("(request_headers LIKE ? OR request_body LIKE ? OR "
                     "response_headers LIKE ? OR response_body LIKE ?)")
        params += [f"%{contains}%"] * 4
    sql = ("SELECT id, method, url, status_code, size, timestamp FROM flows"
           + (" WHERE " + " AND ".join(where) if where else "")
           + " ORDER BY timestamp DESC LIMIT ?")
    params.append(max(1, min(limit, 200)))
    with _conn() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def get(flow_id: str) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM flows WHERE id=?", (flow_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    for k in ("request_body", "response_body", "request_headers", "response_headers"):
        v = d.get(k) or ""
        if len(v) > GET_CLIP:
            d[k] = v[:GET_CLIP] + f"\n…[clipped {len(v) - GET_CLIP} bytes]"
    return d


def _flow_snapshot(flow_id: str) -> dict:
    with _conn() as c:
        r = c.execute("SELECT id, method, url, status_code, size, timestamp "
                      "FROM flows WHERE id=?", (flow_id,)).fetchone()
    if not r:
        raise SystemExit(f"flow {flow_id!r} not found in {traffic_db()}")
    return dict(r)


def bind(target: str | Path, finding_id: str, flow_id: str, *,
         role: str = "supporting", note: str = "", owner: str | None = None) -> dict:
    """Append a traffic_binding event linking one flow to one Finding."""
    if role not in ROLES:
        raise SystemExit(f"role must be one of {ROLES}, got {role!r}")
    events = asg._events_of(target)
    if str(finding_id) not in finding_records(events):
        known = sorted(finding_records(events))
        raise SystemExit(f"finding {finding_id!r} not in {asg._basename(target)} ledger; "
                         f"known: {known or '(none)'}")
    snap = _flow_snapshot(flow_id)
    # position = count of existing bindings for this finding, so list order is stable.
    pos = sum(1 for e in events if e.get("type") == "traffic_binding"
              and str(e.get("finding_id")) == str(finding_id))
    asg.append_event(target, "traffic_binding", owner=owner,
                     finding_id=str(finding_id), flow_id=str(flow_id),
                     role=role, note=note, position=pos, flow=snap)
    return {"bound": {"finding_id": str(finding_id), "flow_id": str(flow_id),
                      "role": role, "position": pos}}


def bindings(target: str | Path, finding_id: str | None = None) -> list[dict]:
    """Current bindings from the ledger, newest-last within each finding."""
    out = []
    for e in asg._events_of(target):
        if e.get("type") != "traffic_binding":
            continue
        if finding_id and str(e.get("finding_id")) != str(finding_id):
            continue
        out.append({"finding_id": e.get("finding_id"), "flow_id": e.get("flow_id"),
                    "role": e.get("role"), "note": e.get("note", ""),
                    "position": e.get("position", 0), "flow": e.get("flow", {}),
                    "at": e.get("at", "")})
    out.sort(key=lambda b: (str(b["finding_id"]), b["position"]))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("search", help="filter captured flows")
    s.add_argument("--host", default="")
    s.add_argument("--contains", default="", help="substring over headers+bodies")
    s.add_argument("--url", default="")
    s.add_argument("--method", default="")
    s.add_argument("--status", type=int, default=None)
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--json", action="store_true")

    g = sub.add_parser("get", help="dump one flow's request+response")
    g.add_argument("flow_id")
    g.add_argument("--json", action="store_true")

    b = sub.add_parser("bind", help="link a flow to a Finding as evidence")
    b.add_argument("target")
    b.add_argument("finding_id")
    b.add_argument("flow_id")
    b.add_argument("--role", choices=ROLES, default="supporting")
    b.add_argument("--note", default="")
    b.add_argument("--owner", default=None)
    b.add_argument("--json", action="store_true")

    l = sub.add_parser("list", help="list bindings on a target")
    l.add_argument("target")
    l.add_argument("finding_id", nargs="?", default=None)
    l.add_argument("--json", action="store_true")

    args = ap.parse_args()

    if args.cmd == "search":
        rows = search(host=args.host, contains=args.contains, url=args.url,
                      method=args.method, status=args.status, limit=args.limit)
        if args.json:
            print(json.dumps(rows, ensure_ascii=False, indent=2)); return 0
        if not rows:
            print("no matching flows."); return 0
        for r in rows:
            print(f"{r['id']}  {r['method']:6} {str(r['status_code']):4} "
                  f"{r['size']:>8}  {r['url'][:90]}")
        return 0

    if args.cmd == "get":
        d = get(args.flow_id)
        if not d:
            print(f"flow {args.flow_id!r} not found."); return 1
        if args.json:
            print(json.dumps(d, ensure_ascii=False, indent=2)); return 0
        print(f"# {d['method']} {d['url']}  -> {d['status_code']}  ({d['size']} bytes)")
        print("\n## request headers\n" + (d.get("request_headers") or ""))
        print("\n## request body\n" + (d.get("request_body") or ""))
        print("\n## response headers\n" + (d.get("response_headers") or ""))
        print("\n## response body\n" + (d.get("response_body") or ""))
        return 0

    if args.cmd == "bind":
        out = bind(args.target, args.finding_id, args.flow_id,
                   role=args.role, note=args.note, owner=args.owner)
        print(json.dumps(out, ensure_ascii=False) if args.json else
              f"bound: {out['bound']}")
        return 0

    if args.cmd == "list":
        bs = bindings(args.target, args.finding_id)
        if args.json:
            print(json.dumps(bs, ensure_ascii=False, indent=2)); return 0
        if not bs:
            print("no bindings."); return 0
        for b_ in bs:
            f = b_.get("flow") or {}
            print(f"{b_['finding_id']}  [{b_['role']}]  flow {b_['flow_id']}  "
                  f"{f.get('method','?')} {f.get('status_code','?')} "
                  f"{f.get('url','')[:70]}"
                  + (f"  — {b_['note']}" if b_['note'] else ""))
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
