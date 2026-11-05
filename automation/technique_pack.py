#!/usr/bin/env python3
"""technique_pack.py — the retriever for 「面 → 必測包」(surface → must-test technique pack).

Content lives in ONE place: `09 - Knowledge Base/Pattern - Surface to Must-Test Technique
Packs.md`. This module PARSES that file (never duplicates it) and answers three questions a
hunter asks the moment recon shows a node:

  for-node <type…>   — packs whose ASG node_types include a type (the primary contract:
                       「retriever 按 ASG node 類型取」). Generic types (endpoint/param/
                       service) match broadly and are de-weighted vs specific ones.
  match "<text>"     — infer applicable packs from free surface text (a surface label +
                       note), scored by specific node_type + curated trigger tokens. This
                       is the fuzzy helper next_work uses to swap a generic surface item's
                       skill for the specific must-test skill. It deliberately returns
                       NOTHING for non-web surfaces (a firmware code-sink label matches no
                       web pack) — no false 路燈 injection.
  index              — parse-check: every pack, its node_types, its skill (also proves the
                       md still parses after edits).

Why a retriever and not "load the skill at session start": the pattern file's own thesis —
opening a whole skill into context makes the model test what it REMEMBERS (XSS/IDOR under
the streetlight), not what the graph shows (the upload/SSTI/SSRF node sitting untested).
The retriever pulls only the pack for the node in front of you.

Usage:
  technique_pack.py index [--json]
  technique_pack.py for-node upload-form [file-param …] [--json]
  technique_pack.py match "avatar upload multipart filename=" [--json]
  technique_pack.py for-target <target> [--json]   # untested surfaces → packs
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

VAULT = Path(os.environ.get("VAULT_ROOT") or Path(__file__).resolve().parents[1])
PATTERN_MD = VAULT / "09 - Knowledge Base" / "Pattern - Surface to Must-Test Technique Packs.md"

# Node types that nearly every web pack lists — true, but too coarse to discriminate on.
# for-node still returns them; match() ignores them so free text doesn't explode to all packs.
GENERIC_TYPES = {"endpoint", "param", "service"}

# Curated trigger tokens per EXECUTING SKILL — the discriminating words a surface label/note
# carries that the node_type name alone misses (upload-form → also "multipart"/"filename=").
# Retriever wiring, not knowledge: the packs' content stays in the md. Lower-cased substring
# match. Keep high-signal only; a token that fires on generic endpoints would defeat the point.
SKILL_SIGNALS: dict[str, list[str]] = {
    "upload-insecure-files": ["upload", "multipart", "filename=", "avatar", "attachment",
                              "logo", "import file", "plugin", "theme", ".jar", ".war",
                              "webshell", "http put", "webdav"],
    "path-traversal-lfi": ["traversal", "lfi", "?file=", "?path=", "?page=", "?doc=",
                           "?template=", "?include=", "?view=", "../", "archive", ".zip",
                           ".tar", "file manager", "log viewer", "download"],
    "xxe-xml-external-entity": ["xxe", "xml", "svg", "docx", "xlsx import", "office",
                                "ocr", "thumbnail", "transcode", "xml parser"],
    "ssti-server-side-template-injection": ["ssti", "template", "jinja", "freemarker",
                                            "velocity", "twig", "{{", "render", "report template",
                                            "pdf template", "email template"],
    "ssrf-server-side-request-forgery": ["ssrf", "?url=", "?next=", "?redirect=", "?dest=",
                                         "?image=", "callback", "webhook", "wkhtmltopdf",
                                         "headless", "fetch url", "pdf export", "screenshot",
                                         "test connection", "verify url"],
    "csv-formula-injection": ["csv", "xlsx export", "formula", "computed column",
                              "low-code", "=cmd", "spreadsheet"],
    "expression-language-injection": ["spel", "ognl", "expression", "rule engine",
                                      "filter-query", "workflow condition"],
    "deserialization-insecure": ["deserial", "viewstate", "__viewstate", "ro0ab", "aced0005",
                                 "pickle", "itsdangerous", "flask session", "_app_session",
                                 "rails session", "restore backup", "import config", "migrate config"],
    "cmdi-command-injection": ["command injection", "cmdi", "ping", "traceroute", "nslookup",
                               "whois lookup", "connectivity test", "diagnostic", "run command",
                               "cron", "scheduled job"],
    "jndi-injection": ["jndi", "log4j", "log4shell", "ldap://", "struts", "jsessionid",
                       "x-powered-by", "user-agent log"],
    "bb-actuator-cloud-chain": ["actuator", "spring boot", "/env", "/heapdump", "/jolokia",
                                "x-application-context", "whitelabel"],
    "bb-version-cve-precheck": ["jboss", "wildfly", "weblogic", "glassfish", "jmx",
                                "/invoker", "version banner", "jm-console"],
    # XSS and SQLi were deliberately absent until 2026-10-02 — the file's own preamble
    # calls them the streetlight classes, on the assumption that a hunter tests them by
    # reflex and the packs' budget belongs to upload/SSTI/SSRF/deser. A real-world case
    # falsified that assumption: an API-first engagement produced 29 findings, every one
    # auth/authz/disclosure, and ZERO injection-class tests — XSS has exactly one data
    # point in the whole target. The reflex does not fire when the lens is authorization.
    # Adding them here does not reintroduce the streetlight: the retriever only answers
    # when a matching surface is registered, so these fire on a mapped reflected-param or
    # orderBy, never on "it is a web app".
    "xss-cross-site-scripting": ["innerhtml", "document.write", "dangerouslysetinnerhtml",
                                 "insertadjacenthtml", "location.hash", "postmessage",
                                 "jsonp", "?callback=", "dom sink", "reflected", "回顯",
                                 "srcdoc", "unsafe-inline"],
    # `orderBy`/`sortField` lead deliberately: they cannot be bound by a prepared
    # statement, so they are where injection survives after parameterisation, and they
    # are the parameters nobody fuzzes.
    "sqli-sql-injection": ["orderby", "sortfield", "sort_field", "groupby", "?filter=",
                           "?where=", "raw sql", "sql injection", "sqli", "second-order",
                           "boolean blind", "union select"],
}


def _parse_packs(md_text: str) -> list[dict]:
    """Split the pattern file into structured packs. Each `## ` block yields
    {skill, summary, node_types:[…], must_test:[…], why, hints, examples, raw_title}."""
    packs: list[dict] = []
    # Blocks start at a line beginning with "## " (H2). The doc preamble before the
    # first H2 is skipped.
    blocks = re.split(r"(?m)^## ", md_text)
    for blk in blocks[1:]:
        title = blk.splitlines()[0].strip() if blk else ""
        # skill: **執行 skill**：`name`
        m_skill = re.search(r"\*\*執行 skill\*\*[:：]\s*`([^`]+)`", blk)
        if not m_skill:
            continue  # not a pack block
        skill = m_skill.group(1).strip()
        # node_types: the backticked tokens on the **node_types** line
        node_types: list[str] = []
        m_nt = re.search(r"\*\*node_types\*\*[^\n]*", blk)
        if m_nt:
            node_types = [t.lower() for t in re.findall(r"`([^`]+)`", m_nt.group(0))]
        # must_test: bullet lines after the **必測包** label until the next **bold** field
        must_test: list[str] = []
        m_mt = re.search(r"\*\*必測包\*\*[^\n]*\n(.*?)(?=\n\*\*|\Z)", blk, re.S)
        if m_mt:
            for line in m_mt.group(1).splitlines():
                s = line.strip()
                if s.startswith("- "):
                    must_test.append(s[2:].strip())
        summary = title.split("—", 1)[1].strip() if "—" in title else title

        def _field(label: str) -> str:
            m = re.search(rf"\*\*{label}\*\*[:：]\s*([^\n]+)", blk)
            return m.group(1).strip() if m else ""

        packs.append({
            "skill": skill,
            "summary": summary,
            "node_types": node_types,
            "specific_types": [t for t in node_types if t not in GENERIC_TYPES],
            "must_test": must_test,
            "why": _field("為何常出 RCE") or _field("為何常出"),
            "hints": _field("偵測提示"),
            "examples": _field("實例"),
            "raw_title": title,
        })
    return packs


def load_packs() -> list[dict]:
    try:
        return _parse_packs(PATTERN_MD.read_text(encoding="utf-8"))
    except OSError:
        return []


def for_node(types, packs=None) -> list[dict]:
    """Packs whose node_types include any of `types` (case-insensitive)."""
    packs = packs if packs is not None else load_packs()
    want = {str(t).lower().strip() for t in types if str(t).strip()}
    return [p for p in packs if want & set(p["node_types"])]


def _token_hit(tok: str, low: str) -> bool:
    """A single-word alnum token must match on a word boundary (so `ping` doesn't fire on
    `mapping`, `parser` on `TLV parser`); a token with punctuation/space matches as a plain
    substring (`?url=`, `.jar`, `test connection`, `http put`)."""
    tok = tok.lower()
    if re.fullmatch(r"[a-z][a-z0-9]*", tok):
        return re.search(rf"\b{re.escape(tok)}\b", low) is not None
    return tok in low


def match(text: str, packs=None) -> list[dict]:
    """Rank packs applicable to free surface text. A pack scores on its skill's curated
    trigger tokens and on any HYPHENATED specific node_type it lists (upload-form/ssrf-sink —
    unambiguous; single-word types like `parser`/`port`/`job` are NOT scored as text because
    they collide with non-web prose). Generic types never score. Returns packs with score>0,
    highest first, each with an added `_score`. Empty for text that matches no web pack (e.g.
    a firmware code-sink label) — no false injection."""
    packs = packs if packs is not None else load_packs()
    low = (text or "").lower()
    scored: list[tuple[int, dict]] = []
    for p in packs:
        score = 0
        for t in p["specific_types"]:
            if "-" in t and t in low:          # hyphenated type as a literal label token
                score += 2
        for tok in SKILL_SIGNALS.get(p["skill"], []):
            if _token_hit(tok, low):
                score += 1
        if score > 0:
            scored.append((score, p))
    scored.sort(key=lambda sp: sp[0], reverse=True)
    out = []
    for score, p in scored:
        q = dict(p)
        q["_score"] = score
        out.append(q)
    return out


def retrieve(text: str, packs=None) -> dict | None:
    """One best pack for a surface, for programmatic callers (next_work). None if no match."""
    hits = match(text, packs)
    return hits[0] if hits else None


def _emit(objs, as_json, human):
    if as_json:
        print(json.dumps(objs, ensure_ascii=False, indent=1))
    else:
        human(objs)


def _print_pack(p, show_score=False):
    tag = f" (score {p['_score']})" if show_score and "_score" in p else ""
    print(f"■ {p['skill']}{tag}")
    print(f"  面: {p['summary'][:110]}")
    print(f"  node_types: {' · '.join(p['node_types'])}")
    if p["must_test"]:
        print("  必測:")
        for mt in p["must_test"]:
            print(f"    - {mt}")
    print("")


def main():
    args = sys.argv[1:]
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    if not args:
        print(__doc__)
        return 2
    action = args[0]
    packs = load_packs()

    if action == "index":
        idx: dict[str, list[str]] = {}
        for p in packs:
            for t in p["node_types"]:
                idx.setdefault(t, []).append(p["skill"])
        data = {"pattern_file": str(PATTERN_MD.relative_to(VAULT)),
                "pack_count": len(packs),
                "node_type_index": {t: sorted(set(v)) for t, v in sorted(idx.items())}}
        if as_json:
            print(json.dumps(data, ensure_ascii=False, indent=1))
        else:
            print(f"{len(packs)} packs parsed from {data['pattern_file']}\n")
            for t, skills in data["node_type_index"].items():
                mark = "" if t in GENERIC_TYPES else "★"
                print(f"  {mark}{t}: {', '.join(skills)}")
        return 0 if packs else 1

    if action == "for-node":
        types = args[1:]
        if not types:
            print("usage: technique_pack.py for-node <type> [type…]", file=sys.stderr)
            return 2
        hits = for_node(types, packs)
        _emit(hits, as_json, lambda hs: [_print_pack(p) for p in hs] or None)
        if not as_json and not hits:
            print(f"(no pack for node_types: {', '.join(types)})")
        return 0

    if action == "match":
        text = " ".join(args[1:])
        if not text:
            print("usage: technique_pack.py match \"<surface text>\"", file=sys.stderr)
            return 2
        hits = match(text, packs)
        _emit(hits, as_json, lambda hs: [_print_pack(p, show_score=True) for p in hs] or None)
        if not as_json and not hits:
            print("(no technique pack matches — likely a non-web surface)")
        return 0

    if action == "for-block":
        # 由「擋你的那句話」直接取繞過包。這是本模組唯一**不靠猜型別**的入口：
        # 錯誤訊息是伺服器自己說出口的觀測，比從面的名字推出來的 node_type 可靠得多
        # （實例：ASG 標籤可能寫成某 BI 產品名，實際卻是 AI agent 平台）。
        if len(args) < 2:
            print('usage: technique_pack.py for-block "<伺服器回的拒絕訊息>"', file=sys.stderr)
            return 2
        msg = " ".join(args[1:]).lower()
        # 角色排在租戶前面：「权限不足，该接口仅限管理员租户访问」兩邊的字都有，
        # 但它講的是權限不足，不是缺租戶上下文——擋你的那一層判錯，繞過向量就全錯。
        RULES = [
            ("blocked-role",   ["privilege", "权限不足", "權限不足", "admin", "管理员", "role", "forbidden", "403"]),
            ("blocked-tenant", ["tenant", "租戶", "租户"]),
            ("blocked-method", ["method", "not allow", "405", "找不到"]),
            ("blocked-auth",   ["unauthor", "authentication", "401", "anonymous", "token", "登入"]),
        ]
        hit = next((t for t, words in RULES if any(w in msg for w in words)), None)
        if not hit:
            print("(訊息看不出被擋在哪一層；四種都看一遍)")
            hit = "blocked-auth"
        print(f"擋在：{hit}\n")
        _emit(for_node([hit], packs), as_json,
              lambda hs: [_print_pack(x) for x in hs] or None)
        print("\n⚠ 把這個面記成 blocked（附原訊息），不要記成 tested——"
              "擋住代表那一層之後的程式碼完全沒被測到。")
        return 0

    if action == "for-target":
        if len(args) < 2:
            print("usage: technique_pack.py for-target <target>", file=sys.stderr)
            return 2
        target = args[1]
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        rows = []
        try:
            import asg
            st = asg.surface_state(target)
        except Exception as e:
            print(f"⚠ cannot read surfaces for {target}: {e}", file=sys.stderr)
            return 2
        # node_type first, free text only as a fallback. `for-node` is this module's
        # primary contract, but this per-target view used to ignore the type entirely and
        # match on the surface's NAME — so after one target's 102 surfaces were finally
        # typed, the view that a hunter actually reads still answered "(generic)" for all
        # but the four whose names happened to contain a trigger word. Typing the graph
        # and then not reading the types is the same break one layer down.
        try:
            types = {}
            for e in asg.HuntLoop.load(asg.ledger_path(target)).events:
                if e.get("type") == "surface" and e.get("name"):
                    types[str(e["name"])] = str(e.get("node_type") or "").strip().lower()
        except Exception:
            types = {}
        for name, state in st.items():
            if state != "untested":
                continue
            nt = types.get(name, "")
            by_type = [p for p in for_node([nt], packs) if nt and nt not in GENERIC_TYPES] if nt else []
            if len(by_type) > 1:
                # A node_type like `version-banner` or `secret-material` appears in several
                # packs, and taking the first listed sends /debug/pprof/ to the upload pack.
                # Rank the type-matched candidates by how well the surface TEXT scores, so
                # the type narrows the field and the wording picks within it.
                ranked = {p["skill"]: i for i, p in enumerate(match(name, packs))}
                by_type.sort(key=lambda p: ranked.get(p["skill"], 10_000))
            best = by_type[0] if by_type else retrieve(name, packs)
            rows.append({"surface": name,
                         "node_type": nt or None,
                         "skill": best["skill"] if best else "bb-surface-mapping",
                         "must_test": best["must_test"] if best else [],
                         "matched": bool(best),
                         "via": "node_type" if by_type else ("text" if best else None)})
        if as_json:
            print(json.dumps({"target": target, "untested_with_pack": rows},
                             ensure_ascii=False, indent=1))
        else:
            if not rows:
                print(f"(no untested surfaces recorded for {target})")
            for r in rows:
                tag = f"→ {r['skill']}" if r["matched"] else "→ (generic) bb-surface-mapping"
                via = f"  [{r['node_type']}]" if r.get("via") == "node_type" else ""
                print(f"• {r['surface']}  {tag}{via}")
        return 0

    print(f"unknown action: {action}", file=sys.stderr)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
