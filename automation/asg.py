#!/usr/bin/env python3
"""asg.py — the single authority for a target's Attack Surface Graph.

Converges the two things that both called themselves "ASG":
  1. the hand-maintained Markdown YAML-schema file (read by surface_graph_lib), and
  2. the hunt event ledger (hunt_loop).
into ONE machine state (the event ledger) plus read-only projections.

Three responsibilities, one place:
  * RESOLVER — the canonical, single source of every per-target ASG path. Fixes the
    filename-contract split (`Attack Surface Graph.md` vs the contract
    `Attack Surface Graph - <target>.md`): all code addresses the ASG through here.
  * append_event() — the SOLE write interface. Resolves the ledger, takes the
    single-writer lock (hunt_lock), appends one event, guard-saves, releases. Nothing
    else should write the ledger directly.
  * project_markdown() / write_snapshot() — one-way projections FROM the ledger: a
    generated block inside the Markdown ASG (preserving the operator's own content)
    and a JSON snapshot for the Obsidian/Dataview dashboard.

Non-goal here: force-migrating existing YAML-schema instances or rewiring every
caller — those ride on this seam next. Existing Markdown stays readable; new machine
state flows through append_event.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Optional

from ledger_reader import read_ledger_events, LedgerReadError
from evidence_refs import normalize_evidence

sys_path_hint = Path(__file__).resolve().parent
import sys
if str(sys_path_hint) not in sys.path:
    sys.path.insert(0, str(sys_path_hint))

from hunt_loop import HuntLoop
from hunt_lock import acquire, release, guarded_save

TARGETS_DIRNAME = "01 - Targets"
GEN_START = "<!-- ASG:GENERATED:START -->"
GEN_END = "<!-- ASG:GENERATED:END -->"

# ── PHASE LOCKING ──────────────────────────────────────────────────────────────
PHASES = ("engage", "osint", "recon", "map", "exploit", "foothold", "report")

PROFILE_CHAINS: dict[str, tuple[str, ...]] = {
    "web":          ("engage", "osint", "recon", "map", "exploit", "foothold", "report"),
    "firmware":     ("engage", "recon", "map", "exploit", "report"),
    "source-audit": ("engage", "recon", "map", "exploit", "report"),
    "native":       ("engage", "recon", "map", "exploit", "report"),
    "engagement":   ("engage", "osint", "recon", "map", "exploit", "foothold", "report"),
}

# ── FINDING STATE MACHINE ──────────────────────────────────────────────────────
# `withdrawn` (2026-10-01): the ledger had no way to say "this one is retracted", so
# a finding that turned out to be a false positive, a duplicate, or was pulled after
# vendor contact kept whatever state it last reached — QNAP carried three findings
# sitting at a validated state while the Markdown said `withdrawn`, and nothing could
# reconcile the two. It is reachable from every state (you can retract at any point)
# and exits only to `tested`, because reopening means re-running the test, not
# inheriting the old verdict.
FINDING_STATES = ("hypothesis", "tested", "adversary-verified", "confirmed", "withdrawn")
FINDING_TRANSITIONS: dict[str, list[str]] = {
    "hypothesis":          ["tested", "withdrawn"],
    "tested":              ["adversary-verified", "hypothesis", "withdrawn"],
    "adversary-verified":  ["confirmed", "tested", "withdrawn"],
    "confirmed":           ["withdrawn"],
    "withdrawn":           ["tested"],
}

# Mandatory workers that fire when a finding reaches "confirmed".
# Order matters: `verb-matrix` is a PREREQUISITE for chain/expand (see
# complete_worker). It forces the read+write verb matrix (GET + PUT/PATCH/DELETE,
# cross-tenant) to be covered — or explicitly waived with a reason — BEFORE the
# more engaging chain/expand work can be closed. Root cause it fixes: "stopping at
# GET" was enforced only by the recall-triggered bb-idor-coverage skill; this makes
# node-level write-path coverage an automatic gate (surfaces in check_pending_workers
# → blocks submission). 0/113 finding events carry vuln_class, so verb-matrix is
# required for EVERY confirmed finding and waived per-finding when it does not apply
# (complete-worker <t> <id> verb-matrix "n/a: <why no object/write path>").
MANDATORY_WORKERS = ("verb-matrix", "chain", "expand")
# States that queue the mandatory workers. `confirmed` alone was the original trigger,
# but the real delivery path tops out at `adversary-verified` (adversary_required_gate
# wants exactly that before a FORM) — 某 target reached 95 findings / 33
# adversary-verified / 0 confirmed, so verb-matrix/chain/expand never ran once while
# FORMs shipped. Queue at the first state a finding can be delivered from; queueing is
# idempotent so the later `confirmed` step does not double-book.
WORKER_TRIGGER_STATES = ("adversary-verified", "confirmed")


def mandatory_workers(target, finding_id, *, state=None):
    """Profile-specific checks; workflow checks are not extra model invocations.

    Old web targets keep their verb matrix. Offline/native targets only inherit
    it when the finding explicitly describes an HTTP action.
    """
    import genesis_lib
    from evidence_refs import finding_records
    state = state if state is not None else read_state(target)
    profile = genesis_lib.normalize_genesis(state['genesis'])['profile']
    record = next((f for f in state['findings'] if f.get('id') == finding_id), {})
    mode = record.get('analysis_mode')
    if mode not in (None, 'http', 'static', 'firmware', 'native'):
        raise ValueError(f'unknown analysis_mode: {mode}')
    http = mode == 'http' or str(record.get('protocol', '')).lower() in ('http', 'https')
    if mode is None and not record.get('protocol'):
        http = profile == 'web'
    return MANDATORY_WORKERS if http else ('chain', 'expand')


# ── RESOLVER (the single source of ASG paths) ───────────────────────────────
def vault_root() -> Path:
    return Path(os.environ.get("VAULT_ROOT") or Path(__file__).resolve().parents[1])


def target_dir(target: str | Path) -> Path:
    """Accept a target NAME or any path under it and return the canonical target
    directory (the immediate child of `01 - Targets/`), validated (no traversal)."""
    root = (vault_root() / TARGETS_DIRNAME).resolve()
    p = Path(target)
    if len(p.parts) == 1 and not p.is_absolute() and p.parts[0] not in (".", ".."):
        cand = (root / p.parts[0]).resolve()       # bare target name
    else:
        cand = p.resolve()                          # path form
    if cand == root or root not in cand.parents:
        raise ValueError(f"target {target!r} does not resolve under {TARGETS_DIRNAME}/")
    while cand.parent != root:                     # climb to the target dir
        cand = cand.parent
    return cand


def _basename(target: str | Path) -> str:
    return target_dir(target).name


def state_dir(target: str | Path) -> Path:
    return target_dir(target) / ".state"


def ledger_path(target: str | Path) -> Path:
    """The AUTHORITY: the append-only event ledger for this target."""
    return state_dir(target) / "asg-events.jsonl"


def snapshot_path(target: str | Path) -> Path:
    return state_dir(target) / "asg-snapshot.json"


def markdown_path(target: str | Path) -> Path:
    """The human-readable PROJECTION. Canonical name = the contract name
    (`Attack Surface Graph - <target>.md`), never `Attack Surface Graph.md`."""
    return target_dir(target) / f"Attack Surface Graph - {_basename(target)}.md"


def read_state(target: str | Path) -> dict:
    """One resolved state revision; ledger wins, legacy YAML remains read-only."""
    from asg_state import read_state as materialize
    return materialize(target_dir(target))

def has_genesis(target: str | Path) -> dict | None:
    """Return the genesis event if one exists, else None."""
    led = ledger_path(target)
    if not led.exists():
        return None
    for ev in read_ledger_events(led):
        if ev.get("type") == "genesis":
            return ev
    return None


# ── PHASE QUERIES ──────────────────────────────────────────────────────────────

def current_phase(target: str | Path) -> str | None:
    """Derive the current phase from the ledger. None if no genesis."""
    led = ledger_path(target)
    if not led.exists():
        return None
    phase = None
    for ev in read_ledger_events(led):
        if ev.get("type") == "genesis":
            phase = "engage"
        elif ev.get("type") == "phase":
            phase = ev.get("to")
    return phase


def phase_chain(target: str | Path) -> tuple[str, ...]:
    """Return the phase chain for this target's profile."""
    genesis = has_genesis(target)
    profile = genesis.get("profile", "web") if genesis else "web"
    return PROFILE_CHAINS.get(profile, PHASES)


def advance_phase(target: str | Path, to: str, *, reason: str = "") -> dict:
    """Advance the target to a new phase. Validates ordering within the
    profile's chain. Returns {ok, from, to} or {ok: False, reason}."""
    genesis = has_genesis(target)
    if not genesis:
        return {"ok": False, "reason": "no genesis"}
    cur = current_phase(target)
    chain = phase_chain(target)
    if to not in chain:
        profile = genesis.get("profile", "web")
        return {"ok": False, "reason": f"phase '{to}' not in chain for profile '{profile}'"}
    cur_idx = chain.index(cur) if cur and cur in chain else -1
    to_idx = chain.index(to)
    if to_idx <= cur_idx:
        return {"ok": False, "reason": f"cannot go backward: {cur} -> {to}"}
    # Coverage-before-report gate: entering the report phase with most of the attack
    # surface still untested is the harvest-bias failure mode (find a lot ≠ covered).
    # The number is objective (status()); require a tested-surface floor before report.
    # Strict by default — being blocked in recon is intended; thorough coverage is the
    # point. Override: BB_SKIP_COVERAGE_GATE=1 ; tune: BB_COVERAGE_FLOOR (0..1).
    if to == "report" and os.environ.get("BB_SKIP_COVERAGE_GATE") != "1":
        # Scope is the one denominator we do not choose for ourselves. Surface
        # coverage below is `settled / surfaces we recorded`, so testing everything
        # we wrote down reaches 100% while whole in-scope hosts sit outside the
        # list — exactly how 某 target read as finished with 29 of 53 hosts never
        # touched. Only fires where the comparison is meaningful (see
        # scope_coverage.gap: host-scoped surfaces, ledger present).
        try:
            import scope_coverage
            sc = scope_coverage.gap(target)
        except Exception:
            sc = {"applicable": False}
        if sc.get("applicable") and sc.get("untouched_hosts"):
            untouched = sc["untouched_hosts"]
            head = "、".join(untouched[:5]) + (f" 等 {len(untouched)} 個" if len(untouched) > 5 else "")
            return {"ok": False, "reason":
                    f"scope 內有 {len(untouched)}/{sc['scope_hosts']} 個 host 從未成為攻擊面"
                    f"（{head}）——這不是「測過沒洞」，是連一個面都還沒記，"
                    f"所以 surface 覆蓋率算不到它們。先對每個 host 做測繪"
                    f"（`python3 automation/scope_coverage.py {sc['target']} --limit 0` 看全部），"
                    f"或 BB_SKIP_COVERAGE_GATE=1 放行。"}
        st = status(target)
        tot = st.get("surfaces_total", 0) or 0
        unt = st.get("surfaces_untested", 0) or 0
        inc = st.get("surfaces_inconclusive", 0) or 0
        if tot > 0:
            # Only settled surfaces count. An `inconclusive` surface ran a test and
            # learned nothing, so it is still open work — see status() for why.
            tested_ratio = (tot - unt - inc) / tot
            try:
                floor = float(os.environ.get("BB_COVERAGE_FLOOR", "0.8"))
            except ValueError:
                floor = 0.8
            if tested_ratio < floor:
                return {"ok": False, "reason":
                        f"coverage {tested_ratio:.0%} < {floor:.0%} 門檻"
                        f"（{tot - unt - inc}/{tot} surface 已決，{unt} 未測"
                        f"{f'、{inc} inconclusive（測了但沒結論，不算覆蓋）' if inc else ''}）"
                        f"——surface 大多未測，不進 report。"
                        f" 先把 surface 測完並在 ledger 標記（surface 事件 untested=False），"
                        f"或 BB_SKIP_COVERAGE_GATE=1 放行、BB_COVERAGE_FLOOR=<0..1> 調門檻。"}
    append_event(target, "phase", to=to, **{"from": cur}, reason=reason)
    return {"ok": True, "from": cur, "to": to}


def phase_index(target: str | Path) -> int:
    """Return the numeric index of the current phase in the target's chain.
    -1 if no genesis/phase."""
    cur = current_phase(target)
    if cur is None:
        return -1
    chain = phase_chain(target)
    return chain.index(cur) if cur in chain else -1


def phase_allows(target: str | Path, required_phase: str) -> bool:
    """True if the current phase >= required_phase in the chain."""
    cur = current_phase(target)
    if cur is None:
        return False
    chain = phase_chain(target)
    if cur not in chain or required_phase not in chain:
        return True
    return chain.index(cur) >= chain.index(required_phase)


# ── FINDING STATE QUERIES ──────────────────────────────────────────────────────

def finding_state(target: str | Path, finding_id: str) -> str | None:
    """Derive the current state of a finding from ledger events."""
    from evidence_refs import finding_records
    finding = finding_records(read_ledger_events(ledger_path(target))).get(finding_id)
    return finding.get("status") if finding else None


# Evidence-shape check for finding promotion. Added 2026-10-02 after 某 target
# 其中一筆 finding (and 11 sibling findings) were promoted to 'tested' on the strength of a
# business-logic/NPE error message alone — "reached the controller, therefore no
# authz check". Re-sent with a complete body, the same endpoint answered
# "用戶{0}不是超級管理員": the authz check runs AFTER parameter validation, so the
# earlier error carried zero information about it. See LL-314.
#
# Deliberately advisory: it annotates the ledger event instead of blocking, because
# a blocking gate here would be routed around (LL-312 dead-gate failure mode).
_OBSERVED_RE = re.compile(
    r"(\b\d[\d,]{1,}\s*(rows?|records?|筆|條|bytes?|KB|MB)\b|HTTP\s*200|\b200\b|"
    r"cross_priv_(read|write)|command_executed|bytes_exfiltrated|rss_growth|stock_crash|"
    r"returns?|returned|retrieved|回傳|取得|讀到|讀取到)", re.I)
_ERRORONLY_RE = re.compile(
    r"(method not found|service interface not found|not allow anonymous|\bNPE\b|"
    r"nullpointer|stack ?trace|business logic|參數|参数|不能為空|不能为空|"
    r"\b4\d\d\b|\b5\d\d\b|error message|錯誤訊息)", re.I)


def evidence_shape_warning(to: str, reason: str) -> str | None:
    """Return a warning when a promotion's stated reason looks like it rests on an
    error response rather than an observed result. None when it looks fine."""
    if to not in ("tested", "adversary-verified", "confirmed"):
        return None
    if not reason.strip():
        return ("no reason given — state what was actually observed "
                "(rows retrieved / HTTP 200 / cross_priv_read), not just that the endpoint responded")
    if _OBSERVED_RE.search(reason):
        return None
    if _ERRORONLY_RE.search(reason):
        return ("reason cites only an error/validation response. An error produced by a "
                "parameter-validation or dispatch layer says nothing about authorization "
                "(LL-314). Re-test with a complete, correctly-shaped request before "
                "treating this as established, or restate the reason with the observed result.")
    # Anything else is left alone on purpose. An earlier revision also warned whenever
    # the reason matched no "observed result" keyword, which flagged 81% of existing
    # promotions (including well-evidenced ones like "admin=true" or a concrete pod
    # name) — a gate that noisy gets ignored wholesale (LL-312). Only the two shapes
    # above are reliable enough to be worth a signal.
    return None


#   data_access   讀到了不該讀的資料
#   state_change  改到了不該改的狀態
#   exec          執行到了
#   none          只碰到認證層／參數層的回應——是線索，不是漏洞
OBSERVATION_KINDS = ("data_access", "state_change", "exec", "source_condition", "none")
EVIDENCED_STATES = ("tested", "adversary-verified", "confirmed")

# 「為什麼這條不算洞」。刻意與 vuln_class 分開：vuln_class 是**漏洞類別**
# （information-disclosure、idor…，ledger 裡已有 222 筆在用），把退件理由塞進去
# 會讓兩種語意混在同一欄，之後誰都分不出「這是 SSRF」與「這是設計如此」。
DISMISSALS = {
    "by_design": "設計如此／協定本性（RFC 允許）",
    "static_only": "靜態看起來危險，動態沒達到 expected",
    "theoretical": "只有版本比對 CVE，無 PoC",
    "insufficient_evidence": "把錯誤層／未授權報錯當成繞過",
    "public_by_design": "公開本就該公開（憑證、DSN）",
    "duplicate_root_cause": "同一根因的第 N 個端點——併進既有 stub",
    "enabler": "資訊洩漏但未升到後果——繼續串，不單獨成洞",
}

# vuln_class 的拼法正規化。實測：222 筆散成 99 種字串，「資訊洩漏」一個類別
# 就有 information-disclosure / 資訊洩漏 / Information Disclosure 三種寫法，
# 任何依這欄分組的統計都會算錯。只在**寫入時**正規化，不改寫歷史。
VULN_CLASS_ALIASES = {
    "資訊洩漏": "information-disclosure", "information disclosure": "information-disclosure",
    "info-disclosure": "information-disclosure", "information_disclosure": "information-disclosure",
    "指令注入攻擊": "command-injection", "code-injection": "command-injection",
    "遠端命令執行": "command-injection", "rce": "command-injection",
    "邏輯漏洞": "logic-error", "logic-flaw": "logic-error",
    "弱密碼": "weak-credentials", "hardcoded-credentials": "weak-credentials",
    "存取控制": "broken-access-control", "越權": "broken-access-control",
    # 2026-10-10 補：上面這份表上線後，值仍散成 118 種。缺的都是同義的另一種拼法
    # ——大寫帶空格的英文、沒收進來的中文、單複數／長短不一的變體。
    "broken access control": "broken-access-control",
    "存取控制缺陷": "broken-access-control", "存取控制漏洞": "broken-access-control",
    "broken access control / idor": "idor", "insecure-direct-object-reference": "idor",
    "missing authentication": "authentication-bypass",
    "broken authentication": "authentication-bypass",
    "auth-bypass": "authentication-bypass", "認證繞過": "authentication-bypass",
    "記憶體破壞": "memory-corruption", "memory corruption": "memory-corruption",
    "命令注入": "command-injection", "command injection": "command-injection",
    "os-command-injection": "command-injection",
    "logic-vulnerability": "logic-error", "business-logic": "logic-error",
    "dos": "denial-of-service", "阻斷服務": "denial-of-service",
    "sql-injection": "sqli", "sql injection": "sqli",
    "cross-site-scripting": "xss", "reflected-xss": "xss", "stored-xss": "xss",
    "directory-traversal": "path-traversal", "lfi": "path-traversal",
    "user enumeration": "user-enumeration", "帳號列舉": "user-enumeration",
    "outdated-component": "vulnerable-component",
    "known-vulnerable-component": "vulnerable-component",
    # 語意無歧義的中文類別名。含多個類別的複合值（「X / Y」）不收 ——
    # 那要拆成兩筆 finding，不是換一個拼法。
    "資料庫注入攻擊": "sqli", "sql 注入": "sqli",
    "預存式跨站腳本攻擊": "xss", "跨站腳本攻擊": "xss",
    "跨站冒名請求": "csrf", "跨站請求偽造": "csrf",
    "程式碼執行": "command-injection", "任意程式碼執行": "command-injection",
    "任意檔案寫入": "unrestricted-file-upload",
    "競爭條件": "race-condition",
    "路徑穿越": "path-traversal", "目錄遍歷": "path-traversal",
}

# 判定「這個值是不是另一種拼法」用**風格**，不用白名單。
#
# 第一版寫成白名單（web 類別那三十個），結果把平台專屬的正當類別（例如桌面／
# OS 層的權限繞過、沙箱逃逸）全報成非標準 —— 那些是真正的類別，不是拼寫變體。
# 一個會對正當輸入報警的計數，跟一個永遠是 0 的計數一樣沒用：看的人第二次就不看了。
#
# kebab-case 是本 vault 的慣例。不符合的（含空白、大寫、底線、中日韓字）
# 才是「同一個類別的另一種寫法」的特徵，而那正是要收進別名表的東西。
# 新的正當類別只要照慣例拼寫，就不會被計入。
VULN_CLASS_STYLE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def canonical_vuln_class(value: str) -> str:
    v = (value or "").strip()
    hit = VULN_CLASS_ALIASES.get(v.lower()) or VULN_CLASS_ALIASES.get(v)
    if hit:
        return hit
    # 純英文的大小寫／空白／底線差異只是拼法，不是不同類別：
    # SSRF → ssrf、Security Misconfiguration → security-misconfiguration。
    # 含 `/` 的複合值（"IDOR / Authentication Bypass"）不碰 —— 那要拆成兩筆，
    # 不是改拼法，所以留著讓 nonstandard 計數報出來給人處理。
    if "/" not in v and re.fullmatch(r"[A-Za-z0-9 _-]+", v):
        return re.sub(r"[ _]+", "-", v.lower()).strip("-")
    return v


def nonstandard_vuln_classes(target: str | Path) -> dict[str, str]:
    """finding_id → 正規化後仍不符 kebab-case 慣例的 vuln_class。

    別名表是白名單式映射：沒收進來的新寫法會原樣通過，而且沒有任何地方會說。
    這個函式把它變成可數的 —— 不然下一次有人發現時又是「118 種」。
    報出來的每一筆都有明確的下一步：改成 kebab-case，或把它收進
    VULN_CLASS_ALIASES 指向既有類別。
    """
    from evidence_refs import finding_records
    out = {}
    for fid, rec in finding_records(_events_of(target)).items():
        vc = canonical_vuln_class(str(rec.get("vuln_class") or "")).strip()
        if vc and not VULN_CLASS_STYLE.match(vc):
            out[fid] = vc
    return out


def _events_of(target: str | Path) -> list[dict]:
    from hunt_loop import HuntLoop
    return HuntLoop.load(ledger_path(target)).events


def observation_kinds(target: str | Path) -> dict[str, str]:
    """每個 finding 最後一次申報的觀察類別。"""
    out: dict[str, str] = {}
    for e in HuntLoop.load(ledger_path(target)).events:
        if e.get("finding_id") and e.get("observation_kind"):
            out[str(e["finding_id"])] = str(e["observation_kind"])
    return out


def root_cause_groups(target: str | Path) -> dict[str, list[str]]:
    """同一個 root_cause 底下有多個 finding 的分組。

    送件的單位是**一次修補**，不是一個端點：「廠商能不能只改一處就同時修掉這兩條？」
    能 → 一份報告，步驟舉 2–3 個例子，其餘列 URL。
    某 target 的 一組疑似同源的 findings 是反例：12 個端點疑似同一處沒核租戶，卻各開一條，
    於是看起來像 12 個洞、實際上是 1 個漏套，而且沒有任何欄位說得出這件事。
    """
    groups: dict[str, list[str]] = {}
    for e in HuntLoop.load(ledger_path(target)).events:
        if e.get("finding_id") and e.get("root_cause"):
            groups.setdefault(str(e["root_cause"]), [])
            fid = str(e["finding_id"])
            if fid not in groups[str(e["root_cause"])]:
                groups[str(e["root_cause"])].append(fid)
    return {k: v for k, v in groups.items() if len(v) > 1}


def findings_without_observation_kind(target: str | Path) -> list[str]:
    """已進到 tested 以上、卻沒申報觀察類別的 finding（舊事件的補登缺口）。"""
    kinds = observation_kinds(target)
    ids = {str(e["finding_id"]) for e in HuntLoop.load(ledger_path(target)).events
           if e.get("type") == "finding" and e.get("finding_id")}
    return sorted(fid for fid in ids
                  if finding_state(target, fid) in EVIDENCED_STATES
                  and fid not in kinds)


def advance_finding(target: str | Path, finding_id: str, to: str, *,
                    reason: str = "", **data) -> dict:
    """Advance a finding's state. Validates allowed transitions.
    When transitioning to 'confirmed', auto-emits worker_required events
    for each MANDATORY_WORKERS entry."""
    cur = finding_state(target, finding_id)
    if cur is None:
        return {"ok": False, "reason": f"no finding event for {finding_id}"}
    allowed = FINDING_TRANSITIONS.get(cur, [])
    if to not in allowed:
        return {"ok": False, "reason": f"cannot transition {finding_id}: {cur} -> {to} "
                f"(allowed: {allowed})"}
    # 「碰到了那句後果」要用申報的，不能靠讀 reason 的字猜。
    # evidence_shape_warning 是關鍵字比對而且只警告——其中一筆 finding 就是把參數驗證層的
    # 報錯當成繞過，而那段文字裡沒有任何它認得的詞。改成硬性申報四選一：
    # none 代表只碰到認證層／參數層，那是線索不是漏洞，不得進 tested 以上。
    kind = data.get("observation_kind") or observation_kinds(target).get(finding_id)
    if to in EVIDENCED_STATES:
        if not kind:
            return {"ok": False, "reason":
                    f"{finding_id} -> {to} 需要 --observation-kind "
                    f"{{{'|'.join(OBSERVATION_KINDS)}}}：證據實際碰到了什麼？"}
        if kind not in OBSERVATION_KINDS:
            return {"ok": False, "reason":
                    f"observation_kind={kind!r} 不是 {OBSERVATION_KINDS} 之一"}
        if kind == "none":
            return {"ok": False, "reason":
                    f"{finding_id}: observation_kind=none——只碰到認證層或參數層的回應。"
                    f"那是線索不是漏洞，記 record-verdict 或 Attempt，不要進 {to}。"}
        data.setdefault("observation_kind", kind)
    ev_warning = evidence_shape_warning(to, reason)
    state_payload = {"finding_id": finding_id, "to": to,
                     "from": cur, "reason": reason, **data}
    if ev_warning:
        state_payload["evidence_warning"] = True
    events: list[tuple[str, dict]] = [("finding_state", state_payload)]
    if to in WORKER_TRIGGER_STATES:
        already = _required_workers(target, finding_id)
        for worker in mandatory_workers(target, finding_id):
            if worker not in already:
                events.append(("worker_required", {
                    "finding_id": finding_id, "worker": worker,
                }))
    append_events(target, events)
    result: dict = {"ok": True, "finding_id": finding_id, "from": cur, "to": to}
    if ev_warning:
        result["evidence_warning"] = ev_warning
    if to in WORKER_TRIGGER_STATES:
        result["workers_queued"] = list(mandatory_workers(target, finding_id))
    return result


def _required_workers(target: str | Path, finding_id: str) -> set[str]:
    """Workers ever queued for a finding (done or not) — keeps queueing idempotent."""
    led = ledger_path(target)
    if not led.exists():
        return set()
    return {ev.get("worker", "") for ev in read_ledger_events(led)
            if ev.get("type") == "worker_required" and ev.get("finding_id") == finding_id}


def pending_workers(target: str | Path, finding_id: str | None = None) -> list[dict]:
    """Return worker_required events that have no matching worker_done.
    If finding_id is None, returns all pending workers across all findings."""
    led = ledger_path(target)
    if not led.exists():
        return []
    required: list[dict] = []
    done: set[tuple[str, str]] = set()
    for ev in read_ledger_events(led):
        if ev.get("type") == "worker_required":
            required.append(ev)
        elif ev.get("type") == "worker_done":
            done.add((ev.get("finding_id", ""), ev.get("worker", "")))
    pending = [r for r in required
               if (r.get("finding_id", ""), r.get("worker", "")) not in done]
    # A retracted finding's mandatory workers are moot. Without this, withdrawing a
    # confirmed finding would leave its verb-matrix/chain/expand pending forever and
    # block submission of everything else on the target — a retraction must not cost
    # more than it saves.
    withdrawn = {fid for fid in {r.get("finding_id", "") for r in pending}
                 if finding_state(target, fid) == "withdrawn"}
    pending = [r for r in pending if r.get("finding_id", "") not in withdrawn]
    if finding_id is not None:
        pending = [r for r in pending if r.get("finding_id") == finding_id]
    return pending


def complete_worker(target: str | Path, finding_id: str, worker: str, *,
                    reason: str = "", **data) -> dict:
    """Mark a mandatory worker as done for a finding."""
    if worker not in MANDATORY_WORKERS:
        return {"ok": False, "reason": f"unknown worker: {worker} (valid: {MANDATORY_WORKERS})"}
    cur = finding_state(target, finding_id)
    if cur not in WORKER_TRIGGER_STATES:
        return {"ok": False, "reason": f"{finding_id} is not adversary-verified/confirmed (state: {cur})"}
    # Prerequisite: node-level verb coverage before chaining/expanding. Only applies
    # when verb-matrix was actually required for this finding (older confirmed findings
    # predate it, so they are unaffected).
    if worker in ("chain", "expand"):
        pend = {r.get("worker") for r in pending_workers(target, finding_id)}
        if "verb-matrix" in pend:
            return {"ok": False, "reason":
                    f"verb-matrix 未完成——先測完讀寫全動詞矩陣（GET + PUT/PATCH/DELETE、"
                    f"物件 ID 變體、跨租戶）再 close '{worker}'（別停在 GET）。"
                    f" 不適用就豁免：python3 automation/asg.py complete-worker "
                    f"{_basename(target)} {finding_id} verb-matrix \"n/a: <為何無 object/write path>\""}
    append_event(target, "worker_done", finding_id=finding_id, worker=worker,
                 reason=reason, **data)
    remaining = pending_workers(target, finding_id)
    return {"ok": True, "finding_id": finding_id, "worker": worker,
            "remaining": [r.get("worker") for r in remaining]}


def queue_workers(target: str | Path, finding_ids: "list[str] | None" = None) -> dict:
    """Backfill worker_required for deliverable findings that never had them queued
    (reached adversary-verified/confirmed before WORKER_TRIGGER_STATES existed).
    No ids → every such finding on the target. Idempotent."""
    state = read_state(target)
    current = {f["id"]: f.get("status") for f in state["findings"]}
    ids = finding_ids or [fid for fid, st in current.items() if st in WORKER_TRIGGER_STATES]
    queued: dict[str, list[str]] = {}
    skipped: dict[str, str] = {}
    events: list[tuple[str, dict]] = []
    for fid in ids:
        st = current.get(fid)
        if st not in WORKER_TRIGGER_STATES:
            skipped[fid] = f"state={st}"
            continue
        already = _required_workers(target, fid)
        new = [w for w in mandatory_workers(target, fid, state=state) if w not in already]
        events += [("worker_required", {"finding_id": fid, "worker": w, "backfill": True})
                   for w in new]
        if new:
            queued[fid] = new
    if events:
        append_events(target, events)
    return {"ok": True, "queued": queued, "skipped": skipped}


def _existing_resolves(target: str | Path, finding_id: str) -> list[str]:
    """Return the most recent resolves list for a finding, or [] if none."""
    led = ledger_path(target)
    if not led.exists():
        return []
    result: list[str] = []
    for ev in read_ledger_events(led):
        if ev.get("type") == "finding" and ev.get("finding_id") == finding_id:
            if "resolves" in ev:
                result = ev["resolves"]
    return result


def record_finding(target: str | Path, finding_id: str, *,
                   resolves: "list[str] | tuple[str, ...]" = (), **data) -> dict:
    """Record a new finding and, atomically, close out the surfaces it settles.

    Why `resolves` (2026-10-01, 某 target): a `finding` event carried nothing but an id,
    so recording a finding moved NOTHING in the coverage projection. 某 target reached
    55 findings with 96/96 surfaces still `untested` and 0 settled — the report-phase
    coverage floor then blocked a target that had in fact been tested hard for a week.
    The ledger already flips a surface (a `surface` event with untested=False); what
    was missing was any way for a finding to say which surface it came from. The
    perverse result was that the more faithfully an operator followed "stub = a ledger
    event", the worse the coverage number got.

    `resolves` holds surface names exactly as the ledger spells them; unknown names are
    still recorded on the finding but flip nothing and come back in `unknown_surfaces`,
    so a typo degrades to a reported no-op rather than to silent corruption.

    Idempotent: refuses if the finding already exists.
    """
    existing = finding_state(target, finding_id)
    if existing is not None:
        return {"ok": False, "reason": f"{finding_id} already in ledger (state: {existing})"}
    if data.get("vuln_class"):
        data["vuln_class"] = canonical_vuln_class(str(data["vuln_class"]))
    known = surface_state(target)
    names = [str(r) for r in resolves]
    if not names:
        import sys as _sys
        _sys.stderr.write(
            f"⚠️  record-finding {finding_id} 沒帶 --resolves。"
            f" 覆蓋率不會動——之後需 --amend --resolves 補回。\n"
        )
    settled = [n for n in names if n in known]
    unknown = [n for n in names if n not in known]
    events: list[tuple[str, dict]] = [
        ("finding", {"finding_id": finding_id, "resolves": names, **data})
    ]
    events += [("surface", {"name": n, "untested": False}) for n in settled]
    append_events(target, events)
    result = {"ok": True, "finding_id": finding_id, "state": "hypothesis",
              "surfaces_settled": settled, "unknown_surfaces": unknown}
    # A new capability is only worth something if it is spent: name the blocked
    # surfaces it opens now, while the operator still has the context to retest them.
    provides = {str(c) for c in (data.get("provides") or [])}
    if provides:
        before = set(surfaces_unlockable(target))
        result["would_unlock"] = sorted(
            s for s in surfaces_unlockable(target, extra_caps=provides) if s not in before)
    return result


# ── SOLE WRITER ─────────────────────────────────────────────────────────────
def append_events(target: str | Path, events: list[tuple[str, dict]], *,
                  owner: Optional[str] = None) -> None:
    """Append a batch of events under ONE lock acquisition (atomic save). The
    single write path for the ledger — one-off writers use append_event()."""
    led = ledger_path(target)
    led.parent.mkdir(parents=True, exist_ok=True)
    owner = owner or os.environ.get("CLAUDE_MODEL", "asg")
    token = acquire(led, owner)
    # Events carried no time of their own, so "this verdict is N days old" could not
    # be computed at all — the session brief was asserting a 14-day staleness rule
    # against a number nothing could produce. Stamp new events so that window can
    # eventually be derived from evidence instead of invented. Existing events stay
    # as they are; anything reading `at` must treat it as optional.
    import datetime as _dt
    now = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
    try:
        loop = HuntLoop.load(led)
        for kind, data in events:
            data = dict(data)
            data.setdefault("at", now)
            if "evidence" in data:
                data["evidence"] = normalize_evidence(
                    data["evidence"], led.parent.parent,
                    data.get("verification_environment") or data.get("environment"),
                    events=loop.events, subject=data.get("hypothesis"), provides=data.get("provides") or [])
            from asg_research import normalize_event
            data = normalize_event(kind, data, loop)
            loop.append(kind, **data)
        guarded_save(loop, led, token)
    finally:
        release(led, token)


def append_event(target: str | Path, kind: str, *, owner: Optional[str] = None,
                 **data) -> None:
    """The ONLY way to write a single ASG state event. Resolves the ledger, takes
    the single-writer lock, appends, guard-saves, releases. Raises
    hunt_lock.ConcurrentWriter if another live writer holds the ledger."""
    append_events(target, [(kind, data)], owner=owner)


# ── MIGRATION: existing YAML-schema Markdown ASG -> ledger events ────────────
def migrate_yaml_to_ledger(target: str | Path) -> dict:
    """Best-effort, IDEMPOTENT import of a hand-maintained YAML-schema ASG onto the
    ledger, so the ledger becomes the authority while the Markdown stays readable.

    Faithful mapping (not lossless): capability_state(confirmed) -> a confirmed
    verdict carrying a subject-bound migration receipt (the old model's confirmed = 已成功
    利用, so it keeps the evidence invariant, transparently labelled); nodes ->
    surfaces; findings(validated) -> confirmed hypotheses; dead edges -> dead_ends.
    Re-running with unchanged Markdown is a no-op (content digest guard)."""
    import hashlib
    from surface_graph_lib import load_graph, _real_nodes, node_identifier

    md = markdown_path(target)
    if not md.exists():
        return {"migrated": 0, "reason": "no Markdown ASG to migrate"}
    graph = load_graph(str(md))
    if not graph:
        return {"migrated": 0, "reason": "no YAML block in Markdown ASG"}
    # digest the PARSED YAML source, not the whole file — so projecting a generated
    # block into the Markdown later does not change it and break idempotency.
    digest = hashlib.sha256(json.dumps(graph, sort_keys=True, default=str).encode()).hexdigest()
    led = ledger_path(target)
    prior = HuntLoop.load(led) if led.exists() else HuntLoop([])
    if any(e.get("type") == "migration" and e.get("digest") == digest for e in prior.events):
        return {"migrated": 0, "reason": "already migrated (same content)"}

    existing_ids: set[str] = set()
    for ev in prior.events:
        for key in ("name", "id"):
            if key in ev:
                existing_ids.add(str(ev[key]))

    proof = {"kind": "reference", "id": f"migration:{digest}",
             "environment": {"source": "legacy_yaml", "path": str(md)}}
    receipt = {"source": "yaml", "digest": digest, "claims": {}}
    events: list[tuple[str, dict]] = [("migration", receipt)]
    for n in _real_nodes(graph):
        nid = str(node_identifier(n))
        if nid not in existing_ids:
            events.append(("surface", {"name": nid, "untested": True}))
    for cap in graph.get("capability_state", []) or []:
        if isinstance(cap, dict) and cap.get("cap") and cap.get("state", "confirmed") == "confirmed":
            c = str(cap["cap"]); hid = f"migrated:{c}"
            if hid not in existing_ids:
                receipt["claims"][hid] = [c]
                events.append(("hypothesis", {"id": hid, "requires": []}))
                events.append(("verdict", {"hypothesis": hid, "status": "confirmed",
                                            "evidence": {**proof, "subject": hid},
                                            "provides": [c]}))
    for f in graph.get("findings", []) or []:
        fid = isinstance(f, dict) and f.get("id")
        if not fid:
            continue
        hid = f"finding:{fid}"
        if hid not in existing_ids:
            events.append(("finding", {**f, "finding_id": str(fid),
                                       "legacy_status": f.get("status", ""),
                                       "verification_environment": "legacy_yaml"}))
            events.append(("hypothesis", {"id": hid, "requires": list(f.get("requires", []) or [])}))
            if f.get("status") == "validated":
                receipt["claims"][hid] = list(f.get("provides", []) or [])
                events.append(("verdict", {"hypothesis": hid, "status": "confirmed",
                                            "evidence": {**proof, "subject": hid},
                                            "provides": list(f.get("provides", []) or [])}))
    for e in graph.get("edges", []) or []:
        if isinstance(e, dict) and e.get("status") == "dead":
            hid = f"edge:{e.get('src')}->{e.get('dst')}"
            if hid not in existing_ids:
                events.append(("dead_end", {"hyp_id": hid, "cause": "refuted",
                                            "reason": e.get("reason", ""),
                                            "reopen_when": "a new capability / variant"}))
    new_count = len(events) - 1
    if new_count > 0:
        append_events(target, events)
    return {"migrated": new_count, "digest": digest}


# ── PROJECTIONS (one-way, from the ledger) ──────────────────────────────────
def _summary(target: str | Path, *, state: Optional[dict] = None) -> dict:
    """Materialize the capsule + resume view once, for both projections."""
    state = read_state(target) if state is None else state
    return {"loop": state["loop"], "cap": state["capsule"],
            "brief": state["brief"], "dead_paths": state["dead_paths"], "state": state}


# ── VERDICT CONFIDENCE + CHAIN PROJECTION ─────────────────────────────────
# Verdict confidence levels: how the verdict was obtained
CONFIDENCE_LEVELS = ("theoretical", "static", "dynamic", "reproduced")


def chain_projection(target: str | Path) -> dict:
    """Compute attack chain graph from meta events + capability edges.
    Returns root-cause groups, chain edges, and a confidence breakdown."""
    led = ledger_path(target)
    if not led.exists():
        return {"chains": [], "root_cause_groups": [], "confidence": {}}

    hypotheses = {}
    verdicts = {}
    meta_edges = []
    cap_requires = {}

    state = read_state(target)
    for e in state["loop"].events:
        if e["type"] == "hypothesis":
            hid = e.get("id", "")
            hypotheses[hid] = e.get("claim", "")
            reqs = e.get("requires", [])
            if reqs:
                cap_requires[hid] = reqs
        elif e["type"] == "verdict":
            verdicts[e.get("hypothesis", "")] = {
                "status": e.get("status", ""),
                "severity": e.get("severity", ""),
                "confidence": e.get("confidence", "static"),
            }
        elif e["type"] == "meta":
            action = e.get("action", "")
            src = e.get("hypothesis", "")
            if action == "variant_of":
                meta_edges.append(("variant", src, e.get("variant_of", "")))
            elif action == "chain":
                meta_edges.append(("chain", src, e.get("chain", "")))
            elif action == "enrichment_of":
                meta_edges.append(("enrichment", src, e.get("enrichment_of", "")))

    # Connected components for root-cause grouping
    from collections import defaultdict
    adj: dict[str, set] = defaultdict(set)
    for etype, src, dst in meta_edges:
        if etype == "variant":
            adj[src].add(dst)
            adj[dst].add(src)
        elif etype == "enrichment":
            adj[src].add(dst)

    visited: set[str] = set()
    groups = []
    for node in hypotheses:
        if node in visited:
            continue
        group: set[str] = set()
        stack = [node]
        while stack:
            n = stack.pop()
            if n in visited:
                continue
            visited.add(n)
            group.add(n)
            for neighbor in adj.get(n, set()):
                if neighbor not in visited:
                    stack.append(neighbor)
        if len(group) > 1:
            groups.append(sorted(group))

    # Confidence breakdown
    conf_counts: dict[str, int] = defaultdict(int)
    for v in verdicts.values():
        conf_counts[v.get("confidence", "static")] += 1

    return {
        "meta_edges": [{"type": t, "src": s, "dst": d} for t, s, d in meta_edges],
        "root_cause_groups": groups,
        "total_hypotheses": len(hypotheses),
        "unique_root_causes": len(hypotheses) - sum(len(g) - 1 for g in groups),
        "confidence_breakdown": dict(conf_counts),
        "capability_dependencies": cap_requires,
    }


def auto_chain(target: str | Path, *, state: Optional[dict] = None) -> dict:
    """Auto-compute attack chains from CG requires/provides + meta edges.
    Returns chain graph data + Mermaid flowchart."""
    led = ledger_path(target)
    if state is None:
        state = read_state(target)
    if state["source"] != "ledger":
        return {"entry_points": [], "chain_edges": [], "capabilities": [],
                "total_confirmed": 0, "nodes_in_graph": 0, "mermaid": ""}

    from collections import defaultdict

    hyps: dict[str, dict] = {
        p["name"]: {"claim": p.get("claim", ""), "requires": p.get("requires", []),
                    "provides": [], "severity": p.get("severity", ""), "status": p.get("status", "")}
        for p in state["paths"]
    }
    meta_edges: list[tuple[str, str, str]] = []

    for e in state["loop"].events:
        if e["type"] == "hypothesis":
            hid = e.get("id", "")
            prev = hyps.get(hid, {})
            hyps[hid] = {
                "claim": e.get("claim", "") or prev.get("claim", ""),
                "requires": e.get("requires", prev.get("requires", [])),
                "provides": prev.get("provides", []),
                "severity": e.get("severity", "") or prev.get("severity", ""),
                "status": prev.get("status", ""),
            }
        elif e["type"] == "verdict":
            hid = e.get("hypothesis", "")
            if hid in hyps:
                hyps[hid]["status"] = e.get("status", "")
                hyps[hid]["severity"] = e.get("severity", "") or hyps[hid]["severity"]
                hyps[hid]["provides"] = e.get("provides", [])
        elif e["type"] == "meta":
            action = e.get("action", "")
            src = e.get("hypothesis", "")
            if action == "variant_of":
                meta_edges.append(("variant", src, e.get("variant_of", "")))
            elif action == "chain":
                meta_edges.append(("chain", src, e.get("chain", "")))
            elif action == "enrichment_of":
                meta_edges.append(("enrichment", src, e.get("enrichment_of", "")))

    effective = state["capsule"]
    live_caps = set(effective["capabilities"])
    confirmed = {h: {**d, "provides": [c for c in effective["confirmed"][h] if c in live_caps]}
                 for h, d in hyps.items() if h in effective["confirmed"]}

    cap_providers: dict[str, list[str]] = defaultdict(list)
    cap_consumers: dict[str, list[str]] = defaultdict(list)
    for hid, data in confirmed.items():
        for cap in data["provides"]:
            cap_providers[cap].append(hid)
        for cap in data["requires"]:
            cap_consumers[cap].append(hid)

    entry_points = sorted(h for h, d in confirmed.items() if not d["requires"])

    chain_edges = []
    for cap in cap_providers:
        for provider in cap_providers[cap]:
            for consumer in cap_consumers.get(cap, []):
                chain_edges.append({"from": provider, "capability": cap, "to": consumer})

    all_caps = set()
    for d in confirmed.values():
        all_caps.update(d["provides"])

    # Determine which nodes belong in the graph
    in_graph: set[str] = set()
    for hid, d in confirmed.items():
        if d["provides"] or d["requires"]:
            in_graph.add(hid)
    for _, src, dst in meta_edges:
        if src in confirmed:
            in_graph.add(src)
        if dst in confirmed:
            in_graph.add(dst)
    for e in chain_edges:
        in_graph.add(e["from"])
        in_graph.add(e["to"])

    # Generate Mermaid
    lines = ["graph TD"]
    lines.append("    classDef p1 fill:#dc2626,color:white,stroke:#991b1b")
    lines.append("    classDef p2 fill:#ea580c,color:white,stroke:#c2410c")
    lines.append("    classDef p3 fill:#ca8a04,color:black,stroke:#a16207")
    lines.append("    classDef cap fill:#2563eb,color:white,stroke:#1d4ed8,stroke-dasharray:5")

    # Capability nodes
    for cap in sorted(all_caps):
        cid = "CAP_" + re.sub(r"[^a-zA-Z0-9]", "_", cap)
        lines.append(f'    {cid}(("{cap}")):::cap')

    # Hypothesis nodes
    for hid in sorted(in_graph):
        if hid not in confirmed:
            continue
        sev = confirmed[hid]["severity"] or "?"
        sc = "p1" if sev == "P1" else "p2" if sev == "P2" else "p3"
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", hid)
        lines.append(f'    {safe}["{hid} {sev}"]:::{sc}')

    # Provides edges
    for hid in sorted(in_graph):
        if hid not in confirmed:
            continue
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", hid)
        for cap in confirmed[hid]["provides"]:
            cid = "CAP_" + re.sub(r"[^a-zA-Z0-9]", "_", cap)
            lines.append(f"    {safe} -->|provides| {cid}")

    # Requires edges
    for hid in sorted(in_graph):
        if hid not in confirmed:
            continue
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", hid)
        for cap in confirmed[hid]["requires"]:
            cid = "CAP_" + re.sub(r"[^a-zA-Z0-9]", "_", cap)
            lines.append(f"    {cid} -->|enables| {safe}")

    # Meta edges
    for mtype, src, dst in meta_edges:
        ss = re.sub(r"[^a-zA-Z0-9_-]", "_", src)
        dd = re.sub(r"[^a-zA-Z0-9_-]", "_", dst)
        if src not in in_graph and src in confirmed:
            sev = confirmed[src]["severity"] or "?"
            sc = "p1" if sev == "P1" else "p2" if sev == "P2" else "p3"
            lines.append(f'    {ss}["{src} {sev}"]:::{sc}')
            in_graph.add(src)
        if dst not in in_graph and dst in confirmed:
            sev = confirmed[dst]["severity"] or "?"
            sc = "p1" if sev == "P1" else "p2" if sev == "P2" else "p3"
            lines.append(f'    {dd}["{dst} {sev}"]:::{sc}')
            in_graph.add(dst)
        if mtype == "variant":
            lines.append(f"    {ss} -.->|variant-of| {dd}")
        elif mtype == "chain":
            lines.append(f"    {ss} ==>|chain| {dd}")
        elif mtype == "enrichment":
            lines.append(f"    {ss} -.->|enriches| {dd}")

    return {
        "entry_points": entry_points,
        "chain_edges": chain_edges,
        "capabilities": sorted(all_caps),
        "total_confirmed": len(confirmed),
        "nodes_in_graph": len(in_graph),
        "mermaid": "\n".join(lines),
    }


def write_snapshot(target: str | Path) -> Path:
    """Frontmatter/Dataview-friendly JSON snapshot of current state."""
    s = _summary(target); cap = s["cap"]; brief = s["brief"]
    chains = auto_chain(target, state=s["state"])
    snap = {
        "target": _basename(target),
        "run_state": brief["run_state"],
        "event_cursor": cap["event_cursor"],
        "capabilities": cap["capabilities"],
        "hypotheses_ready": len(cap["ready_hypotheses"]),
        "hypotheses_blocked": len(cap["blocked_hypotheses"]),
        "disputed": len(cap["disputed"]),
        "evidence_rejected": len(cap["evidence_rejected"]),
        "dead_paths": len(s["dead_paths"]),
        "untested_surface": len(cap["untested_surface"]),
        "next_action": brief["next_action"],
        "chain_edges": len(chains["chain_edges"]),
        "chain_entry_points": len(chains["entry_points"]),
        "chain_capabilities": len(chains["capabilities"]),
        "research": s["state"]["research"]["summary"],
    }
    p = snapshot_path(target)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def _render_generated(target: str | Path, *, state: Optional[dict] = None) -> str:
    s = _summary(target, state=state); cap = s["cap"]; brief = s["brief"]
    chains = auto_chain(target, state=s["state"])
    def block(title, items):
        body = "\n".join(f"- {i}" for i in items) if items else "- —"
        return f"### {title}\n{body}"
    dead = [f"{d['hyp_id']} ({d.get('cause', '?')}) — reopen: {d.get('reopen_when', '?')}"
            for d in s["dead_paths"]]
    chain_items: list[str] = []
    if chains["chain_edges"]:
        from collections import Counter
        cap_counts = Counter(e["capability"] for e in chains["chain_edges"])
        chain_items.append(
            f"{len(chains['chain_edges'])} edges, "
            f"{len(chains['entry_points'])} entry points, "
            f"{len(chains['capabilities'])} capabilities"
        )
        for cap_name, cnt in cap_counts.most_common(5):
            chain_items.append(f"  {cap_name}: {cnt}")
    blocks = [
        "_generated from `.state/asg-events.jsonl` — do not edit inside this block; "
        "write below in Operator Notes_",
        f"### Current Frontier\n- run_state: **{brief['run_state']}**  (events: {cap['event_cursor']})\n"
        f"- next: {brief['next_action']}",
        block("Capabilities (CG)", cap["capabilities"]),
        block("Attack Chains (auto-computed)", chain_items),
        block("Work Queue (DAG) — ready", cap["ready_hypotheses"]),
        block("Blocked", cap["blocked_hypotheses"]),
        block("Disputed", cap["disputed"]),
        block("Evidence repair required", sorted(cap["evidence_rejected"])),
        block("Dead Paths (don't re-tread; see reopen)", dead),
    ]
    if s["state"]["research"]["enabled"]:
        blocks.append(research_markdown(s["state"]["research"]))
    return "\n\n".join(blocks)


def research_markdown(graph: dict) -> str:
    """A human view of the same provenance revision, never an editable queue."""
    if not graph["enabled"]:
        return ""
    lines = ["### Research Goals and Lineage"]
    for node in graph["nodes"]:
        if node["kind"] in {"goal", "intent", "hint"}:
            status = node.get("effective_state", node.get("state"))
            text = str(node["text"]).replace("\n", " ")
            lines.append(f"- **{node['ref']}** [{status}] {text}")
    for digest in graph["digests"]:
        lines.append(f"- **{digest['ref']}** [{digest['state']}] {digest['text'].replace(chr(10), ' ')}")
    for edge in graph["edges"]:
        suffix = " [stale]" if edge.get("valid") is False else ""
        lines.append(f"- `{edge['src']}` —{edge['rel']}→ `{edge['dst']}`{suffix}")
    return "\n".join(lines)


def project_markdown(target: str | Path) -> Path:
    """Render the generated block into the Markdown ASG, preserving everything
    outside the ASG:GENERATED markers (the operator's own content). Creates the
    file with an Operator Notes section if absent."""
    generated = f"{GEN_START}\n{_render_generated(target)}\n{GEN_END}"
    md = markdown_path(target)
    if md.exists():
        txt = md.read_text(encoding="utf-8")
        if GEN_START in txt and GEN_END in txt:
            txt = re.sub(re.escape(GEN_START) + r".*?" + re.escape(GEN_END),
                         lambda _m: generated, txt, count=1, flags=re.DOTALL)
        else:
            # operator file with no generated block yet: append, never overwrite
            txt = txt.rstrip() + "\n\n" + generated + "\n"
        md.write_text(txt, encoding="utf-8")
    else:
        fm = (f"---\nfileClass: AttackSurfaceGraph\ntarget: {_basename(target)}\n"
              f"generated_from: .state/asg-events.jsonl\n---\n\n")
        md.parent.mkdir(parents=True, exist_ok=True)
        md.write_text(f"{fm}# Attack Surface Graph - {_basename(target)}\n\n"
                      f"{generated}\n\n## Operator Notes\n\n", encoding="utf-8")
    return md


# ── SURFACE DISPOSITION: derived state, never hand-maintained ───────────────
# Why (2026-09-21, SonicDX): the hand-written YAML carried `disposition: untested`
# on every node, frozen at the day the graph was drawn. Nobody updated it and
# nobody read it, so it was a write-only field that actively lied — surfaces with
# a recorded `confirmed` verdict still advertised themselves as untested, and
# next_action kept pointing at work that was already done. The ledger already
# supports flipping a surface (`surface` event with untested=False,
# hunt_loop.py:151); what was missing was anything that used it. So: verdicts may
# now declare which surfaces they settle, and `disposition` becomes a projection.

def needs_human_go_queue(target: str | Path) -> list[dict]:
    """The open human-authorization queue, projected from the ledger.

    autodrive appends a `needs_human_go` event when it defers a write/service-impact
    action (the unattended loop keeps running read-only work). This returns the still-open
    ones — a deferred action is CLEARED once its hypothesis gets any verdict (someone
    authorized + ran it, or it was otherwise resolved). Newest-first, deduped by hyp_id.
    """
    loop = HuntLoop.load(ledger_path(target))
    resolved: set[str] = set()
    for e in loop.events:
        if e.get("type") == "verdict" and e.get("hypothesis"):
            if str(e.get("status", "")).strip() in ("confirmed", "refuted", "inconclusive"):
                resolved.add(str(e["hypothesis"]))
    # a human decision (go that then ran → verdict clears it; decline → clear now) also
    # resolves the queue entry. Latest human_go decision per hyp_id wins.
    hg_latest: dict[str, str] = {}
    for e in loop.events:
        if e.get("type") == "human_go" and e.get("hyp_id"):
            d = str(e.get("decision", "")).strip()
            if d in ("go", "decline"):
                hg_latest[str(e["hyp_id"])] = d
    resolved |= {h for h, d in hg_latest.items() if d == "decline"}
    open_q: dict[str, dict] = {}
    for e in loop.events:
        if e.get("type") != "needs_human_go" or not e.get("hyp_id"):
            continue
        hid = str(e["hyp_id"])
        if hid in resolved:
            open_q.pop(hid, None)
            continue
        open_q[hid] = {"hyp_id": hid, "risk": e.get("risk", ""),
                       "action": e.get("action", ""), "surface": e.get("surface"),
                       "invariant": e.get("invariant", "")}
    return list(reversed(list(open_q.values())))


def link_finding_doc(target: str | Path, finding_id: str, doc: str) -> dict:
    """Point a ledger finding at the Finding markdown that writes it up.

    record_finding refuses to touch a finding that already exists (idempotency), so a
    finding recorded without `--doc` could never acquire one afterwards. That left the
    55 某 target ledger findings permanently unlinkable and made the drift report
    un-actionable for exactly the backlog it had just found. `doc` is relative to the
    target directory and must exist — a link to a file that is not there is the same
    bookkeeping lie the drift check exists to catch.
    """
    if finding_state(target, finding_id) is None:
        return {"ok": False, "reason": f"no finding event for {finding_id}"}
    rel = str(doc).strip()
    if not (target_dir(target) / rel).exists():
        return {"ok": False, "reason": f"doc 不存在於 target 目錄下: {rel}"}
    append_event(target, "finding_doc", finding_id=finding_id, doc=rel)
    return {"ok": True, "finding_id": finding_id, "doc": rel}


def backfill_genesis(target: str | Path, *, profile: str = "web",
                     dry_run: bool = False, **data) -> dict:
    """Give a pre-gate ledger the opening record it never got.

    Why (2026-10-01): 15 of the 18 ledgers in the vault had no genesis event. 另一個 target
    carried 331 events and 119 settled surfaces, and `asg.py status 另一個 target` still
    answered `{"error": "no genesis for 另一個 target"}` — so the documented single source
    of numbers was unusable for 15/18 targets, and engage_gate blocked active work on
    ledgers that plainly recorded a completed hunt. The work happened; only the opening
    record is missing, because these targets predate the engage gate.

    The event is stamped `backfilled: true` and backdated to the ledger's earliest
    event, so it never claims the target started today and a reader can always tell it
    from a genesis an operator actually wrote at engage time.
    """
    led = ledger_path(target)
    if not led.exists():
        return {"ok": False, "reason": f"no ledger for {target}"}
    existing = has_genesis(target)
    if existing:
        return {"ok": False, "reason": "already has a genesis", "genesis": existing}
    first_at = ""
    events = read_ledger_events(led)
    first_at = events[0].get("at", "") or "" if events else ""
    ev = {"profile": profile, "backfilled": True,
          "note": "backfilled by asg.py backfill-genesis; predates the engage gate",
          **data}
    if first_at:
        ev["at"] = first_at
    if dry_run:
        return {"ok": True, "dry_run": True, "target": _basename(target), "event": ev}
    append_event(target, "genesis", **ev)
    return {"ok": True, "target": _basename(target), "profile": profile,
            "backdated_to": first_at or "(now)"}


def known_node_types() -> tuple[set[str], str]:
    """The node_type vocabulary, read from the must-test packs (never duplicated here).

    Returns (types, error). An empty set with an error means the vocabulary could not be
    loaded — callers accept the type rather than blocking all work on a KB parse error.
    """
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import technique_pack  # noqa: PLC0415 — optional, resolved at call time
        types = {t.lower() for p in technique_pack.load_packs() for t in p["node_types"]}
        return types, ""
    except Exception as exc:  # KB missing, renamed, or unparseable
        return set(), f"{type(exc).__name__}: {exc}"


# Types that route to the broad packs only. A surface stuck here was registered but never
# characterised: "this host exists" is not "this host has an upload form".
_GENERIC_NODE_TYPES = {"endpoint", "param", "service"}


def findings_on_hold(target: str | Path) -> dict[str, str]:
    """明確標示「現在不要送」的 finding → 理由。

    為什麼需要：某 target 的 一組疑似同源的 findings 全部卡在「過了中介層、沒證明 impact」，
    要驗證需要一個隸屬租戶的帳號，而該計畫的官方簡報第 4 頁明文「本次不提供測試帳號」。
    它們既不是成立、也不是死路，而是**在可見的未來都驗不了**。

    沒有這個狀態的話，它們就只是靜靜躺在 ledger 裡等人批量灌 FORM——而批量送出
    一批「我進得去但證明不了影響」的通報，傷害的是整批送件的可信度，不只是那幾件。
    hold 讓「刻意不送」與「忘了送」分得開。
    """
    loop = HuntLoop.load(ledger_path(target))
    out: dict[str, str] = {}
    for e in loop.events:
        if e.get("type") != "finding" or not e.get("finding_id"):
            continue
        fid = str(e["finding_id"])
        if e.get("submit_unhold"):
            out.pop(fid, None)
        elif e.get("submit_hold"):
            out[fid] = str(e["submit_hold"])
    return out


def findings_without_claim(target: str | Path) -> list[str]:
    """記了 finding 事件、但沒說「預期影響」或「實際看到什麼」的 stub。

    stub 的用意是「一行記下來、立刻測下一個」，重文件延後——那是對的。
    但延後的只能是**文字**，不能是**主張**：沒有 expected_impact 就無從判斷這條值不值得
    追；沒有 observed 就分不出「拿到資料」與「只是過了中介層」。
    某 target 的 一組疑似同源的 findings 全卡在「過了 auth、沒證明 impact」，而 其中一筆 finding 是
    false positive——兩者都是因為 stub 只記了「有東西」，沒記「我看到什麼」。

    這是 bug bounty 版的 LL-302：把 `code 0` 讀成「查詢已發動」。
    """
    loop = HuntLoop.load(ledger_path(target))
    latest: dict[str, dict] = {}
    for e in loop.events:
        if e.get("type") == "finding" and e.get("finding_id"):
            cur = latest.setdefault(str(e["finding_id"]), {})
            for k in ("expected_impact", "observed"):
                if e.get(k):
                    cur[k] = e[k]
    return sorted(fid for fid, d in latest.items()
                  if not d.get("expected_impact") or not d.get("observed"))


def surface_blocked(target: str | Path) -> dict[str, str]:
    """被某一層擋住、因此**後面的程式碼完全沒被測到**的面 → 原始拒絕訊息。

    與 untested 分開記的理由：untested 是「還沒去」，blocked 是「去了，進不去」。
    兩者在覆蓋率上的意義完全不同，而把 blocked 記成 tested 會留下假綠燈——
    實例:某產品的上傳端點 10 個副檔名變體全被「上傳檔必傳租戶」擋下,
    副檔名與 Content-Type 的檢查強度**一次都沒被測到**，記成「測過且安全」就是說謊。
    見 LL-310：「不可驗」是當時的能力狀態，不是漏洞的性質。

    繞過向量：technique_pack.py for-block "<訊息>"
    """
    loop = HuntLoop.load(ledger_path(target))
    out: dict[str, str] = {}
    for e in loop.events:
        if e.get("type") != "surface" or not e.get("name"):
            continue
        name = str(e["name"])
        if e.get("blocked"):
            out[name] = str(e["blocked"])
        elif name in out and not e.get("blocked"):
            out.pop(name, None)   # 後續事件沒有 blocked = 已解除
    return out


def surface_blocked_by(target: str | Path) -> dict[str, list[str]]:
    """Blocked surfaces → the capabilities they wait on (`add-surface --blocked-by`).

    Why (2026-10-09 某 target): a forged-app-token capability was on record from 09-30,
    but the surfaces it opened only carried a free-text `blocked` reason, so nothing
    could join "capability now available" to "surface waiting for it". The highest-value
    finding of the engagement surfaced two weeks later, only after the
    operator asked whether the ASG was being used. Same last-event semantics as
    surface_blocked: a later event without `blocked` clears it.
    """
    loop = HuntLoop.load(ledger_path(target))
    out: dict[str, list[str]] = {}
    for e in loop.events:
        if e.get("type") != "surface" or not e.get("name"):
            continue
        name = str(e["name"])
        if e.get("blocked") and e.get("blocked_by"):
            out[name] = [str(c) for c in e["blocked_by"]]
        elif not e.get("blocked"):
            out.pop(name, None)
    return out


def available_capabilities(target: str | Path, *, state: Optional[dict] = None) -> set[str]:
    """Capabilities worth spending now: confirmed capability_state, evidence-backed
    `provides`, and the *declared* provides of findings past `tested`. Declared ones
    count here (not in capability_view) because the use is "which blocked surfaces to
    retest", and that retest is itself what verifies the capability."""
    state = state if state is not None else read_state(target)
    caps = {str(c["cap"]) for c in state.get("capability_state", [])
            if isinstance(c, dict) and c.get("cap") and c.get("state", "confirmed") == "confirmed"}
    for f in state.get("findings", []):
        if f.get("status") not in ("withdrawn", "dead_end", "hypothesis", "tested", "disputed"):
            caps |= {str(c) for c in (f.get("provides") or [])}
            caps |= {str(c) for c in (f.get("declared_provides") or [])}
    return caps


def surfaces_unlockable(target: str | Path, *, state: Optional[dict] = None,
                        extra_caps: "set[str] | None" = None) -> dict[str, list[str]]:
    """Blocked surfaces whose every awaited capability is now available → retest them."""
    have = available_capabilities(target, state=state) | set(extra_caps or ())
    return {s: caps for s, caps in surface_blocked_by(target).items() if set(caps) <= have}


# 「影響依賴型」漏洞類別：技術缺口成立**不等於**有影響，價值完全取決於攻擊者
# 能不能在「受害者零額外動作」的前提下把人帶到那條程式碼路徑。
#
# 為什麼要有這張表（來自一次實測）：
#   兩天、數十筆裁決、數十個 PoC、0 個可送件 finding。多條線的死因完全相同——
#   缺口是真的，但要發作，受害者得先自己執行某個非預設的本機操作。
#   一般使用路徑全部正常。缺口真、影響零。
#   而這件事**在每條線的第一分鐘就看得出來**，卻每次都是做完才寫在結論段。
#
# 送件端早就有硬擋（lint_frontmatter 的 delivery_vector），擋不住的是
# 「把兩天投進一個註定沒有影響的面」。所以把同一個問題問在**開挖端**。
IMPACT_DEPENDENT_CLASSES = {
    "gatekeeper-bypass", "tcc-bypass", "sandbox-escape", "codesign-bypass",
    "notarization-bypass", "quarantine-propagation", "service-sandbox-quarantine",
    "metadata-filter-bypass", "provenance-bypass",
}


def is_impact_dependent(vuln_class: str) -> bool:
    """影響依賴型？`quarantine-*` 整族都算（傳播／標記／繼承各種拼法）。"""
    v = canonical_vuln_class(vuln_class or "").strip().lower()
    if not v:
        return False
    return v in IMPACT_DEPENDENT_CLASSES or v.startswith("quarantine-")


def surface_delivery(target: str | Path) -> dict[str, str]:
    """每個面最後一次申報的投遞路徑。`none` 是**合法值**，不是缺漏。

    與 `surface_blocked` 的「後續事件沒帶 = 已解除」相反：這裡是**帶了 key 才改**。
    理由不對稱是刻意的——blocked 解除是常態（門開了就該清掉），而「投遞路徑」
    是一次性的事實判斷，一個 retype 事件不該把它靜默弄丟。
    會悄悄弄丟斷言的寫入路徑，比沒有那個斷言更糟（同 surface_blocked 的註解）。
    """
    out: dict[str, str] = {}
    for e in HuntLoop.load(ledger_path(target)).events:
        if e.get("type") != "surface" or not e.get("name"):
            continue
        if "delivery" in e:
            out[str(e["name"])] = str(e.get("delivery") or "").strip()
    return out


def surface_vuln_class(target: str | Path) -> dict[str, str]:
    """每個面最後一次申報的 vuln_class（同 delivery 的「帶了 key 才改」語意）。"""
    out: dict[str, str] = {}
    for e in HuntLoop.load(ledger_path(target)).events:
        if e.get("type") != "surface" or not e.get("name"):
            continue
        if e.get("vuln_class"):
            out[str(e["name"])] = canonical_vuln_class(str(e["vuln_class"]))
    return out


def surfaces_impact_blocked(target: str | Path) -> dict[str, str]:
    """影響依賴型、但投遞路徑申報為 `none`（或從未申報）的面 → 原因。

    `none` 不是錯誤，是一個**看得見的欄位**：它讓「這面的上限是 informational」
    在開工前就擺在檯面上，而不是兩天後寫在結論段。
    """
    cls = surface_vuln_class(target)
    dlv = surface_delivery(target)
    out: dict[str, str] = {}
    for name, vc in cls.items():
        if not is_impact_dependent(vc):
            continue
        d = dlv.get(name)
        if d is None:
            out[name] = f"{vc}：未申報投遞路徑"
        elif d.lower() in ("none", "no", "n/a", "無"):
            out[name] = f"{vc}：delivery=none（上限 informational）"
    return out


def root_cause_exhaustion(target: str | Path, *, floor: int = 3) -> list[dict]:
    """同一根因／同一類別連續吃到 N 筆 refuted ⇒ 這一族已經挖到見底。

    為什麼需要（一次同根因家族的實測）：前 3–4 格就已經顯示同一個死因，
    卻又做了十幾格才停。既有的 `root_cause_groups` 只回答「哪些 finding 該併成
    一份報告」，**沒有任何東西回答「這一族還值不值得再做一格」**。

    分組鍵的取法（刻意兩段）：
      1. `root_cause` —— 最準，但要人填，而舊 ledger 常常一筆都沒有。
         只靠它＝又一個「要新紀律才會動」的欄位，這類自願欄位的採用率實測極低。
      2. 沒有 root_cause 就退回 `vuln_class` —— record-verdict 支援 `--vuln-class`，
         實測一個家族的裁決裡多數已帶值，所以這條從第一天就有訊號，不用等任何人改習慣。
    回傳的 `key_kind` 標明用了哪一段，避免把粗的當成細的。

    `confirmed` 一筆就解除：這一族還有活的，不該停。
    `inconclusive` 不計入 floor（測了但沒決定不是證據），但會回報，
    因為「全是 inconclusive」通常代表量測工具有問題，不代表這族乾淨。
    """
    buckets: dict[tuple[str, str], dict] = {}
    for e in HuntLoop.load(ledger_path(target)).events:
        if e.get("type") != "verdict":
            continue
        status = str(e.get("status", "")).strip()
        if status not in ("confirmed", "refuted", "inconclusive"):
            continue
        if e.get("root_cause"):
            key, kind = str(e["root_cause"]), "root_cause"
        elif e.get("vuln_class"):
            key, kind = canonical_vuln_class(str(e["vuln_class"])), "vuln_class"
        else:
            continue
        b = buckets.setdefault((kind, key), {"refuted": 0, "confirmed": 0,
                                             "inconclusive": 0, "hypotheses": []})
        b[status] += 1
        b["hypotheses"].append(str(e.get("hypothesis", "")))

    out: list[dict] = []
    for (kind, key), b in sorted(buckets.items()):
        if b["confirmed"]:
            continue                      # 這族還有活的
        if b["refuted"] < floor:
            continue
        out.append({
            "key": key, "key_kind": kind,
            "refuted": b["refuted"], "inconclusive": b["inconclusive"],
            "hypotheses": b["hypotheses"],
            "verdict": (f"{key}：連續 {b['refuted']} 筆 refuted、0 筆 confirmed"
                        f"{'（另有 %d 筆 inconclusive）' % b['inconclusive'] if b['inconclusive'] else ''}"
                        f" ⇒ 這一族已挖到見底，再開一格前先說出「這格與前 "
                        f"{b['refuted']} 格的差異在哪」"),
        })
    return out


def surface_typing(target: str | Path) -> dict[str, list[str]]:
    """Split surfaces by how specifically they can be routed to a must-test pack.

    `technique_pack` keys the packs off a surface's node_type. A surface registered
    without one retrieves nothing and silently degrades to the generic answer: on
    某 target all 102 surfaces were free text, so the SSRF pack — whose trigger line
    names `?url=` verbatim — went unread for nine days while a surface literally called
    `GET /api/dmc/v2/file/preview?url=` sat in the ledger.

    Counting them is the point. A number next to the coverage figures is visible at the
    moment of use; "remember to classify surfaces" is not. The generic bucket is split
    out separately because typing every new host `service` would otherwise zero the
    untyped count while leaving the same blind spot in place.

    The ledger is append-only, so a surface may carry several events and only the last
    one is current — same precedence `surface_state` uses. Without that, back-filling a
    type by appending would leave the surface counted in both the untyped and the typed
    bucket at once, and the totals would exceed `surfaces_total`.

    2026-10-10 fix: "last event wins" has to mean "last event that CARRIES a type".
    Not every surface event is about typing — `record-finding` appends a bare
    `{type: surface, name, untested: false}` to settle the surface it resolves, and
    that event has no `node_type`. Overwriting unconditionally let those state-only
    events erase the type: trendlab registered all 19 surfaces with an explicit
    `--type` and `status` still reported `surfaces_untyped: 19`, i.e. the exact blind
    spot this function exists to measure, produced by the measurement itself. A
    surface stays untyped only until some event actually names a type.
    """
    loop = HuntLoop.load(ledger_path(target))
    latest_type: dict[str, str] = {}
    prov: dict[str, bool] = {}
    for e in loop.events:
        if e.get("type") != "surface" or not e.get("name"):
            continue
        name = str(e["name"])
        ntype = str(e.get("node_type") or "").strip().lower()
        if ntype:
            latest_type[name] = ntype
            prov[name] = bool(e.get("type_provisional"))
        else:
            # state-only event (untested toggles, blocked markers): registers the
            # surface, never clears a type an earlier event established
            latest_type.setdefault(name, "")
            prov.setdefault(name, False)

    untyped: list[str] = []
    generic: list[str] = []
    specific: list[str] = []
    for name, nt in latest_type.items():
        if nt in ("", "unknown"):
            untyped.append(name)
        elif nt in _GENERIC_NODE_TYPES:
            generic.append(name)
        else:
            specific.append(name)
    return {"untyped": sorted(untyped), "generic": sorted(generic),
            "specific": sorted(specific),
            # 「暫定」＝型別是從面的**名字**推的，沒有真的去看過那個面。
            # 某 target 的 102 筆全是這樣來的，而當晚就證明會錯：ASG 上寫
            # 標籤寫成某個 BI 產品名,實際是個 AI agent 平台——照那個型別去測
            # 只會測錯方向，而且在覆蓋率上顯示為綠。錯的型別比沒有型別更危險。
            "provisional": sorted(n for n in latest_type if prov.get(n))}


def ingest_surfaces(target: str | Path, names: "list[str] | tuple[str, ...]", *,
                    node_type: str = "service", source: str = "recon",
                    note: str = "", cap: int = 100) -> list[str]:
    """Program-driven surface ingestion (artex-inspired, 2026-10-09): add each NEW name as
    an untested surface, instead of waiting for the model to run `add-surface` by hand.

    Why: 12% of targets ever got an ASG, and OpenCode hunts wrote the graph 0 times while
    reading it 21× — the graph starved because its upkeep depended on model discipline.
    When a tool already emits the attack surface (subfinder/httpx hosts), the program can
    fold it in. Idempotent (skips existing), capped (a scan must not flood the ledger with
    thousands of rows), and only acts when a genesis exists (no graph, nothing to feed).
    Rows are stamped `auto: True` + `source` so the operator can tell machine-added surfaces
    from hand-mapped ones. Returns the names actually added."""
    if not has_genesis(target):
        return []
    existing = set(surface_state(target))
    seen: set[str] = set()
    new: list[str] = []
    for raw in names:
        n = str(raw).strip().lower().rstrip(".")
        if not n or n in existing or n in seen:
            continue
        seen.add(n)
        new.append(n)
        if len(new) >= cap:
            break
    if not new:
        return []
    append_events(target, [("surface", {"name": n, "untested": True, "node_type": node_type,
                                         "source": source, "note": note, "auto": True})
                           for n in new])
    return new


def surface_state(target: str | Path) -> dict[str, str]:
    """Derive each surface's current disposition from the ledger alone.

    Precedence: the latest verdict that claims the surface wins; otherwise an
    explicit `untested: False` surface event marks it tested; otherwise untested.
    """
    loop = HuntLoop.load(ledger_path(target))
    # latest verdict per hypothesis — the ledger is append-only, so a hypothesis
    # may carry several historical verdicts and only the last one is current.
    latest: dict[str, str] = {}
    for e in loop.events:
        if e.get("type") == "verdict" and e.get("hypothesis"):
            status = str(e.get("status", "")).strip()
            if status in ("confirmed", "refuted", "inconclusive"):
                latest[str(e["hypothesis"])] = status

    state: dict[str, str] = {}
    for e in loop.events:
        if e.get("type") != "surface" or not e.get("name"):
            continue
        name = str(e["name"])
        if e.get("untested", True):
            state[name] = "untested"
            continue
        # A surface closed out by reference inherits that hypothesis's verdict,
        # so `refuted` reaches the projection instead of a flat `tested`.
        state[name] = latest.get(str(e.get("settled_by", "")), "tested")

    # A verdict may also claim its surfaces directly (record_verdict writes both).
    for e in loop.events:
        if e.get("type") != "verdict":
            continue
        status = str(e.get("status", "")).strip()
        if status not in ("confirmed", "refuted", "inconclusive"):
            continue
        for name in e.get("resolves", []) or []:
            if str(name) in state:
                state[str(name)] = status
    return state


def verdict_volatility(target: str | Path) -> dict:
    """How often a verdict on this target has later been overturned.

    A re-verification that contradicts an earlier verdict is the only direct
    evidence that a target's state moves. SonicDX produced several in one day
    (extdev inconclusive->refuted, the WMS help index 404->200, the ASP.NET version
    leak inconclusive->confirmed), which is precisely why a stale verdict there is
    dangerous. Reporting the measured flip count beats asserting a made-up window.
    """
    loop = HuntLoop.load(ledger_path(target))
    seq: dict[str, list[str]] = {}
    for e in loop.events:
        if e.get("type") == "verdict" and e.get("hypothesis"):
            s = str(e.get("status", "")).strip()
            if s in ("confirmed", "refuted", "inconclusive"):
                seq.setdefault(str(e["hypothesis"]), []).append(s)
    flipped = {h: v for h, v in seq.items() if len(set(v)) > 1}
    return {"hypotheses": len(seq), "flipped": len(flipped),
            "flips": {h: v for h, v in flipped.items()}}


def hypothesis_state(target: str | Path, hyp_id: str) -> dict | None:
    """Return the LATEST hypothesis event for `hyp_id`, or None if never registered.

    Added with `add-hypothesis` (2026-10-08). A verdict that names a hypothesis the
    ledger never heard of is invisible to the strategy feedback loop: `compute_strategy_stats`
    joins on `hypothesis.id → strategy`, so an un-registered hypothesis drops its verdict
    silently. 16 of the 19 ledgers in this vault have verdicts with no matching hypothesis
    event for exactly this reason — the interactive CLI had no way to create one.

    LATEST, not first: a hypothesis may be re-declared under a different `--strategy`
    (appended, never rewritten — the ledger is append-only), and the whole point of the
    re-tag is that it supersedes the old attribution. Returning the first match made
    `record_verdict`'s re-tag guard compare against a value the ledger had already
    superseded, so it appended every time and the caller kept reading the stale tag.
    """
    led = ledger_path(target)
    if not led.exists():
        return None
    latest: dict | None = None
    for ev in read_ledger_events(led):
        if ev.get("type") == "hypothesis" and str(ev.get("id")) == str(hyp_id):
            latest = ev
    return latest


def add_hypothesis(target: str | Path, hyp_id: str, *,
                   strategy: str = "", requires: "list[str] | tuple[str, ...]" = (),
                   **data) -> dict:
    """Register a hypothesis so its later verdict can be attributed to a strategy.

    Idempotent by id: re-registering an existing hypothesis is a no-op that reports the
    stored value, so a retried command never appends a duplicate event. `--strategy` is
    what feeds the UCCU feedback loop (`thinking_strategies.compute_strategy_stats`); an
    untagged hypothesis is legal but contributes nothing to effectiveness ranking.
    """
    hyp_id = str(hyp_id).strip()
    if not hyp_id:
        return {"ok": False, "reason": "empty hypothesis id"}
    prior = hypothesis_state(target, hyp_id)
    if prior is not None:
        return {"ok": True, "skipped": "already registered", "hypothesis": hyp_id,
                "strategy": prior.get("strategy", ""),
                "hint": "換 strategy 用 record-verdict --strategy（會附加事件，不改寫既有的）"}
    ev: dict = {"id": hyp_id, "requires": list(requires)}
    if strategy:
        ev["strategy"] = strategy
    for k, v in data.items():
        if v not in (None, "", [], {}):
            ev[k] = v
    append_events(target, [("hypothesis", ev)])
    return {"ok": True, "hypothesis": hyp_id, "strategy": ev.get("strategy", ""),
            "requires": ev["requires"]}


def record_verdict(target: str | Path, hypothesis: str, status: str, *,
                   resolves: "list[str] | tuple[str, ...]" = (), **data) -> dict:
    """Append a verdict and, atomically, close out the surfaces it settles.

    Use this instead of a bare append_event("verdict", ...) so a decided surface
    stops being advertised as untested. `resolves` holds surface names exactly as
    the ledger spells them (== the YAML node label); unknown names are recorded on
    the verdict but flip nothing, so a typo degrades to a no-op rather than to
    silent corruption.
    """
    known = surface_state(target)
    names = [str(r) for r in resolves]
    events: list[tuple[str, dict]] = []
    # A verdict whose hypothesis was never registered is invisible to the strategy
    # feedback loop — the join is `hypothesis.id → strategy`. Auto-register here so an
    # interactive verdict isn't a silent no-op for effectiveness stats.
    registered = hypothesis_state(target, hypothesis) is not None
    if not registered:
        h_ev: dict = {"id": hypothesis, "requires": []}
        if data.get("strategy"):
            h_ev["strategy"] = data["strategy"]
        events.append(("hypothesis", h_ev))
    elif data.get("strategy") and data["strategy"] != (hypothesis_state(target, hypothesis) or {}).get("strategy"):
        # Either untagged, or tagged with a DIFFERENT move than the operator just
        # declared. Both cases append a fresh hypothesis event carrying the new tag.
        #
        # The "different" case matters more than it looks: only the hypothesis EVENT's
        # strategy reaches `compute_strategy_stats` (the join is on the event, the
        # verdict's copy is ignored). So a re-tag that doesn't append leaves the ledger
        # asserting CHAIN_ESCALATION while the verdict says DEFENSE_INVERSION — measured
        # against the wrong thinking move, which is worse than having no measurement.
        # Append-only ledger → append; stats read the latest, not the first.
        events.append(("hypothesis", {"id": hypothesis, "requires": [],
                                      "strategy": data["strategy"]}))
    events.append(
        ("verdict", {"hypothesis": hypothesis, "status": status,
                     "resolves": names, **data})
    )
    settled: list[str] = []
    if status in ("confirmed", "refuted", "inconclusive"):
        for name in names:
            if name in known:
                settled.append(name)
                events.append(("surface", {"name": name, "untested": False}))
    append_events(target, events)
    out = {"ok": True, "hypothesis": hypothesis, "status": status,
           "surfaces_settled": settled,
           "hypothesis_auto_registered": not registered,
           "strategy": data.get("strategy", ""),
           "unknown_surfaces": [n for n in names if n not in known]}
    # 停損訊號要出現在**記下這筆的當下**，不是兩天後翻 status 的時候。
    # 犯錯的時點與讀報表的時點不重合——這正是這個停損訊號的整個重點。
    key = str(data.get("root_cause") or data.get("vuln_class") or "")
    if status == "refuted" and key:
        for fam in root_cause_exhaustion(target):
            if fam["key"] in (key, canonical_vuln_class(key)):
                out["family_exhausted"] = fam["verdict"]
                break
    return out


_DISPOSITION_RE = re.compile(r"^(?P<indent>\s*)disposition:\s*(?P<val>\S.*?)\s*$")
_NODE_START_RE = re.compile(r"^\s*-\s+id:\s*\S")
_LABEL_RE = re.compile(r"^\s*label:\s*[\"']?(?P<label>.+?)[\"']?\s*$")


# A projection must only ever ADD information. The operator's disposition
# vocabulary is richer than the ledger's: `covered`, `blocked`, `deferred`,
# `[finding]` all say more than a bare `tested`, and far more than `untested`.
# Overwriting them from the ledger would re-open settled work and manufacture
# false "untested" signals — the exact failure this projection exists to end.
# So rank the values and only ever move a node UP the lattice.
_DISPOSITION_RANK = {
    "untested": 0,
    "tested": 1,
    # Everything the operator writes that is not a lifecycle value outranks
    # `tested`; unknown strings fall here too (see _rank).
    "inconclusive": 3,
    "refuted": 4,
    "confirmed": 4,
}
_OPERATOR_RANK = 2  # covered / blocked / deferred / "[finding]" / anything bespoke


def _rank(value: str) -> int:
    return _DISPOSITION_RANK.get(value.strip().strip('"\''), _OPERATOR_RANK)


def project_dispositions(target: str | Path) -> dict:
    """Rewrite `disposition:` in the Markdown YAML block from the ledger, upward only.

    Only that one field is touched: ids, labels, hypotheses and comments are the
    operator's and are preserved byte-for-byte. A node whose label the ledger has
    never seen is left alone rather than guessed at, and a node already carrying a
    richer disposition than the ledger can justify is left alone too.
    """
    md = markdown_path(target)
    if not md.exists():
        return {"updated": 0, "reason": "no Markdown ASG"}
    state = surface_state(target)
    if not state:
        return {"updated": 0, "reason": "ledger has no surfaces"}

    lines = md.read_text(encoding="utf-8").splitlines(keepends=True)
    label: str | None = None
    updated = 0
    changes: list[str] = []
    kept: list[str] = []
    for i, line in enumerate(lines):
        if _NODE_START_RE.match(line):
            label = None
            continue
        m_label = _LABEL_RE.match(line)
        if m_label:
            label = m_label.group("label").strip()
            continue
        m_disp = _DISPOSITION_RE.match(line)
        if not m_disp or label is None:
            continue
        derived = state.get(label)
        current = m_disp.group("val")
        if derived is None or derived == current:
            continue
        if _rank(derived) <= _rank(current):
            # The ledger knows no more than the file already says. Leave it.
            kept.append(f"{label}: kept {current} (ledger only has {derived})")
            continue
        eol = "\n" if line.endswith("\n") else ""
        lines[i] = f"{m_disp.group('indent')}disposition: {derived}{eol}"
        changes.append(f"{label}: {current} -> {derived}")
        updated += 1
    if updated:
        md.write_text("".join(lines), encoding="utf-8")
    return {"updated": updated, "changes": changes, "kept": kept, "markdown": str(md)}


def project_all(target: str | Path) -> dict:
    """Refresh every projection from the ledger."""
    nw = ""
    try:
        import next_work
        nw = str(next_work.write(Path(target).name if isinstance(target, Path) else str(target)))
    except LedgerReadError:
        raise
    except Exception:
        pass
    result = {"markdown": str(project_markdown(target)),
            "dispositions": project_dispositions(target),
            "snapshot": str(write_snapshot(target)),
            "next_work": nw}
    if read_state(target)["research"]["enabled"]:
        from render_surface_graph_canvas import write_research_canvas
        result["research_canvas"] = str(write_research_canvas(target))
    return result


def status(target: str | Path) -> dict:
    """The SINGLE SOURCE for target statistics. Never hand-write these numbers."""
    led = ledger_path(target)
    if not led.exists():
        return {"error": f"no ledger for {target}"}
    state = read_state(target)
    genesis = state["genesis"]
    if not genesis:
        return {"error": f"no genesis for {target}"}
    phase = state["phase"]
    chain = phase_chain(target)
    findings = {f["id"]: f.get("status", "hypothesis") for f in state["findings"]}
    by_state: dict[str, list[str]] = {}
    for fid, st in findings.items():
        by_state.setdefault(st, []).append(fid)
    pw = pending_workers(target)
    surfaces = surface_state(target)
    untested = sum(1 for s in surfaces.values() if s == "untested")
    # `inconclusive` means the test ran but decided nothing — it is NOT coverage.
    # Counting it as tested let a single anonymous GET that resolved to
    # inconclusive flip a surface out of the untested pool and satisfy the
    # coverage floor, which is the harvest-bias hole the floor exists to close.
    inconclusive = sum(1 for s in surfaces.values() if s == "inconclusive")
    _typing = surface_typing(target)
    _nonstd_vc = nonstandard_vuln_classes(target)
    _impact_blocked = surfaces_impact_blocked(target)
    _exhausted = root_cause_exhaustion(target)
    chains = auto_chain(target, state=state)
    return {
        "target": _basename(target),
        "profile": genesis.get("profile", "web"),
        "phase": phase,
        "phase_chain": list(chain),
        "findings_total": len(findings),
        "findings_by_state": {k: len(v) for k, v in sorted(by_state.items())},
        # `pending_workers: 0` reads as "all gates cleared", but it is also what a
        # target looks like when no finding ever reached `confirmed` and therefore no
        # worker was ever QUEUED. 某 target showed 0 pending against 55 findings, none
        # confirmed — a clean bill of health for a gate that had never run. Publish the
        # distinction so the number cannot be misread.
        "workers_never_scheduled": bool(findings) and not any(
            _required_workers(target, fid) for fid in findings),
        # Deliverable findings that predate WORKER_TRIGGER_STATES (or skipped it) and so
        # never had verb-matrix/chain/expand queued. Backfill:
        # `asg.py queue-workers <t> [<id>…]`.
        "findings_unscheduled_workers": sorted(
            fid for fid, st in findings.items()
            if st in WORKER_TRIGGER_STATES and not _required_workers(target, fid)),
        "pending_workers": len(pw),
        "pending_workers_detail": [
            {"finding_id": w.get("finding_id"), "worker": w.get("worker")}
            for w in pw
        ],
        "surfaces_total": len(surfaces),
        "surfaces_untested": untested,
        "surfaces_inconclusive": inconclusive,
        # `surfaces_untested` says how much of the registry was worked. These say how
        # much of it can be routed to a technique at all: untyped retrieves no pack,
        # generic retrieves only the broad ones. A low untested count sitting on top of
        # a high untyped/generic count means the registry was worked through one lens.
        "surfaces_untyped": len(_typing["untyped"]),
        # 正規化後仍不在正規集合裡的 vuln_class。別名表是白名單，沒收進來的新寫法
        # 原樣通過且沒有任何地方會說 —— 上一次發現時已經散成 118 種。
        "findings_nonstandard_vuln_class": len(_nonstd_vc),
        "findings_nonstandard_vuln_class_detail": dict(sorted(_nonstd_vc.items())),
        "surfaces_generic_type": len(_typing["generic"]),
        "surfaces_type_provisional": len(_typing["provisional"]),
        # blocked ≠ untested ≠ tested：去了但進不去，門後的東西一行都沒測到
        "surfaces_blocked": len(surface_blocked(target)),
        # blocked surfaces whose awaited capability is now held — retest these first
        "surfaces_unlockable": surfaces_unlockable(target, state=state),
        # 影響依賴型（Gatekeeper／TCC／quarantine／沙箱／簽章）但投遞路徑是 none
        # 或從未申報的面。這些的上限是 informational —— 數字擺在覆蓋率旁邊，
        # 是為了讓「這面註定沒影響」在**開工前**就看得見。
        # 和 untested 分開：不是沒測，是測了也不值錢。
        "surfaces_impact_blocked": len(_impact_blocked),
        "surfaces_impact_blocked_detail": _impact_blocked,
        # stub 可以延後寫長文，不能延後寫主張：沒有 expected_impact／observed 的
        # finding 事件，之後沒有人能判斷它值不值得追，也分不出「拿到資料」與「過了中介層」
        "findings_without_claim": len(findings_without_claim(target)),
        # 刻意不送 ≠ 忘了送。沒有這個區分，一批驗不了的 finding 會被當成待辦灌成 FORM
        "findings_on_hold": len(findings_on_hold(target)),
        # 已當成「測過／已確認」、卻沒申報證據實際碰到什麼（data_access / state_change /
        # exec）。這些是 其中一筆 finding 的形狀：把參數驗證層的報錯當成授權繞過。
        "findings_without_observation_kind": len(findings_without_observation_kind(target)),
        # 同一個 root_cause 底下有多個 finding ＝ 它們很可能是**一次修補**，應合成一份
        # 報告而非各開一條（某 target 030–043：12 個端點疑似同一處沒核租戶）。
        "root_cause_groups": {k: v for k, v in root_cause_groups(target).items()},
        # 同一根因／類別連吃 N 筆 refuted、0 筆 confirmed ＝ 這族挖到見底。
        # root_cause_groups 回答「哪些該併成一份報告」，這個回答「還值不值得再做一格」。
        # 一個同根因家族前 3–4 格就顯示同一死因，仍做了十幾格。
        "exhausted_families": _exhausted,
        # Settled = decided one way or the other (confirmed / refuted / operator-
        # asserted tested). This, not `total - untested`, is the coverage numerator.
        "surfaces_settled": len(surfaces) - untested - inconclusive,
        "chain_edges": len(chains.get("chain_edges", [])),
        "chain_entry_points": len(chains.get("entry_points", [])),
        # How far behind the ledger the cached snapshot is. 某 target's snapshot sat 37
        # events back while next_work.json confidently pointed at recon dimensions the
        # ASG already marked done — a stale projection does not announce itself, so
        # anything reading the snapshot deserves to see the lag next to the numbers.
        "snapshot_lag": _snapshot_lag(target),
        "research": state["research"]["summary"],
    }


def _snapshot_lag(target: str | Path) -> int:
    """Ledger events minus the snapshot's cursor; 0 when there is no snapshot."""
    snap = snapshot_path(target)
    if not snap.exists():
        return 0
    try:
        cursor = int(json.loads(snap.read_text(encoding="utf-8")).get("event_cursor") or 0)
    except (ValueError, TypeError, json.JSONDecodeError):
        return 0
    total = sum(1 for ln in ledger_path(target).read_text(encoding="utf-8").splitlines()
                if ln.strip())
    return max(0, total - cursor)


def _split_flags(extra: list[str]) -> tuple[list[str], dict[str, str]]:
    """Split trailing `extra` args into positionals and `--key value` / `--key=value`.

    The CLI takes `extra` as a free-form list (so each action parses its own tail);
    this keeps that parsing in one place instead of per-action string slicing.
    A valueless flag (`--dry-run`) lands as an empty string, so test membership.
    """
    pos: list[str] = []
    flags: dict[str, str] = {}
    i = 0
    while i < len(extra):
        tok = extra[i]
        if tok.startswith("--"):
            if "=" in tok:
                key, val = tok[2:].split("=", 1)
                flags[key] = val
                i += 1
            else:
                key = tok[2:]
                nxt = extra[i + 1] if i + 1 < len(extra) else None
                if nxt is not None and not nxt.startswith("--"):
                    flags[key] = nxt
                    i += 2
                else:
                    flags[key] = ""
                    i += 1
        else:
            pos.append(tok)
            i += 1
    return pos, flags


def _csv(val: str) -> list[str]:
    """Split `a,b,c` into stripped names; a literal comma is escaped as `\\,`.

    Surface names are free text and may themselves contain commas
    (`portal.arc.io /api/log/{info,warn,error}`). The naive `split(",")` turned
    such a name into three unknown surfaces: the verdict was recorded (with a
    stderr warning nobody was reading), the real surface stayed `untested`, and
    the coverage figure quietly under-reported it. Found 2026-10-19 during the
    portal coverage reconciliation. No existing ledger carried a `\\,` sequence,
    so the escape is backward compatible.
    """
    out: list[str] = []
    buf: list[str] = []
    s = str(val)
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s) and s[i + 1] == ",":
            buf.append(",")
            i += 2
            continue
        if ch == ",":
            item = "".join(buf).strip()
            if item:
                out.append(item)
            buf = []
        else:
            buf.append(ch)
        i += 1
    item = "".join(buf).strip()
    if item:
        out.append(item)
    return out


def _main(argv: list[str]) -> int:
    if argv and argv[0] == "research":
        from asg_research import cli
        return cli(argv[1:])
    import argparse
    ap = argparse.ArgumentParser(description="ASG single-authority resolver + projections.")
    ap.add_argument("action", choices=["paths", "project", "snapshot", "migrate", "chains",
                                       "auto-chain", "surfaces", "add-surface", "phase",
                                       "advance-phase", "finding-state", "record-finding",
                                       "advance-finding", "status", "pending-workers",
                                       "complete-worker", "queue-workers", "needs-human-go",
                                       "record-verdict", "add-hypothesis",
                                       "backfill-genesis", "link-doc", "research"])
    ap.add_argument("target")
    ap.add_argument("extra", nargs="*", default=[])
    # Everything after `<action> <target>` belongs to the action, option-looking tokens
    # included. Left to argparse, a positional `nargs="*"` does NOT capture `--resolves`
    # — it bails out with "unrecognized arguments" — so every flag added below would be
    # unreachable from the command line while still passing its unit tests.
    if argv and argv[0] not in ("-h", "--help"):
        head, tail = argv[:2], list(argv[2:])
    else:
        head, tail = argv, []
    a = ap.parse_args(head)
    a.extra = tail
    if a.action == "paths":
        print(json.dumps({"target_dir": str(target_dir(a.target)),
                          "ledger": str(ledger_path(a.target)),
                          "markdown": str(markdown_path(a.target)),
                          "snapshot": str(snapshot_path(a.target))}, ensure_ascii=False, indent=2))
    elif a.action == "project":
        print(json.dumps(project_all(a.target), ensure_ascii=False, indent=2))
    elif a.action == "snapshot":
        print(str(write_snapshot(a.target)))
    elif a.action == "migrate":
        print(json.dumps(migrate_yaml_to_ledger(a.target), ensure_ascii=False, indent=2))
    elif a.action == "add-surface":
        # Tool output → graph: record a discovered surface as a ledger event (untested).
        # Used by post_hunt_sync instead of rewriting the RECON_DB attack-surface table.
        pos, fl = _split_flags(a.extra)
        if not pos:
            print("usage: asg.py add-surface <target> <name> --type <node_type> [note...]\n"
                  "       --type unknown  （逃生口：明說分不出來，會出現在 status 的 "
                  "surfaces_untyped 計數裡）\n"
                  "       [--vuln-class <class>] [--delivery '<一句話>'|none]\n"
                  "       [--blocked '<拒絕訊息>'] [--blocked-by <cap>[,<cap>...]]  "
                  "（缺哪個能力；拿到時 next_work 會把它排第一）\n"
                  "       影響依賴型類別（Gatekeeper／TCC／quarantine／沙箱／簽章）"
                  "必須同時給 --delivery", file=sys.stderr)
            return 1
        name = pos[0]
        note = " ".join(pos[1:]).strip()
        ntype = (fl.get("type") or "").strip().lower()
        known, vocab_err = known_node_types()
        if not ntype:
            print(f"add-surface 需要 --type。\n"
                  f"  可用型別：{', '.join(sorted(known)) if known else '(詞彙載入失敗)'}\n"
                  f"  分不出來就寫 --type unknown（會被計入 surfaces_untyped，不是靜默放行）\n"
                  f"  為何必填：surface 的 node_type 是 technique_pack 取必測包的唯一依據"
                  f"（`technique_pack.py for-node <type>`）。沒有型別的面會退化成 generic，"
                  f"該面的必測清單就永遠取不到——某 target 102 個面全部無型別，"
                  f"SSRF 包因此在架上躺了九天沒被取用。", file=sys.stderr)
            return 1
        if ntype != "unknown" and known and ntype not in known:
            print(f"未知的 node_type: {ntype!r}\n"
                  f"  可用型別：{', '.join(sorted(known))}\n"
                  f"  真的是新型別 → 先在必測包檔案（09 - Knowledge Base/"
                  f"Pattern - Surface to Must-Test Technique Packs.md）建該型別的包，"
                  f"否則型別存在而必測清單不存在，等於沒分類。", file=sys.stderr)
            return 1
        if vocab_err:
            print(f"⚠ node_type 詞彙載入失敗（{vocab_err}），本次不驗證型別", file=sys.stderr)

        # ── 開挖端的投遞路徑閘 ──────────────────────────────
        # 送件端的 delivery_vector 硬擋只攔得住「寫完要送」，攔不住
        # 「把兩天投進一個註定沒有影響的面」。同一個問題必須問在開工前。
        # 判準很鋒利：那條路徑上有沒有一個**使用者本來就會做的動作**
        # （雙擊下載檔、開資料夾看縮圖、收信、插隨身碟）。
        # 如果需要的是「使用者打開終端機敲某個指令」，那就是沒有 → 寫 none。
        vclass = canonical_vuln_class(fl.get("vuln-class") or "")
        delivery = (fl.get("delivery") or "").strip()
        if is_impact_dependent(vclass) and not delivery:
            print(f"vuln-class {vclass!r} 是影響依賴型，--delivery 必填。\n"
                  f"  回答這一句：**零額外使用者動作下，攻擊者怎麼讓受害者走到這條程式碼路徑？**\n"
                  f"    答得出來 → --delivery '<那一句話>'（之後它就是現成的 delivery_vector）\n"
                  f"    答不出來 → --delivery none（不是錯誤，是把「這面上限 informational」\n"
                  f"                               在開工前擺上檯面；會進 status 的 "
                  f"surfaces_impact_blocked）\n"
                  f"  為何必填：曾有一次兩天、數十筆裁決、數十個 PoC、0 個可送件 —— "
                  f"多條線同一個死因，而且每條線的第一分鐘就看得出來。", file=sys.stderr)
            return 1

        existing = surface_state(a.target)
        if name in existing and "retype" not in fl:
            print(json.dumps({"ok": True, "skipped": "already a surface",
                              "name": name, "state": existing[name],
                              "hint": "改型別用 --retype（會附加一筆事件，不改寫既有的）"},
                             ensure_ascii=False))
        elif name in existing:
            # Re-typing an existing surface. Append rather than rewrite — the ledger is
            # append-only and `surface_typing` reads the latest event per name — and carry
            # the current tested state forward so a back-fill never resurrects a settled
            # surface as untested.
            was_untested = existing[name] == "untested"
            kw2: dict = {}
            # retype 也要帶 blocked，否則「換個型別」會把「去了但進不去」這個狀態
            # 靜默清掉——surface_blocked 讀的是最後一筆事件，少了這個欄位就等於解除封鎖。
            # 一個會悄悄弄丟斷言的寫入路徑，比沒有那個斷言更糟。
            if "blocked" in fl:
                kw2["blocked"] = fl["blocked"] or "blocked (no reason given)"
            elif existing_block := surface_blocked(a.target).get(name):
                kw2["blocked"] = existing_block      # 沒明講就沿用，不默默清除
            if fl.get("blocked-by"):
                kw2["blocked_by"] = _csv(fl["blocked-by"])
                kw2.setdefault("blocked", f"needs {fl['blocked-by']}")
            elif "blocked" in kw2 and (prev_by := surface_blocked_by(a.target).get(name)):
                kw2["blocked_by"] = prev_by
            # vuln_class / delivery 同理：retype 不該把開挖前做過的影響判斷弄丟。
            if vclass:
                kw2["vuln_class"] = vclass
            elif prev_vc := surface_vuln_class(a.target).get(name):
                kw2["vuln_class"] = prev_vc
            if delivery:
                kw2["delivery"] = delivery
            elif (prev_d := surface_delivery(a.target).get(name)) is not None:
                kw2["delivery"] = prev_d
            append_event(a.target, "surface", name=name, untested=was_untested,
                         node_type=ntype, type_provisional="provisional" in fl,
                         note=note or "retype", **kw2)
            print(json.dumps({"ok": True, "retyped": name, "node_type": ntype,
                              "state": existing[name]}, ensure_ascii=False))
        else:
            kw = {"note": note} if note else {}
            if "blocked" in fl:
                kw["blocked"] = fl["blocked"] or "blocked (no reason given)"
            if fl.get("blocked-by"):
                kw["blocked_by"] = _csv(fl["blocked-by"])
                kw.setdefault("blocked", f"needs {fl['blocked-by']}")
            if vclass:
                kw["vuln_class"] = vclass
            if delivery:
                kw["delivery"] = delivery
            append_event(a.target, "surface", name=name, untested=True,
                         node_type=ntype, type_provisional="provisional" in fl, **kw)
            out = {"ok": True, "added": name, "node_type": ntype}
            if ntype != "unknown":
                out["must_test"] = (f"python3 automation/technique_pack.py for-node {ntype}")
            if delivery and delivery.lower() in ("none", "no", "n/a", "無"):
                out["impact_ceiling"] = (
                    "delivery=none ⇒ 本面上限 informational。要開工是可以的，"
                    "但它會出現在 status 的 surfaces_impact_blocked，"
                    "別在它身上投第二天。")
            print(json.dumps(out, ensure_ascii=False))
    elif a.action == "needs-human-go":
        # the human-authorization queue: deferred write/service-impact actions.
        q = needs_human_go_queue(a.target)
        if "--json" in a.extra:
            print(json.dumps({"target": a.target, "count": len(q), "queue": q},
                             ensure_ascii=False, indent=2))
        elif not q:
            print(f"(needs_human_go queue empty for {a.target})")
        else:
            print(f"needs_human_go — {len(q)} action(s) awaiting authorization ({a.target}):")
            for it in q:
                print(f"  [{it['risk']}] {it['hyp_id']}: {it['action']}")
                print(f"      go:      python3 automation/bb_authorize.py {a.target} {it['hyp_id']} --decision go")
                print(f"      decline: python3 automation/bb_authorize.py {a.target} {it['hyp_id']} --decision decline")
    elif a.action == "surfaces":
        st = surface_state(a.target)
        undecided = [n for n, s in st.items() if s == "untested"]
        print(json.dumps({"total": len(st), "untested": len(undecided),
                          "by_state": {s: sorted(n for n, v in st.items() if v == s)
                                       for s in sorted(set(st.values()))}},
                         ensure_ascii=False, indent=2))
    elif a.action == "chains":
        print(json.dumps(chain_projection(a.target), ensure_ascii=False, indent=2))
    elif a.action == "auto-chain":
        result = auto_chain(a.target)
        mermaid = result.pop("mermaid")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        print("\n--- Mermaid ---")
        print(mermaid)
    elif a.action == "phase":
        p = current_phase(a.target)
        chain = phase_chain(a.target)
        idx = phase_index(a.target)
        print(json.dumps({"phase": p, "index": idx, "chain": list(chain)},
                         ensure_ascii=False, indent=2))
    elif a.action == "advance-phase":
        if len(a.extra) < 1:
            print("usage: asg.py advance-phase <target> <to-phase> [reason]", file=sys.stderr)
            return 1
        to = a.extra[0]
        reason = " ".join(a.extra[1:])
        print(json.dumps(advance_phase(a.target, to, reason=reason),
                         ensure_ascii=False, indent=2))
    elif a.action == "finding-state":
        if len(a.extra) < 1:
            print("usage: asg.py finding-state <target> <finding-id>", file=sys.stderr)
            return 1
        fid = a.extra[0]
        print(json.dumps({"finding_id": fid, "state": finding_state(a.target, fid)},
                         ensure_ascii=False, indent=2))
    elif a.action == "record-finding":
        pos, fl = _split_flags(a.extra)
        if not pos:
            print("usage: asg.py record-finding <target> <finding-id> "
                  "[--resolves <surface>[,<surface>...]] [--surface <name>] "
                  "[--provides <cap>[,<cap>...]] [--poc-ref <path>] [--evidence <path>] "
                  "[--doc <Findings/...md>] [--severity <P1..P4>] [--vuln-class <class>]\n"
                  "       [--root-cause '<同一處修補的分組鍵>']  （同根因＝一份報告；"
                  "同 surface-prefix 的姊妹 finding 用同一字串，check_report_bar R2 會據此擋多份）\n"
                  "       [--expected-impact '<一句話：成立的話代表什麼>'] "
                  "[--observed '<你實際看到什麼：資料/錯誤層/只有版本>']",
                  file=sys.stderr)
            return 1
        fid = pos[0]
        # `--amend`：對已存在的 finding 補欄位（典型是補上 expected_impact / observed）。
        # record_finding 本身是 idempotent、遇到既有 id 直接拒絕——那對「重複記錄」是對的，
        # 但讓「補齊主張」沒有路可走。ledger 是 append-only，補欄位就是再追加一筆事件，
        # 讀取端（findings_without_claim）本來就是跨事件合併的。
        if "amend" in fl:
            patch = {}
            for flag, field in (("expected-impact", "expected_impact"), ("observed", "observed"),
                                ("severity", "severity"), ("vuln-class", "vuln_class"),
                                ("doc", "doc"), ("evidence", "evidence"), ("poc-ref", "poc_ref"),
                                ("root-cause", "root_cause"), ("intent", "intent_id"),
                                ("observation-kind", "observation_kind"),
                                ("claim-scope", "claim_scope"), ("finding-kind", "finding_kind"),
                                ("analysis-mode", "analysis_mode"), ("protocol", "protocol"),
                                # 2026-10-27：補 delivery_gate 要求、但這裡原本寫不進去的三個欄位。
                                # 死結：gate 的 `runtime_impact_not_achieved` /
                                # `runtime_environment_unproven` 讀 `meta = {**doc, **record}`，
                                # ledger(record) 覆蓋檔案(doc)；但 amend 對照表沒有這兩個欄位，
                                # 而 Finding 檔又被 delivery_ready_hook 擋住所有編輯
                                # ⇒ 兩條路都寫不進去，finding 永遠 ready=false。
                                # 與上面 --resolves 同一個判準：補救的路必須存在。
                                # 值域仍由 delivery_gate 驗（stock_target/equivalent_test、
                                # achieved/… ），這裡只開寫入通道，不放寬判準。
                                ("impact-result", "impact_result"),
                                ("verification-environment", "verification_environment"),
                                ("environment-equivalence-ref", "environment_equivalence_ref"),
                                ("hold", "submit_hold"), ("unhold", "submit_unhold")):
                if fl.get(flag):
                    patch[field] = fl[flag]
            if fl.get("provides"):
                patch["provides"] = _csv(fl["provides"])
            # `--amend --resolves`：補上「這個 finding 關掉了哪個面」。
            # 少了這條，一個當初漏帶 --resolves 的 finding 永遠補不回覆蓋率——
            # 而 CLAUDE.md 把 --resolves 列為不可省，某 target 的 55 findings／96 面
            # 全未測正是漏帶造成的。補救的路必須存在。
            #
            # Guard (2026-10-08): amend --resolves on a finding that already HAS
            # different resolves is almost always an ID-repurpose bug (R8: one finding
            # was repointed from one service to an unrelated component — two completely
            # different vulns sharing one ID). Warn and require --force.
            if fl.get("resolves"):
                names = _csv(fl["resolves"])
                # Check if this finding already has resolves that would be replaced
                old_resolves = _existing_resolves(a.target, fid)
                if old_resolves and set(old_resolves) != set(names) and "force" not in fl:
                    print(f"⚠️  {fid} 已有 resolves={old_resolves}，"
                          f"新值={names} 完全不同。\n"
                          f"   如果是兩個不同漏洞，應配新 ID。\n"
                          f"   確定要覆蓋：加 --force", file=sys.stderr)
                    return 1
                known = surface_state(a.target)
                unknown_resolves = [n for n in names if n not in known]
                if unknown_resolves and "allow-unknown" not in fl:
                    print(f"⛔ {fid} --amend --resolves 包含未知 surface：{unknown_resolves}\n"
                          f"   這通常是 surface 名稱拼錯，或該 surface 尚未加入 ASG。\n"
                          f"   修正 surface 名稱，或先用 asg.py add-surface 建 surface。\n"
                          f"   若真的有意為之：加 --allow-unknown（會被記錄）。",
                          file=sys.stderr)
                    return 1
                patch["resolves"] = names
                for n in names:
                    if n in known:
                        append_event(a.target, "surface", name=n, untested=False,
                                     settled_by=fid)
            if not patch:
                print("--amend 需要至少一個欄位", file=sys.stderr)
                return 1
            if finding_state(a.target, fid) is None:
                print(f"{fid} 不在 ledger 裡，--amend 無對象", file=sys.stderr)
                return 1
            before = set(surfaces_unlockable(a.target)) if "provides" in patch else set()
            append_event(a.target, "finding", finding_id=fid, amend=True, **patch)
            out = {"ok": True, "amended": fid, "fields": sorted(patch)}
            if "provides" in patch:
                out["would_unlock"] = sorted(
                    s for s in surfaces_unlockable(a.target, extra_caps=set(patch["provides"]))
                    if s not in before)
            print(json.dumps(out, ensure_ascii=False))
            return 0
        data: dict = {}
        for flag, field in (("poc-ref", "poc_ref"), ("evidence", "evidence"),
                            ("expected-impact", "expected_impact"), ("observed", "observed"),
                            ("severity", "severity"), ("doc", "doc"),
                            ("vuln-class", "vuln_class"), ("root-cause", "root_cause"),
                            ("observation-kind", "observation_kind"),
                            ("claim-scope", "claim_scope"), ("finding-kind", "finding_kind"),
                            ("analysis-mode", "analysis_mode"), ("protocol", "protocol"),
                            ("intent", "intent_id")):
            if fl.get(flag):
                data[field] = fl[flag]
        if fl.get("provides"):
            data["provides"] = _csv(fl["provides"])
        resolves = _csv(fl.get("resolves", ""))
        # `--surface` is sugar for the common case: the surface this finding came from
        # is also one the finding settles. Keeping it separate from `--resolves` means
        # the usual one-surface call does not need comma syntax.
        if fl.get("surface") and fl["surface"] not in resolves:
            resolves.append(fl["surface"])
        known = surface_state(a.target)
        unknown_resolves = [n for n in resolves if n not in known]
        if unknown_resolves and "allow-unknown" not in fl:
            print(f"⛔ {fid} 的 --resolves 包含未知 surface：{unknown_resolves}\n"
                  f"   這通常是 surface 名稱拼錯，或該 surface 尚未加入 ASG。\n"
                  f"   修正 surface 名稱，或先用 asg.py add-surface 建 surface。\n"
                  f"   若真的有意為之：加 --allow-unknown（會被記錄）。",
                  file=sys.stderr)
            return 1
        print(json.dumps(record_finding(a.target, fid, resolves=resolves, **data),
                         ensure_ascii=False, indent=2))
    elif a.action == "add-hypothesis":
        pos, fl = _split_flags(a.extra)
        if not pos:
            print("usage: asg.py add-hypothesis <target> <hyp_id> "
                  "[--strategy <NAME>] [--requires <cap>[,...]]\n"
                  "       --strategy 是餵回 thinking_strategies 效能迴圈的那個欄位；"
                  "不給也合法，但對排名零貢獻。\n"
                  "       可用名單見 automation/thinking_strategies.py STRATEGIES",
                  file=sys.stderr)
            return 1
        print(json.dumps(add_hypothesis(
            a.target, pos[0], strategy=(fl.get("strategy") or "").strip(),
            requires=_csv(fl.get("requires", ""))),
            ensure_ascii=False, indent=2))
    elif a.action == "record-verdict":
        pos, fl = _split_flags(a.extra)
        if len(pos) < 2:
            print("usage: asg.py record-verdict <target> <hypothesis> "
                  "<confirmed|refuted|inconclusive> [--resolves <surface>[,...]] "
                  "[--evidence <path>] [--provides <cap>[,...]] [--confidence <level>] "
                  "[--vuln-class <class>] [--root-cause <key>] [--strategy <NAME>] "
                  "[--dismissal <" + "|".join(sorted(DISMISSALS)) + ">]\n"
                  "       refuted 必須帶 --vuln-class 或 --root-cause"
                  "（逃生口 --unclassified '<理由>'）\n"
                  "       --strategy 會自動補登 hypothesis event——這是互動 session "
                  "餵回策略效能排名的唯一路徑",
                  file=sys.stderr)
            return 1
        hyp, verdict = pos[0], pos[1]
        data = {}
        for flag in ("evidence", "confidence"):
            if fl.get(flag):
                data[flag] = fl[flag]
        if fl.get("strategy"):
            data["strategy"] = fl["strategy"].strip()
        # `--vuln-class` on a REFUTED verdict is what makes "we tested this class and
        # it was clean" a machine fact. record-finding has carried it since 2026-10-01;
        # without it here the 87 refuted verdicts in the ledger stay unusable for
        # coverage (they name a hypothesis id and nothing else), and evidence of
        # absence has to be hand-written into an Attempt file instead — which is why
        # the vault holds 639 Finding files against 53 Attempts.
        if fl.get("vuln-class"):
            data["vuln_class"] = canonical_vuln_class(fl["vuln-class"])
        # `--root-cause`：比 vuln_class 細一級的分組鍵（「同一處程式碼／同一個漏套」）。
        # root_cause_exhaustion 優先用它，沒有才退回 vuln_class——所以不填也有訊號，
        # 填了訊號更準。這是刻意的：只靠要人填的欄位＝0.4% 採用率。
        if fl.get("root-cause"):
            data["root_cause"] = fl["root-cause"]
        # ── refuted 必須帶分組鍵（2026-10-03）──────────────────────────
        # 不帶就沒有任何東西能回答「這一族還值不值得再做一格」。
        # 量過才加的：舊 ledger 裡只有極少數裁決帶分組鍵。一個靠自願填寫的欄位，
        # 實測採用率極低——和那些大量無型別的面同一種死法。
        # 所以照 add-surface 的 --type 怎麼處理就怎麼處理：必填，附明示逃生口。
        if verdict == "refuted" and not (fl.get("vuln-class") or fl.get("root-cause")):
            if fl.get("unclassified"):
                data["unclassified"] = fl["unclassified"]
            else:
                print("refuted 的裁決必須帶 --vuln-class 或 --root-cause。\n"
                      "  為何必填：少了分組鍵，root_cause_exhaustion 看不到這一筆，"
                      "「這族連吃 N 筆 refuted」就永遠不會響——\n"
                      "  一個同根因家族前 3–4 格就顯示同一死因，"
                      "卻又做了十幾格才停。\n"
                      "  真的分不出類別 → --unclassified '<理由>'"
                      "（明示且留在 ledger 裡，不是靜默放行）", file=sys.stderr)
                return 1
        # `--dismissal`：為什麼這條不算洞。與 vuln_class（是哪一類漏洞）分開記，
        # 否則「這是 SSRF」與「這是設計如此」會擠在同一欄，之後分不開。
        if fl.get("dismissal"):
            d = fl["dismissal"]
            if d not in DISMISSALS:
                print(f"--dismissal 必須是 {sorted(DISMISSALS)} 之一，收到 {d!r}",
                      file=sys.stderr)
                return 1
            data["dismissal"] = d
        if fl.get("provides"):
            data["provides"] = _csv(fl["provides"])
        # ── confirmed 的證據要當下就解析得到 ──────────────
        # 之前只是靜默標記 unresolved_at_recording 然後照寫。後果不是漏一個欄位：
        # 解析不到 → I1 不授予 capability → chain 算不出來。這種未解析判決很容易
        # 一路漂著沒人發現，因為它只出現在 drift report 裡，混在修不動的遷移佔位符中。
        # 寫入時擋，是唯一能在「還記得這筆在幹嘛」的時候要到證據的時機。
        if verdict == "confirmed" and not fl.get("evidence-pending"):
            from evidence_refs import evidence_resolves
            from hunt_loop import HuntLoop
            _loop = HuntLoop.load(ledger_path(a.target))
            if not evidence_resolves(data.get("evidence"), _loop.base_path, _loop.events,
                                     subject=hyp, provides=data.get("provides") or []):
                print(f"confirmed 的證據解析不到：{data.get('evidence')!r}\n"
                      f"  後果：capability 不授予 → 這筆進不了 chain，"
                      f"status 看起來卻一切正常。\n"
                      f"  free-text 散句不算證據（嚴格：須是可釘住的 artifact 或可解析的引用）。\n"
                      f"  可解析的寫法：\n"
                      f"    • 檔案路徑（相對 target 目錄）：poc/<id>/<script>.py\n"
                      f"    • 另一筆已有證據的 finding id（鏈會往下接）\n"
                      f"  證據還沒落地 → --evidence-pending '<要補什麼／何時補>'"
                      f"（明示且留在 ledger，不是靜默放行）", file=sys.stderr)
                return 1
        if fl.get("evidence-pending"):
            data["evidence_pending"] = fl["evidence-pending"]
        print(json.dumps(record_verdict(a.target, hyp, verdict,
                                        resolves=_csv(fl.get("resolves", "")), **data),
                         ensure_ascii=False, indent=2))
    elif a.action == "link-doc":
        pos, _ = _split_flags(a.extra)
        if len(pos) < 2:
            print("usage: asg.py link-doc <target> <finding-id> <Findings/...md>",
                  file=sys.stderr)
            return 1
        print(json.dumps(link_finding_doc(a.target, pos[0], pos[1]),
                         ensure_ascii=False, indent=2))
    elif a.action == "backfill-genesis":
        _, fl = _split_flags(a.extra)
        print(json.dumps(backfill_genesis(a.target, profile=fl.get("profile") or "web",
                                          dry_run="dry-run" in fl),
                         ensure_ascii=False, indent=2))
    elif a.action == "advance-finding":
        if len(a.extra) < 2:
            print("usage: asg.py advance-finding <target> <finding-id> <to-state> [reason]",
                  file=sys.stderr)
            return 1
        pos, flags = _split_flags(a.extra)
        fid, to = pos[0], pos[1]
        reason = " ".join(pos[2:])
        kw = {}
        if k := flags.get("observation-kind") or flags.get("observation_kind"):
            kw["observation_kind"] = k
        print(json.dumps(advance_finding(a.target, fid, to, reason=reason, **kw),
                         ensure_ascii=False, indent=2))
    elif a.action == "status":
        print(json.dumps(status(a.target), ensure_ascii=False, indent=2))
    elif a.action == "pending-workers":
        fid = a.extra[0] if a.extra else None
        pw = pending_workers(a.target, fid)
        print(json.dumps([{"finding_id": w.get("finding_id"), "worker": w.get("worker")}
                          for w in pw], ensure_ascii=False, indent=2))
    elif a.action == "complete-worker":
        if len(a.extra) < 2:
            print("usage: asg.py complete-worker <target> <finding-id> <worker> [reason]",
                  file=sys.stderr)
            return 1
        fid, worker = a.extra[0], a.extra[1]
        reason = " ".join(a.extra[2:])
        print(json.dumps(complete_worker(a.target, fid, worker, reason=reason),
                         ensure_ascii=False, indent=2))
    elif a.action == "queue-workers":
        print(json.dumps(queue_workers(a.target, a.extra or None),
                         ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
