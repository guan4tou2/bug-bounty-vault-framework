"""asg.py 的兩個「開挖端」控制 —— 投遞路徑閘與家族停損計數的正負對照。

來源（一次實測：數十筆裁決、數十個 PoC、0 個可送件）：
  1. 多條線同一個死因——技術缺口成立但沒有投遞路徑，而這在第一分鐘就看得出來。
     送件端的 delivery_vector 硬擋只攔得住「寫完要送」，攔不住「投兩天進去」。
  2. 同根因家族前 3–4 格就顯示同一死因，仍續做十幾格；
     既有的 root_cause_groups 只回答「哪些該併成一份報告」。

負向對照和正向一樣重要：這兩個閘都很容易寫成「什麼都擋」，
那會讓每一次 add-surface 都要填一堆東西，然後被整條繞過。
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
import asg  # noqa: E402

VAULT = Path(__file__).resolve().parents[1]
ASG_CLI = VAULT / "automation" / "asg.py"


@pytest.fixture
def t(tmp_path, monkeypatch):
    monkeypatch.setattr(asg, "vault_root", lambda: tmp_path)
    asg.append_event("IM1", "genesis", profile="source-audit")
    return "IM1"


@pytest.fixture
def cli_target():
    """CLI 層的閘只能在真的 target 目錄上測：vault_root() 是寫死的，
    monkeypatch 進不到 subprocess 裡。用一次性 target，finally 一定清掉。"""
    name = "_pytest_asg_gate"
    tdir = VAULT / "01 - Targets" / name
    shutil.rmtree(tdir, ignore_errors=True)
    (tdir / ".state").mkdir(parents=True)
    (tdir / ".state" / "asg-events.jsonl").write_text(
        json.dumps({"type": "genesis", "profile": "source-audit",
                    "at": "2026-10-03T00:00:00+08:00"}) + "\n", encoding="utf-8")
    try:
        yield name
    finally:
        shutil.rmtree(tdir, ignore_errors=True)


def cli(*args):
    return subprocess.run([sys.executable, str(ASG_CLI), *args],
                          cwd=VAULT, capture_output=True, text=True)


# ── 影響依賴型的辨識 ────────────────────────────────────────────────
@pytest.mark.parametrize("vc,want", [
    ("gatekeeper-bypass", True),
    ("tcc-bypass", True),
    ("sandbox-escape", True),
    ("codesign-bypass", True),
    ("quarantine-propagation", True),     # quarantine-* 整族
    ("quarantine-anything-else", True),
    ("sql-injection", False),
    ("command-injection", False),
    ("information-disclosure", False),
    ("", False),                           # 沒給就不是，不得擴大打擊面
])
def test_impact_dependent_classification(vc, want):
    assert asg.is_impact_dependent(vc) is want


# ── surfaces_impact_blocked ────────────────────────────────────────
def test_impact_blocked_counts_only_undelivered_impact_dependent(t):
    asg.append_event(t, "surface", name="s-none", untested=True,
                     node_type="unknown", vuln_class="tcc-bypass", delivery="none")
    asg.append_event(t, "surface", name="s-real", untested=True,
                     node_type="unknown", vuln_class="gatekeeper-bypass",
                     delivery="雙擊下載的 dmg")
    asg.append_event(t, "surface", name="s-other", untested=True,
                     node_type="unknown", vuln_class="sql-injection")
    asg.append_event(t, "surface", name="s-bare", untested=True, node_type="unknown")
    blocked = asg.surfaces_impact_blocked(t)
    assert "s-none" in blocked                       # delivery=none → 上限 informational
    assert "s-real" not in blocked                   # 有真路徑
    assert "s-other" not in blocked                  # 不是影響依賴型
    assert "s-bare" not in blocked                   # 沒宣告類別 → 不猜
    assert asg.status(t)["surfaces_impact_blocked"] == 1


def test_impact_dependent_without_delivery_is_also_counted(t):
    """未申報 ≠ 已申報為 none，但兩者在覆蓋率上的意義一樣：影響未知。"""
    asg.append_event(t, "surface", name="s-silent", untested=True,
                     node_type="unknown", vuln_class="tcc-bypass")
    assert "s-silent" in asg.surfaces_impact_blocked(t)


def test_delivery_survives_a_later_event(t):
    """retype／補登不得把開挖前做過的影響判斷靜默弄丟。

    與 surface_blocked 的「後續事件沒帶 = 已解除」刻意相反——
    會悄悄弄丟斷言的寫入路徑，比沒有那個斷言更糟。
    """
    asg.append_event(t, "surface", name="s1", untested=True,
                     node_type="unknown", vuln_class="tcc-bypass",
                     delivery="開啟資料夾看縮圖")
    asg.append_event(t, "surface", name="s1", untested=False, node_type="unknown")
    assert asg.surface_delivery(t)["s1"] == "開啟資料夾看縮圖"
    assert "s1" not in asg.surfaces_impact_blocked(t)


# ── root_cause_exhaustion ──────────────────────────────────────────
def _refute(t, n, **kw):
    for i in range(n):
        asg.record_verdict(t, f"h-{kw.get('vuln_class', kw.get('root_cause'))}-{i}",
                           "refuted", **kw)


def test_three_refuted_same_class_marks_family_exhausted(t):
    _refute(t, 3, vuln_class="tcc-bypass")
    fams = {f["key"]: f for f in asg.root_cause_exhaustion(t)}
    assert "tcc-bypass" in fams
    assert fams["tcc-bypass"]["key_kind"] == "vuln_class"
    assert fams["tcc-bypass"]["refuted"] == 3


def test_two_refuted_is_below_the_floor(t):
    _refute(t, 2, vuln_class="path-traversal")
    assert not any(f["key"] == "path-traversal" for f in asg.root_cause_exhaustion(t))


def test_one_confirmed_keeps_the_family_open(t):
    """這族還有活的就不該喊停——否則第一個洞反而會把後續探索關掉。"""
    _refute(t, 4, vuln_class="command-injection")
    asg.record_verdict(t, "h-hit", "confirmed", vuln_class="command-injection")
    assert not any(f["key"] == "command-injection"
                   for f in asg.root_cause_exhaustion(t))


def test_root_cause_outranks_vuln_class_as_the_grouping_key(t):
    _refute(t, 3, vuln_class="logic-error", root_cause="missing-tenant-check")
    fams = {f["key"]: f["key_kind"] for f in asg.root_cause_exhaustion(t)}
    assert fams.get("missing-tenant-check") == "root_cause"
    assert "logic-error" not in fams


def test_inconclusive_does_not_count_toward_the_floor(t):
    """測了但沒決定不是證據——尤其這類常代表量測工具壞了，不代表這族乾淨。"""
    for i in range(5):
        asg.record_verdict(t, f"h-inc-{i}", "inconclusive", vuln_class="ssrf")
    assert not any(f["key"] == "ssrf" for f in asg.root_cause_exhaustion(t))


def test_record_verdict_reports_exhaustion_at_the_moment_of_recording(t):
    """停損訊號要出現在記下這筆的當下，不是兩天後翻 status 的時候。

    犯錯的時點與讀報表的時點不重合 —— 這是這個停損訊號的整個重點。
    """
    _refute(t, 2, vuln_class="tcc-bypass")
    out = asg.record_verdict(t, "h-third", "refuted", vuln_class="tcc-bypass")
    assert "family_exhausted" in out
    assert "tcc-bypass" in out["family_exhausted"]


def test_status_exposes_both_signals(t):
    asg.append_event(t, "surface", name="s-none", untested=True,
                     node_type="unknown", vuln_class="tcc-bypass", delivery="none")
    _refute(t, 3, vuln_class="gatekeeper-bypass")
    st = asg.status(t)
    assert st["surfaces_impact_blocked"] == 1
    assert [f["key"] for f in st["exhausted_families"]] == ["gatekeeper-bypass"]


# ── CLI 層的硬閘 ───────────────────────────────────────────────────
@pytest.mark.parametrize("extra,want_block", [
    (("--vuln-class", "gatekeeper-bypass"), True),              # 影響依賴型缺 delivery
    (("--vuln-class", "quarantine-propagation"), True),
    (("--vuln-class", "tcc-bypass", "--delivery", "none"), False),
    (("--vuln-class", "tcc-bypass", "--delivery", "雙擊下載檔"), False),
    (("--vuln-class", "sql-injection"), False),                 # 不是影響依賴型
    ((), False),                                                # 沒宣告類別
])
def test_add_surface_requires_delivery_for_impact_dependent(cli_target, extra, want_block):
    r = cli("add-surface", cli_target, f"s{hash(extra) & 0xffff}",
            "--type", "unknown", *extra)
    assert (r.returncode != 0) is want_block, r.stderr


@pytest.mark.parametrize("extra,want_block", [
    ((), True),                                        # refuted 無分組鍵
    (("--vuln-class", "ssrf"), False),
    (("--root-cause", "no-tenant-check"), False),
    (("--unclassified", "跨多類別的架構觀察"), False),   # 明示逃生口
])
def test_record_verdict_requires_a_grouping_key_for_refuted(cli_target, extra, want_block):
    """沒有分組鍵，root_cause_exhaustion 看不到這一筆，家族停損就永遠不會響。

    量過才加的：舊 ledger 裡只有極少數裁決帶鍵。靠自願填寫的欄位實測採用率
    極低，和那些大量無型別的面同一種死法。
    """
    r = cli("record-verdict", cli_target, f"h{hash(extra) & 0xffff}", "refuted", *extra)
    assert (r.returncode != 0) is want_block, r.stderr


@pytest.mark.parametrize("verdict", ["confirmed", "inconclusive"])
def test_grouping_key_is_only_required_for_refuted(cli_target, verdict):
    """不得擴大打擊面：停損訊號只讀 refuted，其餘不該被連坐。"""
    # confirmed verdict requires evidence that resolves; inconclusive does not.
    # Strict gate: free prose is not proof, so cite a real artifact the CLI can pin.
    args = ["record-verdict", cli_target, f"h-{verdict}", verdict]
    if verdict == "confirmed":
        proof = VAULT / "01 - Targets" / cli_target / "proof.txt"
        proof.write_text("controlled fixture evidence bytes", encoding="utf-8")
        args += ["--evidence", "proof.txt"]
    r = cli(*args)
    assert r.returncode == 0, r.stderr


def test_unclassified_escape_hatch_is_auditable(cli_target):
    """逃生口要『明示且可稽核』：理由必須落進 ledger，不是靜默放行。"""
    cli("record-verdict", cli_target, "h-esc", "refuted",
        "--unclassified", "跨多類別的架構觀察")
    evs = [json.loads(l) for l in
           (VAULT / "01 - Targets" / cli_target / ".state" / "asg-events.jsonl")
           .read_text(encoding="utf-8").splitlines() if l.strip()]
    assert any(e.get("unclassified") == "跨多類別的架構觀察" for e in evs)
