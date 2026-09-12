"""lesson_candidates — auto-draft LL candidates from the ASG ledger (policy A)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
import asg  # noqa: E402
from hunt_loop import HuntLoop  # noqa: E402
import lesson_candidates as lc  # noqa: E402


def _ledger(tmp_path, events):
    led = tmp_path / "t" / ".state" / "asg-events.jsonl"
    led.parent.mkdir(parents=True, exist_ok=True)
    loop = HuntLoop.load(led)
    for k, d in events:
        loop.append(k, **d)
    loop.save(led)
    return led


def test_drafts_only_generalisable_refuted_and_deadends(tmp_path, monkeypatch):
    led = _ledger(tmp_path, [
        # refuted WITH a logic reason -> candidate
        ("logic_hypothesis", {"hyp_id": "H1", "dimension": "trust", "invariant": "denylist blocks proto"}),
        ("logic_verdict", {"hyp_id": "H1", "verdict": "refuted", "reason": "control also 403; default behaviour",
                           "test_outcome": "403", "control_outcome": "403"}),
        ("verdict", {"hyp_id": "H1", "verdict": "refuted"}),
        # refuted via hand-recorded evidence_ref (no logic_verdict) -> candidate
        ("verdict", {"hyp_id": "H2", "verdict": "refuted", "evidence_ref": "explicit path guards present"}),
        # dead_end generalisable + reopen -> candidate
        ("dead_end", {"hyp_id": "H3", "cause": "inconclusive-exhausted",
                      "reopen_when": "dynamic env ready", "scope": {"role": "anon"}}),
        # BLOCKED (env-gated) -> NOT a lesson
        ("verdict", {"hyp_id": "H4", "verdict": "blocked"}),
        # CONFIRMED (a finding) -> NOT a candidate
        ("verdict", {"hyp_id": "H5", "verdict": "confirmed", "evidence_ref": "poc/x", "provides": ["P:x"]}),
        # refuted with NO reusable content -> skipped
        ("verdict", {"hyp_id": "H6", "verdict": "refuted"}),
    ])
    monkeypatch.setattr(asg, "ledger_path", lambda t: led)
    monkeypatch.setattr(lc, "_existing_ll_titles", lambda: [])  # no dedup interference

    cands = lc.draft_candidates(tmp_path / "t")
    ids = {c["hyp_id"] for c in cands}
    assert ids == {"H1", "H2", "H3"}                 # blocked/confirmed/empty excluded
    h1 = next(c for c in cands if c["hyp_id"] == "H1")
    assert "default behaviour" in h1["rule"] and "control比較" in h1["rule"].replace(" ", "")
    h3 = next(c for c in cands if c["hyp_id"] == "H3")
    assert "dynamic env ready" in h3["rule"]         # reopen condition carried


def test_write_stages_outside_the_LL_glob_and_dedups(tmp_path, monkeypatch):
    led = _ledger(tmp_path, [
        ("logic_hypothesis", {"hyp_id": "H1", "dimension": "trust", "invariant": "denylist protocol validation bypass"}),
        ("logic_verdict", {"hyp_id": "H1", "verdict": "refuted", "reason": "r", "test_outcome": "a", "control_outcome": "a"}),
        ("verdict", {"hyp_id": "H1", "verdict": "refuted"}),
    ])
    stage = tmp_path / "stage"
    monkeypatch.setattr(asg, "ledger_path", lambda t: led)
    monkeypatch.setattr(asg, "_basename", lambda t: "t")
    monkeypatch.setattr(lc, "_staging_dir", lambda: stage)
    monkeypatch.setattr(lc, "_existing_ll_titles", lambda: [])

    written = lc.write_candidates(tmp_path / "t")
    assert len(written) == 1
    p = written[0]
    assert p.exists() and p.parent == stage
    # staging filename must NOT match the curated KB's LL-*.md retrieval glob
    assert not p.name.startswith("LL-") and p.name.startswith("CAND-")
    assert "status: candidate" in p.read_text()

    # dedup: an existing LL covering the same title -> skipped
    monkeypatch.setattr(lc, "_existing_ll_titles", lambda: ["denylist protocol validation is a default"])
    assert lc.write_candidates(tmp_path / "t") == []
