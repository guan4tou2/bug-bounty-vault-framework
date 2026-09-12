"""hunt_session resume/recovery entry — the takeover-correctness cases.

Completion-standard slice: after a compaction/interrupt, a resumed session must
recover the right state and continue correctly — specifically it must NOT lose an
interrupted action and must NOT blindly re-run it.
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from hunt_loop import HuntLoop, Verdict  # noqa: E402
from hunt_session import resume_brief, inflight_actions, next_action, dead_paths  # noqa: E402

SESSION = Path(__file__).resolve().parents[1] / "automation" / "hunt_session.py"


def test_resume_points_at_ready_hypothesis():
    lp = HuntLoop()
    lp.add_hypothesis("h1")
    b = resume_brief(lp)
    assert b["ready_hypotheses"] == ["h1"]
    assert b["inflight_actions"] == []
    assert "RUN hypothesis 'h1'" in b["next_action"]


def test_interrupted_action_is_flagged_and_not_rerun(tmp_path):
    # crash-safe design: execute_command saves the ledger right after action_started,
    # before action_finished. Simulate a compaction landing in that window.
    ledger = tmp_path / "l.jsonl"
    lp = HuntLoop()
    lp.add_hypothesis("h1")
    lp.append("action_started", action_id="probe1", hyp_id="h1",
              argv=["curl", "..."], output_ref=str(tmp_path / "o.txt"))
    lp.save(ledger)                       # <-- interrupt happens here (no finished)

    # takeover: a fresh session loads the ledger.
    resumed = HuntLoop.load(ledger)
    b = resume_brief(resumed)
    assert b["inflight_actions"] == ["probe1"]                 # not lost
    assert b["next_action"].startswith("RECONCILE interrupted action 'probe1'")  # reconcile first, no blind re-run


def test_reconciled_action_clears_inflight():
    lp = HuntLoop()
    lp.add_hypothesis("h1")
    lp.append("action_started", action_id="probe1", hyp_id="h1", argv=["x"], output_ref="o")
    assert inflight_actions(lp) == ["probe1"]
    lp.append("action_finished", action_id="probe1", hyp_id="h1", exit_ok=True, output_ref="o")
    assert inflight_actions(lp) == []                          # reconciled -> cleared
    b = resume_brief(lp)
    assert "RECONCILE" not in b["next_action"]                 # moved on


def test_reconcile_takes_priority_over_ready_work():
    lp = HuntLoop()
    lp.add_hypothesis("h_ready")
    lp.append("action_started", action_id="probe1", hyp_id="h_ready", argv=["x"], output_ref="o")
    b = resume_brief(lp)
    # even though h_ready is "ready", the interrupt must be reconciled first.
    assert b["next_action"].startswith("RECONCILE")


def test_dispute_and_untested_surface_next_steps():
    lp = HuntLoop()
    lp.add_hypothesis("d")
    lp.record_verdict("d", Verdict.CONFIRMED, evidence_ref="a")
    lp.record_verdict("d", Verdict.REFUTED, evidence_ref="b")   # -> disputed
    assert resume_brief(lp)["next_action"].startswith("RESOLVE dispute on 'd'")

    lp2 = HuntLoop()
    lp2.add_surface("ep1", untested=True)
    assert resume_brief(lp2)["next_action"].startswith("MAP/HYPOTHESISE")


def test_cli_resume_runs_as_entrypoint(tmp_path):
    ledger = tmp_path / "l.jsonl"
    lp = HuntLoop(); lp.add_hypothesis("h1"); lp.save(ledger)
    out = subprocess.run([sys.executable, str(SESSION), "resume", str(ledger)],
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0
    assert "hunt resume brief" in out.stdout
    assert "NEXT →" in out.stdout
    # status subcommand too
    st = subprocess.run([sys.executable, str(SESSION), "status", str(ledger)],
                        capture_output=True, text=True, timeout=30)
    assert st.stdout.strip() == "running"


# the takeover must SEE the dead-end graveyard, or it re-treads a refuted path.
# autodrive records dead ends inside the loop; the resume brief for a human/
# compaction handoff previously dropped them (§8: handoff must carry reopen conditions).
def test_resume_surfaces_scoped_dead_paths_with_reopen(tmp_path):
    ledger = tmp_path / "l.jsonl"
    lp = HuntLoop()
    lp.add_hypothesis("idor_anon")
    # shape matches autodrive.record_dead_end
    lp.append("dead_end", hyp_id="idor_anon", cause="refuted",
              scope={"version": "v3", "role": "anonymous", "host": "api"},
              surface_id="checkout", reopen_when="an authenticated session is obtained")
    lp.save(ledger)

    b = resume_brief(HuntLoop.load(ledger))         # fresh takeover
    assert b["dead_paths"] == [{
        "hyp_id": "idor_anon", "cause": "refuted",
        "scope": {"version": "v3", "role": "anonymous", "host": "api"},
        "reopen_when": "an authenticated session is obtained",
    }]
    # latest-wins: a later reopen/re-death updates in place, not duplicates
    lp2 = HuntLoop.load(ledger)
    lp2.append("dead_end", hyp_id="idor_anon", cause="blocked",
               scope={}, reopen_when="account provisioned")
    assert [d["cause"] for d in dead_paths(lp2)] == ["blocked"]


# vault-97 friction #3d: resume on a nonexistent ledger warns (typo vs new hunt).
def test_missing_ledger_is_flagged(tmp_path):
    missing = tmp_path / "does_not_exist.jsonl"
    out = subprocess.run([sys.executable, str(SESSION), "resume", str(missing)],
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0
    assert "ledger not found" in out.stdout
