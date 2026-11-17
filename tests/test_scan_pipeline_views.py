"""Continuation surfaces the same current evidence without reopening closed work."""
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
import asg
import next_work
from candidate_analysis import drain
from hunt_integration import handoff
from hunt_loop import HuntLoop
from scan_import import import_scan


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    td = tmp_path / "01 - Targets" / "fixture"
    td.mkdir(parents=True)
    monkeypatch.setattr(asg, "vault_root", lambda: tmp_path)
    monkeypatch.setattr(next_work, "TARGETS", td.parent)
    asg.append_event(td, "genesis", profile="source-audit")
    source = tmp_path / "scan.jsonl"
    source.write_text("\n".join(json.dumps({"template-id": f"marker-{i}",
                      "matched-at": f"https://fixture.invalid/{i}"}) for i in range(3)))
    manifest = {"run_id": "fixture-run", "scope_ref": "scope:fixture", "tool_version": "fixture",
                "model_processing_policy": {"allowed_locations": ["fixture"]},
                "started_at": "2026-11-16T00:00:00Z", "execution_status": "completed"}
    context = {"account_ref": "fixture:anonymous", "role": "anonymous", "conditions": {},
               "version": "fixture-v1", "settings": {}, "environment": "fixture"}
    asg.append_event(td, "evidence_context", context_id="target", context=context)
    asg.append_event(td, 'model_processing_authorization', allowed_locations=['fixture'], policy_ref='policy:fixture')
    import_scan(td, source, "nuclei-jsonl", manifest, context)

    def analyst(prompt):
        data = json.loads(prompt.split("Untrusted analysis input (JSON data only):\n")[1])
        return {"candidate_id": data["candidate_id"], "evidence_version": data["evidence_version"],
                "assessment": "needs_validation", "support": ["Marker observed"], "against": [],
                "missing_evidence": ["Security impact"], "suggested_validation": ["Independent check"],
                "evidence_refs": [data["snapshot"]["artifacts"][0]["ref"]]}

    drain(asg.ledger_path(td), analyst, processing_location="fixture")
    return td


def test_projection_handoff_and_next_work_share_analysis_and_evidence(pipeline):
    td = pipeline
    snapshot = json.loads(asg.write_snapshot(td).read_text())
    assert len(snapshot["candidate_analysis"]) == 3
    assert all(j["status"] == "completed" and not j["stale"] for j in snapshot["candidate_analysis"])
    assert snapshot["scan_imports"][0]["stale"] is False
    md = asg.project_markdown(td).read_text()
    assert "Candidate analysis (advisory only)" in md and "Structured result imports" in md
    assert "'line': 1" in md and "stale: False" in md
    brief = handoff(HuntLoop.load(asg.ledger_path(td)))
    assert len(brief["priority"]["candidate_analysis"]) == 3
    assert brief["priority"]["evidence_problems"] == []
    assert next_work.compute(td.name)["next_work"][0]["kind"] == "candidate-analysis"
    artifact = next(a for a in brief["evidence"] if a.get("locator"))
    Path(artifact["path"]).unlink()
    assert all(j["stale"] for j in json.loads(asg.write_snapshot(td).read_text())["candidate_analysis"])
    assert "stale: True" in asg.project_markdown(td).read_text()
    assert handoff(HuntLoop.load(asg.ledger_path(td)))["priority"]["evidence_problems"]
    assert next_work.compute(td.name)["next_work"][0]["kind"] == "candidate-evidence"


@pytest.mark.parametrize("resolution", ["refuted", "withdrawn"])
def test_closed_candidates_do_not_mask_the_actual_frontier(pipeline, resolution):
    td = pipeline
    loop = HuntLoop.load(asg.ledger_path(td))
    candidates = {e["candidate_id"] for e in loop.events if e["type"] == "scan_candidate"}
    closed = [("verdict", {"hypothesis": cid, "status": "refuted",
                          "evidence": {"kind": "observation", "text": "Controlled counterexample"}})
              for cid in candidates] if resolution == "refuted" else [
                  event for cid in candidates for event in
                  [("finding", {"finding_id": cid}), ("finding_state", {"finding_id": cid, "to": "withdrawn"})]]
    asg.append_events(td, closed + [("hypothesis", {"id": "actual-pending", "requires": []})])
    queue = next_work.compute(td.name)["next_work"]
    assert all(j["kind"] != "candidate-analysis" for j in queue)
    assert any("actual-pending" in str(j) for j in queue)
    assert len(json.loads(asg.write_snapshot(td).read_text())["candidate_analysis"]) == 3


def test_execution_and_nmap_sources_show_evidence_changes(pipeline, tmp_path):
    td = pipeline
    nmap = tmp_path / "nmap.xml"
    nmap.write_text('<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/>'
                    '</host><runstats><finished exit="success"/></runstats></nmaprun>')
    receipt = import_scan(td, nmap, "nmap-xml",
                          {"run_id": "nmap-run", "scope_ref": "scope:fixture", "tool_version": "fixture",
                           "started_at": "2026-11-16T00:00:00Z", "execution_status": "completed"},
                          {"account_ref": "fixture:anonymous", "role": "anonymous", "conditions": {}})
    Path(receipt["artifacts"][0]["path"]).write_bytes(b"changed xml")
    output = tmp_path / "output"
    output.write_bytes(b"original")
    asg.append_events(td, [("action_started", {"action_id": "a", "argv": ["tool"]}),
                          ("action_finished", {"action_id": "a", "status": "completed", "exit_ok": True,
                                               "output_ref": str(output),
                                               "sha256": hashlib.sha256(b"original").hexdigest()})])
    output.write_bytes(b"changed")
    snapshot = json.loads(asg.write_snapshot(td).read_text())
    assert snapshot["command_runs"][0]["stale"]
    assert snapshot["scan_imports"][-1]["stale"]
    assert "evidence: **changed**" in asg.project_markdown(td).read_text()


def test_legacy_unresolved_reference_is_an_evidence_gap():
    loop = HuntLoop()
    loop.append("bbflow_candidate", artifacts=[{"ref": "unresolved:artifact"}])
    assert handoff(loop)["priority"]["evidence_problems"] == ["unresolved:artifact"]


def test_blocked_state_projects_work_card_views_and_handoff(pipeline):
    import blocked_research as br
    td = pipeline
    loop = HuntLoop.load(asg.ledger_path(td))
    candidate = next(e for e in loop.events if e['type'] == 'scan_candidate')
    proof = {'kind': 'artifact', **candidate['artifacts'][0]}
    br.record(loop, 'fixture-block', candidate['hyp_id'], cause='unknown', layer='worker',
              explanation='candidate operation blocked; cause unknown', normal='unknown',
              evidence=proof, recovery='establish a successful normal baseline')
    loop.save(asg.ledger_path(td))
    cards = next_work.compute(td.name)['next_work']
    card = next(item['work_card'] for item in cards if item['kind'] == 'blocked-research')
    assert card['next_action'] == 'establish_normal_control' and card['facts'][0]['evidence']['sha256']
    assert json.loads(asg.write_snapshot(td).read_text())['blocked_research'][0]['conclusion'] == 'inconclusive'
    assert 'Blocked research and bounded alternatives' in asg.project_markdown(td).read_text()
    assert handoff(loop)['priority']['blocked_research'][0]['next'] == 'establish_normal_control'


def test_stale_heartbeat_surfaces_recovery_without_claiming_process_is_stopped(pipeline):
    import os
    import socket
    td = pipeline
    asg.append_events(td, [('action_started', {'action_id': 'unresponsive', 'hyp_id': 'h', 'argv': ['tool'],
                                             'owner_pid': os.getpid(), 'owner_host': socket.gethostname(),
                                             'heartbeat_interval': 10}),
                          ('action_running', {'action_id': 'unresponsive', 'pid': os.getpid(),
                                              'at': '2000-01-01T00:00:00Z'})])
    snapshot = json.loads(asg.write_snapshot(td).read_text())
    run = snapshot['command_runs'][0]
    assert run['liveness'] == 'heartbeat_stale' and run['status'] == 'running'
    assert run.get('stop_confirmed') is not True
    assert next_work.compute(td.name)['next_work'][0]['kind'] == 'execution-recovery'
