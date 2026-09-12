import json
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'automation'))
from hunt_loop import HuntLoop
from hunt_integration import import_bbflow, record_lesson, retrieve_lessons, handoff


def fixture_run(path):
    (path / 'proof.txt').write_text('candidate observation, not proof of vulnerability')
    (path / 'run_manifest.json').write_text(json.dumps(dict(run_id='r1', target='local-fixture', started_at='test', tool_versions={}, scope_contract={}, scan_level=0)))
    # bbflow output-contract shape (bbflow/output-contract.md)
    row = dict(candidate_id='c1', asset='local-object', candidate_type='idor',
               category='access-control', evidence_ref='proof.txt', review_status='new')
    (path / 'candidates.jsonl').write_text(json.dumps(row)+'\n')
    return row


def test_import_learning_reload_and_evidence_integrity(tmp_path):
    fixture_run(tmp_path)
    lp = HuntLoop()
    assert import_bbflow(lp, tmp_path) == 1
    assert import_bbflow(lp, tmp_path) == 0
    assert lp.capsule()['confirmed'] == {}
    hid = lp.capsule()['ready_hypotheses'][0]
    record_lesson(lp, 'control', ['idor'], 'Compare owner and non-owner responses', tmp_path/'proof.txt')
    assert retrieve_lessons(lp, hid, ['idor'])[0]['lesson_id'] == 'control'
    lp.save(tmp_path/'ledger.jsonl')
    restored = HuntLoop.load(tmp_path/'ledger.jsonl')
    assert handoff(restored) == handoff(lp)
    (tmp_path/'proof.txt').write_text('changed')
    assert handoff(restored)['priority']['evidence_problems']


def test_import_rejects_escaping_artifact_without_partial_write(tmp_path):
    row = fixture_run(tmp_path)
    bad = dict(row, candidate_id='c2', evidence_ref='../outside')
    (tmp_path/'candidates.jsonl').write_text(json.dumps(row)+'\n'+json.dumps(bad))
    lp = HuntLoop()
    with pytest.raises(ValueError):
        import_bbflow(lp, tmp_path)
    assert lp.events == []


def test_changed_duplicate_is_not_silently_ignored(tmp_path):
    row = fixture_run(tmp_path)
    lp = HuntLoop()
    import_bbflow(lp, tmp_path)
    row['asset'] = 'other'
    (tmp_path/'candidates.jsonl').write_text(json.dumps(row))
    with pytest.raises(ValueError):
        import_bbflow(lp, tmp_path)


def test_real_process_output_persists_without_confirming(tmp_path):
    from hunt_integration import execute_command
    lp = HuntLoop()
    lp.add_hypothesis('h')
    ledger = tmp_path/'ledger'
    assert execute_command(lp, ledger, 'h', 'a', [sys.executable, '-c', 'print("controlled observation")'], tmp_path/'out')
    restored = HuntLoop.load(ledger)
    assert restored.capsule()['confirmed'] == {}
    assert not handoff(restored)['priority']['in_flight_requires_reconciliation']
    assert (tmp_path/'out').read_text().strip() == 'controlled observation'
    with pytest.raises(ValueError):
        execute_command(restored, ledger, 'h', 'a', [sys.executable], tmp_path/'out2')


def test_crash_after_intent_cannot_replay(tmp_path):
    from hunt_integration import execute_command
    lp = HuntLoop()
    lp.add_hypothesis('h')
    lp.append('action_started', action_id='a', hyp_id='h', argv=['unused'])
    lp.save(tmp_path/'ledger')
    restored = HuntLoop.load(tmp_path/'ledger')
    assert handoff(restored)['priority']['in_flight_requires_reconciliation'][0]['action_id'] == 'a'
    with pytest.raises(ValueError):
        execute_command(restored, tmp_path/'ledger', 'h', 'a', [sys.executable], tmp_path/'out')


def test_real_process_failure_remains_observation(tmp_path):
    from hunt_integration import execute_command
    lp = HuntLoop()
    lp.add_hypothesis('h')
    assert not execute_command(lp, tmp_path/'ledger', 'h', 'a', [sys.executable, '-c', 'raise SystemExit(2)'], tmp_path/'out')
    assert lp.capsule()['refuted'] == []


def test_full_output_contract_candidate_is_ingested_as_lead(tmp_path):
    """A candidates.jsonl in the FULL bbflow output-contract shape imports cleanly,
    stays a review LEAD (hypothesis, never confirmed), and keeps its routing fields."""
    (tmp_path / 'run_manifest.json').write_text(json.dumps(dict(
        run_id='r1', target='local-fixture', started_at='t', tool_versions={},
        scope_contract={}, scan_level=0)))
    (tmp_path / 'obs.txt').write_text('http response snippet')
    row = {
        "schema version": 1, "candidate_id": "c9", "asset": "asset-1",
        "category": "access-control", "candidate_type": "idor",
        "evidence_hint": "http_response", "chain_potential": "medium",
        "requires_scope_safety": False, "suggested_skill": "bb-attack-chain-review",
        "evidence_ref": "obs.txt", "review_status": "new", "knowledge_capture": "none",
    }
    (tmp_path / 'candidates.jsonl').write_text(json.dumps(row) + '\n')
    lp = HuntLoop()
    assert import_bbflow(lp, tmp_path) == 1
    assert lp.capsule()['confirmed'] == {}                 # I1: a hit is not a finding
    ev = [e for e in lp.events if e['kind'] == 'bbflow_candidate'][-1]
    assert ev['candidate']['candidate_type'] == 'idor'
    assert ev['candidate']['review_status'] == 'new'
    assert ev['candidate']['suggested_skill'] == 'bb-attack-chain-review'
    assert ev['artifacts'][0]['sha256']                    # local evidence hashed


def test_remote_argv_wraps_ssh_safely():
    from hunt_integration import remote_argv
    assert remote_argv("vps-host", ["curl", "-s", "https://x/api"]) == \
        ["ssh", "vps-host", "--", "curl", "-s", "https://x/api"]
    with pytest.raises(ValueError):
        remote_argv("evil; rm -rf /", ["curl"])   # shell metachars in host rejected
    with pytest.raises(ValueError):
        remote_argv("host", [])                    # empty argv rejected
