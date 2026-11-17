"""Execution views preserve identities and distinguish missing exit evidence."""
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from asg_command_runs import action_runs, load_runs, project


def test_legacy_ids_survive_prepend_and_unknown_is_not_success(tmp_path):
    state = tmp_path / ".state"
    state.mkdir()
    path = state / "recon_runs.jsonl"
    row = {"type": "command_run", "cmd": "nmap example.com", "dim": "live_host_port"}
    path.write_text(json.dumps(row) + "\n")
    original = load_runs(tmp_path)[0]
    path.write_text(json.dumps({**row, "cmd": "httpx example.com", "exit_code": 0}) + "\n" +
                    json.dumps(row) + "\n[]\n{bad\n")
    assert load_runs(tmp_path)[1]["id"] == original["id"]
    assert original["status"] == "unknown"
    assert "started_at" not in original
    assert project(load_runs(tmp_path))["live_host_port"]["statuses"] == {"succeeded": 1, "unknown": 1}


def test_action_attempts_remain_separate_and_show_recovery():
    events = [
        {"type": "action_started", "action_id": "a1", "argv": ["tool", "one value"], "at": "t1"},
        {"type": "action_running", "action_id": "a1", "pid": 123},
        {"type": "action_finished", "action_id": "a1", "status": "interrupted", "at": "t2",
         "exit_ok": False, "sha256": "abc", "output_ref": "raw.txt"},
        {"type": "action_started", "action_id": "a2", "argv": ["tool"], "at": "t3"},
    ]
    first, second = action_runs(events)
    assert first["id"] == "a1" and first["status"] == "interrupted"
    assert first["started_at"] == "t1" and first["finished_at"] == "t2"
    assert first["command"] == "tool 'one value'"
    assert first["output_ref"] == "raw.txt" and first["sha256"] == "abc"
    assert second["id"] == "a2" and second["status"] == "running"


def test_completed_attempt_detects_missing_or_changed_evidence(tmp_path):
    import hashlib
    path = tmp_path / "raw"
    path.write_bytes(b"original")
    events = [{"type": "action_started", "action_id": "a", "argv": ["tool"]},
              {"type": "action_finished", "action_id": "a", "status": "completed",
               "output_ref": str(path), "sha256": hashlib.sha256(b"original").hexdigest()}]
    assert action_runs(events)[0]["evidence_status"] == "valid"
    path.write_bytes(b"changed")
    assert action_runs(events)[0]["evidence_status"] == "changed"
    assert action_runs(events)[0]["stale"]
    path.unlink()
    assert action_runs(events)[0]["evidence_status"] == "missing"


def test_post_tool_hook_records_unknown_without_leaking_command(tmp_path):
    import hashlib
    root = Path(__file__).resolve().parents[1]
    target = tmp_path / "01 - Targets" / "fixture"
    target.mkdir(parents=True)
    payload = {"tool_name": "Bash", "tool_use_id": "fixture-call", "session_id": "fixture-session",
               "tool_input": {"command": "dig --token do-not-copy-this-secret example.invalid"},
               "tool_response": {"stdout": "測試\n"}}
    result = subprocess.run(["bash", str(root / "automation/recon_ingest.sh")],
                            input=json.dumps(payload), text=True, capture_output=True, cwd=target,
                            env={**os.environ, "VAULT_ROOT": str(tmp_path)}, timeout=30)
    assert result.returncode == 0
    recorded = (target / ".state/recon_runs.jsonl").read_text()
    assert "do-not-copy-this-secret" not in recorded
    row = load_runs(target)[0]
    assert row["id"] == "recon-fixture-call" and row["status"] == "unknown"
    assert row["out_bytes"] == len("測試\n".encode())
    assert row["output_sha256"] == hashlib.sha256("測試\n".encode()).hexdigest()
