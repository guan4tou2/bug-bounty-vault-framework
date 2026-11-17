"""Observable import behavior on fixed, offline scanner samples."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
import asg
from hunt_lock import ConcurrentWriter, acquire, release
from hunt_loop import HuntLoop
from scan_import import evidence_valid, import_scan, parse_scan

NUCLEI = {"template-id": "fixture-control", "matched-at": "https://fixture.invalid/api",
          "type": "http", "info": {"severity": "medium"},
          "request": "Authorization: private-fixture-value", "response": "private fixture body"}
NMAP = b'''<?xml version="1.0"?><!DOCTYPE nmaprun SYSTEM "nmap.dtd">
<nmaprun scanner="nmap" version="7.95"><host><status state="up"/>
<address addr="192.0.2.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
<port protocol="tcp" portid="22"><state state="closed"/></port></ports></host>
<runstats><finished exit="success"/></runstats></nmaprun>'''


@pytest.fixture
def env(tmp_path, monkeypatch):
    td = tmp_path / "01 - Targets" / "fixture"
    td.mkdir(parents=True)
    monkeypatch.setattr(asg, "vault_root", lambda: tmp_path)
    asg.append_event(td, "genesis", profile="source-audit")
    source = tmp_path / "nuclei.jsonl"
    source.write_text("\n" + json.dumps(NUCLEI) + "\n")
    manifest = {"run_id": "local-run-1", "scope_ref": "scope:fixture", "tool_version": "3.5.1",
                "started_at": "2020-01-01T00:00:00Z", "execution_status": "completed",
                "model_processing_policy": {"allowed_locations": ["fixture"]}}
    context = {"account_ref": "account:A", "role": "member", "conditions": {"tenant_ref": "tenant:1"},
               "version": "fixture:1", "settings": {}, "environment": "lab:fixture"}
    asg.append_event(td, "evidence_context", context_id="target", context=context)
    return td, source, manifest, context


def events(td, kind):
    return [e for e in HuntLoop.load(asg.ledger_path(td)).events if e["type"] == kind]


def test_import_reload_exact_locator_and_immutable_original(env):
    td, source, manifest, context = env
    result = import_scan(td, source, "nuclei-jsonl", manifest, context)
    assert result["status"] == "success"
    assert result["queued"] == 1
    assert import_scan(td, source, "nuclei-jsonl", manifest, context)["imported"] == 0
    assert len(events(td, "candidate_analysis_queued")) == 1
    candidate = events(td, "scan_candidate")[0]
    assert candidate["artifacts"][0]["locator"] == {"kind": "jsonl", "line": 2}
    assert evidence_valid(candidate["artifacts"][0])
    assert candidate["source"]["parser_version"]
    assert candidate["candidate"]["context"] == context
    assert HuntLoop.load(asg.ledger_path(td)).capsule()["confirmed"] == {}
    assert not events(td, "verdict")
    assert "private-fixture-value" not in asg.ledger_path(td).read_text()
    original = source.read_bytes()
    source.write_text("changed source")
    assert Path(candidate["artifacts"][0]["path"]).read_bytes() == original
    assert evidence_valid(candidate["artifacts"][0])
    with pytest.raises(ValueError, match="changed evidence"):
        import_scan(td, source, "nuclei-jsonl", manifest, context)


@pytest.mark.parametrize("change", [{"account_ref": "account:B"}, {"role": "admin"},
                                  {"conditions": {"tenant_ref": "tenant:2"}}])
def test_same_location_different_test_context_is_not_merged(env, change):
    td, source, manifest, context = env
    import_scan(td, source, "nuclei-jsonl", manifest, context)
    import_scan(td, source, "nuclei-jsonl", manifest, {**context, **change})
    leads = events(td, "scan_candidate")
    assert len(leads) == 2
    assert leads[0]["candidate_id"] != leads[1]["candidate_id"]


@pytest.mark.parametrize("raw,status,count", [(b"", "empty", 0), (b"\n ", "empty", 0),
                                              (b"{broken", "failed", 0),
                                              (b'{}', "failed", 0),
                                              (json.dumps(NUCLEI).encode()+b"\n{broken", "partial", 1)])
def test_zero_corrupt_and_partial_are_distinct(raw, status, count):
    parsed = parse_scan(raw, "nuclei-jsonl")
    assert parsed["status"] == status
    assert len(parsed["records"]) == count
    assert bool(parsed["errors"]) == (status in ("failed", "partial"))


def test_failed_execution_cannot_be_a_clean_empty_scan(env):
    td, source, manifest, context = env
    source.write_bytes(b"")
    receipt = import_scan(td, source, "nuclei-jsonl", {**manifest, "execution_status": "timed_out"}, context)
    assert receipt["status"] == "failed"
    assert len(events(td, "scan_import")) == 1
    assert events(td, "scan_candidate") == []


def test_nmap_services_have_exact_nodes_and_never_become_candidates(env):
    td, source, manifest, context = env
    source.write_bytes(NMAP)
    result = import_scan(td, source, "nmap-xml", manifest, context)
    assert result["status"] == "success"
    observations = events(td, "scan_observation")
    assert len(observations) == 2
    assert observations[1]["candidate"]["port"] == 443
    assert all(evidence_valid(e["artifacts"][0]) for e in observations)
    assert events(td, "scan_candidate") == []
    assert events(td, "hypothesis") == []


def test_nmap_completion_corruption_and_entities():
    assert parse_scan(NMAP.replace(b'exit="success"', b'exit="error"'), "nmap-xml")["status"] == "partial"
    empty = b'<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'
    assert parse_scan(empty, "nmap-xml")["status"] == "empty"
    assert parse_scan(NMAP[:-10], "nmap-xml")["status"] == "failed"
    malicious = b'<!DOCTYPE nmaprun [<!ENTITY x "abc">]><nmaprun>&x;</nmaprun>'
    assert parse_scan(malicious, "nmap-xml")["status"] == "failed"


def test_negative_match_is_observation_not_candidate(env):
    td, source, manifest, context = env
    source.write_text(json.dumps({**NUCLEI, "matcher-status": False}))
    import_scan(td, source, "nuclei-jsonl", manifest, context)
    assert events(td, "scan_candidate") == []
    assert len(events(td, "scan_observation")) == 1


def test_evidence_tampering_and_wrong_locator_fail(env):
    td, source, manifest, context = env
    import_scan(td, source, "nuclei-jsonl", manifest, context)
    artifact = events(td, "scan_candidate")[0]["artifacts"][0]
    assert not evidence_valid({**artifact, "locator": {"kind": "jsonl", "line": 99}})
    Path(artifact["path"]).write_text("tampered")
    assert not evidence_valid(artifact)
    with pytest.raises(ValueError, match="archived evidence"):
        import_scan(td, source, "nuclei-jsonl", manifest, context)


def test_writer_lock_and_required_context(env):
    td, source, manifest, context = env
    token = acquire(asg.ledger_path(td), "other-writer")
    try:
        with pytest.raises(ConcurrentWriter):
            import_scan(td, source, "nuclei-jsonl", manifest, context)
    finally:
        release(asg.ledger_path(td), token)
    with pytest.raises(ValueError, match="context requires"):
        import_scan(td, source, "nuclei-jsonl", manifest, {})
    with pytest.raises(ValueError, match="credentials"):
        import_scan(td, source, "nuclei-jsonl", manifest, {**context, "token": "private"})
    assert not events(td, "scan_import")


def test_cli_import_to_canonical_ledger_and_failure_exit(env):
    td, source, manifest, context = env
    manifest_path, context_path = source.parent / "manifest.json", source.parent / "context.json"
    manifest_path.write_text(json.dumps(manifest))
    context_path.write_text(json.dumps(context))
    command = [sys.executable, str(Path(__file__).resolve().parents[1] / "automation/scan_import.py"),
               "fixture", "nuclei-jsonl", str(source), "--manifest", str(manifest_path),
               "--context", str(context_path)]
    process_env = {**os.environ, "VAULT_ROOT": str(td.parent.parent)}
    result = subprocess.run(command, capture_output=True, text=True, env=process_env, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["queued"] == 1
    assert len(events(td, "scan_candidate")) == 1
    source.write_text("{broken")
    manifest_path.write_text(json.dumps({**manifest, "run_id": "run-broken"}))
    broken = subprocess.run(command, capture_output=True, text=True, env=process_env, check=False)
    assert broken.returncode == 1
    assert json.loads(broken.stdout)["status"] == "failed"
    assert len(events(td, "scan_candidate")) == 1


def test_nonstandard_json_and_invalid_evidence_locators_are_rejected():
    assert parse_scan(b'{"template-id":"x","host":"x","info":{"severity":NaN}}',
                      "nuclei-jsonl")["status"] == "failed"


def test_cross_run_identical_results_keep_logical_identity_and_analysis(env):
    td, source, manifest, context = env
    import_scan(td, source, "nuclei-jsonl", manifest, context)
    import_scan(td, source, "nuclei-jsonl", {**manifest, "run_id": "next-run"}, context)
    leads = events(td, "scan_candidate")
    assert len(leads) == 2  # source/run history is retained
    assert len({e["candidate_id"] for e in leads}) == 1
    assert len(events(td, "hypothesis")) == 1
    assert len(events(td, "candidate_analysis_queued")) == 1


def test_relocated_vault_keeps_import_and_logical_candidate_identity(env, tmp_path, monkeypatch):
    import shutil
    td, source, manifest, context = env
    import_scan(td, source, "nuclei-jsonl", manifest, context)
    before = events(td, 'scan_candidate')[0]['candidate_id']
    relocated_root = tmp_path / 'relocated-vault'
    relocated = relocated_root / '01 - Targets' / td.name
    shutil.copytree(td, relocated)
    monkeypatch.setattr(asg, 'vault_root', lambda: relocated_root)
    assert import_scan(td.name, source, 'nuclei-jsonl', manifest, context)['duplicate']
    import_scan(td.name, source, 'nuclei-jsonl', {**manifest, 'run_id': 'next-run'}, context)
    assert {e['candidate_id'] for e in events(relocated, 'scan_candidate')} == {before}


def test_new_evidence_keeps_candidate_and_stales_prior_analysis(env):
    from candidate_analysis import analysis_view
    td, source, manifest, context = env
    import_scan(td, source, "nuclei-jsonl", manifest, context)
    source.write_text(json.dumps({**NUCLEI, "response": "new observed fixture body"}))
    import_scan(td, source, "nuclei-jsonl", {**manifest, "run_id": "next-run"}, context)
    leads = events(td, "scan_candidate")
    assert len({e["candidate_id"] for e in leads}) == 1
    assert len(events(td, "hypothesis")) == 1
    assert leads[0]["artifacts"][0]["sha256"] != leads[1]["artifacts"][0]["sha256"]
    analyses = analysis_view(HuntLoop.load(asg.ledger_path(td)))
    assert len(analyses) == 2
    assert analyses[0]["stale"]
    assert not analyses[1]["stale"]
