"""Integrity alone does not make historical evidence applicable today."""
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
import asg
from evidence_applicability import assess_artifact, assess_evidence, latest_context, record_context
from evidence_refs import evidence_resolves, normalize_evidence
from hunt_loop import HuntLoop
from scan_import import import_scan

CONTEXT = {"version": "release:1", "role": "member", "settings": {"sharing": False},
           "environment": "lab:1", "account_ref": "account:1", "conditions": {}}
BINDING = {**CONTEXT, "observed_at": "2020-01-01T00:00:00Z"}
NOW = "2026-11-16T00:00:00Z"


def test_full_context_without_global_ttl_remains_applicable():
    assert assess_evidence(BINDING, CONTEXT, NOW)["status"] == "applicable"
    assert not assess_evidence(BINDING, CONTEXT, NOW)["requires_revalidation"]


@pytest.mark.parametrize("key,value", [("version", "release:2"), ("role", "admin"),
                                     ("settings", {"sharing": True}), ("environment", "prod:1"),
                                     ("account_ref", "account:2"), ("conditions", {"waf": "on"})])
def test_changed_conditions_require_revalidation(key, value):
    result = assess_evidence(BINDING, {**CONTEXT, key: value}, NOW)
    assert result["status"] == "conditions_changed"
    assert result["requires_revalidation"]
    assert key + " changed" in result["reasons"]


@pytest.mark.parametrize("key", ["version", "role", "settings", "environment", "observed_at"])
def test_missing_bindings_are_unknown(key):
    incomplete = {k: v for k, v in BINDING.items() if k != key}
    assert assess_evidence(incomplete, CONTEXT, NOW)["status"] == "unknown"


def test_legacy_wildcard_unknown_current_and_invalid_time_do_not_pass():
    assert assess_evidence(None, CONTEXT, NOW)["status"] == "unknown"
    assert assess_evidence(BINDING, None, NOW)["status"] == "unknown"
    assert assess_evidence({**BINDING, "version": "*"}, CONTEXT, NOW)["status"] == "unknown"
    assert assess_evidence({**BINDING, "observed_at": "2020-01-01"}, CONTEXT, NOW)["status"] == "unknown"
    assert assess_evidence({**BINDING, "observed_at": "2030-01-01T00:00:00Z"}, CONTEXT, NOW)["status"] == "unknown"
    assert assess_evidence({**BINDING, "observed_at": "2020-01-01T00:00:00-00:00"},
                           CONTEXT, NOW)["status"] == "unknown"


@pytest.mark.parametrize("key,value", [("version", {}), ("role", []), ("environment", {}),
                                     ("settings", "unknown")])
def test_invalid_condition_shapes_do_not_become_valid_by_equal_values(key, value):
    assert assess_evidence({**BINDING, key: value}, {**CONTEXT, key: value}, NOW)["status"] == "unknown"


def test_explicit_expiry_is_inclusive_and_bad_expiry_unknown():
    assert assess_evidence({**BINDING, "expires_at": NOW}, CONTEXT, NOW)["status"] == "expired"
    assert assess_evidence({**BINDING, "expires_at": "2027-01-01T00:00:00Z"},
                           CONTEXT, NOW)["status"] == "applicable"
    assert assess_evidence({**BINDING, "expires_at": "bad"}, CONTEXT, NOW)["status"] == "unknown"
    assert assess_evidence({**BINDING, "expires_at": "2019-01-01T00:00:00Z"},
                           CONTEXT, NOW)["status"] == "unknown"


def test_explicit_condition_change_time_blocks_even_when_settings_reverted():
    current = {**CONTEXT, "effective_at": "2026-01-01T00:00:00Z"}
    assert assess_evidence(BINDING, current, NOW)["status"] == "conditions_changed"


def test_latest_context_is_explicit_separate_from_scan_history():
    events = [{"type": "evidence_context", "context": CONTEXT},
              {"type": "scan_import", "context": {**CONTEXT, "version": "release:99"}}]
    assert latest_context(events) == CONTEXT
    returned = latest_context(events)
    returned["settings"]["sharing"] = True
    assert not CONTEXT["settings"]["sharing"]
    assert latest_context(events, "other") is None


def test_explicit_binding_gates_existing_proof_resolver_but_keeps_legacy(tmp_path):
    path = tmp_path / "proof.txt"
    path.write_text("local immutable evidence")
    legacy = normalize_evidence(str(path))
    proof = {**legacy, "applicability": copy.deepcopy(BINDING)}
    events = [{"type": "evidence_context", "context": CONTEXT}]
    assert evidence_resolves(legacy)
    assert evidence_resolves(proof, events=events)
    assert not evidence_resolves(proof)
    events.append({"type": "evidence_context", "context": {**CONTEXT, "version": "release:2"}})
    assert not evidence_resolves(proof, events=events)
    assert evidence_resolves(legacy, events=events)
    observation = {"kind": "observation", "text": "Controlled local fixture observed",
                   "applicability": BINDING}
    assert not evidence_resolves(observation, events=events)
    assert assess_artifact(legacy, events, NOW)["status"] == "unknown"


def test_import_bindings_do_not_create_current_context(tmp_path, monkeypatch):
    td = tmp_path / "01 - Targets" / "fixture"
    td.mkdir(parents=True)
    monkeypatch.setattr(asg, "vault_root", lambda: tmp_path)
    asg.append_event(td, "genesis", profile="source-audit")
    source = tmp_path / "scan.jsonl"
    source.write_text('{"template-id":"fixture","host":"https://fixture.invalid"}')
    manifest = {"run_id": "r1", "scope_ref": "scope:fixture", "tool_version": "3.5.1",
                "started_at": BINDING["observed_at"], "execution_status": "completed",
                "expires_at": "2027-01-01T00:00:00Z"}
    import_scan(td, source, "nuclei-jsonl", manifest, CONTEXT)
    loop = HuntLoop.load(asg.ledger_path(td))
    artifact = next(e for e in loop.events if e["type"] == "scan_candidate")["artifacts"][0]
    assert artifact["applicability"]["version"] == "release:1"
    assert latest_context(loop.events) is None
    assert assess_artifact(artifact, loop.events, NOW)["status"] == "unknown"
    record_context(td, CONTEXT)
    loop = HuntLoop.load(asg.ledger_path(td))
    assert assess_artifact(artifact, loop.events, NOW)["status"] == "applicable"
    record_context(td, {**CONTEXT, "settings": {"sharing": True}})
    loop = HuntLoop.load(asg.ledger_path(td))
    assert assess_artifact(artifact, loop.events, NOW)["status"] == "conditions_changed"


def test_context_cli_uses_canonical_writer(tmp_path, monkeypatch):
    td = tmp_path / "01 - Targets" / "fixture"
    td.mkdir(parents=True)
    monkeypatch.setattr(asg, "vault_root", lambda: tmp_path)
    asg.append_event(td, "genesis", profile="source-audit")
    context_file = tmp_path / "current.json"
    context_file.write_text(json.dumps(CONTEXT))
    command = [sys.executable,
               str(Path(__file__).resolve().parents[1] / "automation/evidence_applicability.py"),
               "fixture", "--context", str(context_file)]
    result = subprocess.run(command, env={**os.environ, "VAULT_ROOT": str(tmp_path)},
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert latest_context(HuntLoop.load(asg.ledger_path(td)).events) == CONTEXT
    with pytest.raises(ValueError, match="credentials"):
        record_context(td, {**CONTEXT, "settings": {"password": "private"}})
