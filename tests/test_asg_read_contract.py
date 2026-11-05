"""Observable state consistency and evidence integrity across ASG entrypoints."""
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
import asg
import capability_view
import next_work
from hunt_loop import HuntLoop, Verdict
from hunt_session import resume_brief
from asg_surface_scan import read_ledger_events
from ledger_reader import LedgerReadError
from evidence_refs import evidence_resolves, normalize_evidence


@pytest.fixture
def target(tmp_path, monkeypatch):
    root = tmp_path / "vault"
    td = root / "01 - Targets" / "fixture"
    td.mkdir(parents=True)
    monkeypatch.setattr(asg, "vault_root", lambda: root)
    monkeypatch.setattr(capability_view, "TARGETS", td.parent)
    monkeypatch.setattr(next_work, "TARGETS", td.parent)
    return td


def test_pending_ledger_work_survives_projection_and_missing_markdown(target):
    asg.append_events("fixture", [("genesis", {"profile": "source-audit"}),
                                 ("hypothesis", {"id": "pending-1", "requires": []})])
    state = asg.read_state("fixture")
    assert state["source"] == "ledger"
    assert state["capsule"]["ready_hypotheses"] == ["pending-1"]
    assert state["paths"][0]["name"] == "pending-1"
    md = asg.project_markdown("fixture")
    assert capability_view.load(md)[3][0]["name"] == "pending-1"
    md.unlink()
    assert asg.read_state("fixture")["paths"] == state["paths"]
    assert any("pending-1" in str(item) for item in next_work.compute("fixture")["next_work"])


def test_stale_yaml_cannot_override_ledger_or_revoked_capabilities(target):
    md = asg.markdown_path("fixture")
    md.write_text('```yaml\ncapability_state:\n- cap: stale-admin\n  state: confirmed\npaths:\n- name: stale-work\n  status: hypothesis\n```\n')
    proof = {"kind": "observation", "text": "controlled fixture returned the expected private record"}
    asg.append_events("fixture", [("hypothesis", {"id": "h", "requires": []}),
                                 ("verdict", {"hypothesis": "h", "status": "confirmed", "evidence": proof, "provides": ["read"]})])
    cs, cg, findings, paths, _ = capability_view.load(md)
    assert capability_view.all_caps(cs, cg, findings) == {"read"}
    assert "stale-work" not in {p["name"] for p in paths}
    asg.append_event("fixture", "revoke", cap="read", reason="fixture rotation")
    cs, cg, findings, _, _ = capability_view.load(md)
    assert capability_view.all_caps(cs, cg, findings) == set()
    assert asg.write_snapshot("fixture").exists()


def test_legacy_graph_remains_readable_without_creating_a_ledger(target):
    md = asg.markdown_path("fixture")
    md.write_text('```yaml\ncapability_state:\n- cap: legacy-read\n  state: confirmed\npaths:\n- name: legacy-work\n  status: hypothesis\n```\n')
    assert asg.read_state("fixture")["source"] == "legacy"
    assert capability_view.load(md)[3][0]["name"] == "legacy-work"
    assert not asg.ledger_path("fixture").exists()


@pytest.mark.parametrize("bad_line", ['{broken}', '[]', '{"missing":"type"}'])
def test_all_readers_reject_the_same_bad_line_without_partial_state(target, bad_line):
    led = asg.ledger_path("fixture")
    led.parent.mkdir()
    led.write_text('{"type":"surface","name":"one"}\n'+bad_line+'\n')
    for read in (lambda: read_ledger_events(led), lambda: HuntLoop.load(led),
                 lambda: asg.read_state("fixture"), lambda: next_work.compute("fixture")):
        with pytest.raises(LedgerReadError) as error:
            read()
        assert error.value.path == led and error.value.line == 2
        assert bad_line not in str(error.value)


def test_unknown_reference_cannot_grant_capability():
    loop = HuntLoop()
    loop.add_hypothesis("h")
    loop.record_verdict("h", Verdict.CONFIRMED, "ZZ-999", ["admin"])
    assert loop.capsule()["capabilities"] == []
    assert "h" in loop.capsule()["evidence_rejected"]


def test_reference_requires_resolvable_proof_not_only_a_finding_stub(tmp_path):
    proof = tmp_path / "proof with spaces.txt"
    proof.write_text("fixture private body")
    loop = HuntLoop(base_path=tmp_path)
    loop.append("finding", finding_id="ZZ-999")
    assert not evidence_resolves("ZZ-999", tmp_path, loop.events)
    pinned = normalize_evidence(str(proof), tmp_path, {"role": "fixture", "host": "local"})
    loop.append("evidence", id="EV-1", evidence=pinned)
    loop.record_verdict("h", Verdict.CONFIRMED, "EV-1", ["read"])
    assert loop.capsule()["capabilities"] == ["read"]
    assert pinned["environment"]["host"] == "local"
    proof.write_text("replaced body")
    assert loop.capsule()["capabilities"] == []


def test_new_artifact_verdict_pins_hash_and_survives_reload(tmp_path):
    proof = tmp_path / "proof.txt"
    proof.write_text("fixture private body")
    loop = HuntLoop(base_path=tmp_path)
    loop.add_hypothesis("h")
    loop.record_verdict("h", Verdict.CONFIRMED, str(proof), ["read"])
    assert loop.events[-1]["evidence"]["kind"] == "artifact"
    assert len(loop.events[-1]["evidence"]["sha256"]) == 64
    led = tmp_path / "ledger.jsonl"
    loop.save(led)
    assert HuntLoop.load(led).capsule() == loop.capsule()
    proof.unlink()
    assert HuntLoop.load(led).capsule()["capabilities"] == []


def test_reference_cycles_are_rejected():
    events = [{"type": "evidence", "id": "A", "evidence": {"kind": "reference", "id": "B"}},
              {"type": "evidence", "id": "B", "evidence": {"kind": "reference", "id": "A"}}]
    assert not evidence_resolves({"kind": "reference", "id": "A"}, events=events)


def test_status_snapshot_capabilities_and_handoff_agree(target):
    asg.append_events("fixture", [("genesis", {"profile": "web"}),
                                 ("hypothesis", {"id": "pending", "requires": []}),
                                 ("finding", {"finding_id": "F-001"}),
                                 ("finding_state", {"finding_id": "F-001", "to": "withdrawn"})])
    state = asg.read_state("fixture")
    assert asg.status("fixture")["findings_by_state"] == {"withdrawn": 1}
    brief = resume_brief(HuntLoop.load(asg.ledger_path("fixture")))
    assert state["capsule"]["ready_hypotheses"] == brief["ready_hypotheses"]
    assert state["findings"][0]["status"] == "withdrawn"


def test_migration_receipt_is_bound_to_imported_subject_and_caps(target):
    asg.markdown_path("fixture").write_text(
        '```yaml\ncapability_state:\n- cap: legacy-read\n  state: confirmed\n```\n')
    asg.migrate_yaml_to_ledger("fixture")
    loop = HuntLoop.load(asg.ledger_path("fixture"))
    imported = next(e for e in loop.events if e["type"] == "verdict")
    assert loop.capsule()["capabilities"] == ["legacy-read"]
    for proof in (imported["evidence"], {"kind": "reference", "id": imported["evidence"]["id"]},
                  "migrated:legacy-read"):
        loop.record_verdict("unrelated", Verdict.CONFIRMED, proof, ["admin"])
        assert "admin" not in loop.capsule()["capabilities"]
    loop.record_verdict(imported["hypothesis"], Verdict.CONFIRMED, imported["evidence"], ["admin"])
    assert loop.capsule()["capabilities"] == []


def test_finding_amendment_preserves_state_and_original_proof(target):
    proof = target / "proof.txt"
    proof.write_text("private fixture record")
    asg.append_events("fixture", [
        ("finding", {"finding_id": "F-1", "poc_ref": str(proof), "provides": ["read"]}),
        ("finding_state", {"finding_id": "F-1", "to": "confirmed"}),
        ("hypothesis", {"id": "finding:F-1", "requires": []}),
        ("verdict", {"hypothesis": "finding:F-1", "status": "confirmed", "evidence": "F-1", "provides": ["read"]}),
        ("finding", {"finding_id": "F-1", "severity": "P2"}),
    ])
    state = asg.read_state("fixture")
    finding = state["findings"][0]
    assert finding["status"] == "confirmed" and finding["severity"] == "P2"
    assert finding["poc_ref"] == str(proof) and finding["provides"] == ["read"]
    assert state["capsule"]["capabilities"] == ["read"]
    proof.write_text("changed fixture bytes")
    assert asg.read_state("fixture")["capsule"]["capabilities"] == []


def test_references_pin_latest_evidence_revision(tmp_path):
    loop = HuntLoop(base_path=tmp_path)
    loop.append("evidence", id="EV-1", evidence={"kind": "observation", "text": "original controlled result"})
    loop.record_verdict("h", Verdict.CONFIRMED, "EV-1", ["read"])
    assert loop.capsule()["capabilities"] == ["read"]
    assert loop.events[-1]["evidence"].get("proof_sha256")
    loop.append("evidence", id="EV-1", evidence={"kind": "observation", "text": "different controlled result"})
    assert loop.capsule()["capabilities"] == []


@pytest.mark.parametrize("change", ["withdraw", "replace", "revoke"])
def test_attack_chain_excludes_ineffective_confirmations(target, change):
    proof = target / "proof.txt"
    proof.write_text("private fixture record")
    asg.append_events("fixture", [
        ("finding", {"finding_id": "F-1"}),
        ("hypothesis", {"id": "finding:F-1", "requires": []}),
        ("verdict", {"hypothesis": "finding:F-1", "status": "confirmed", "evidence": str(proof), "provides": ["read"]}),
        ("hypothesis", {"id": "dependent", "requires": ["read"]}),
        ("verdict", {"hypothesis": "dependent", "status": "confirmed", "evidence": {"kind": "observation", "text": "controlled dependent outcome"}, "provides": ["write"]}),
    ])
    if change == "withdraw":
        asg.append_event("fixture", "finding_state", finding_id="F-1", to="withdrawn")
    elif change == "replace":
        proof.write_text("replaced bytes")
    else:
        asg.append_event("fixture", "revoke", cap="read", reason="fixture rotation")
    state = asg.read_state("fixture")
    chain = asg.auto_chain("fixture", state=state)
    assert "finding:F-1" not in chain["entry_points"] or change == "revoke"
    assert chain["chain_edges"] == [] and chain["capabilities"] == []
    snap = __import__("json").loads(asg.write_snapshot("fixture").read_text())
    assert snap["chain_edges"] == 0 and snap["chain_capabilities"] == 0
    assert "read" not in state["capsule"]["capabilities"]


def test_confirmed_path_json_is_terminal(target):
    asg.append_events("fixture", [
        ("hypothesis", {"id": "h", "requires": []}),
        ("verdict", {"hypothesis": "h", "status": "confirmed", "evidence": {"kind": "observation", "text": "controlled fixture result"}, "provides": ["read"]}),
    ])
    values = capability_view.load(asg.markdown_path("fixture"))
    projection = capability_view.to_json("fixture", *values)
    assert projection["blocked"] == 0 and projection["unlocked"] == 1


def test_corruption_does_not_overwrite_authorization_queue(target):
    led = asg.ledger_path("fixture")
    led.parent.mkdir()
    led.write_text('{"type":"hypothesis","id":[],"requires":[]}\n')
    out = target / "needs_human_go.json"
    out.write_text("previous queue")
    with pytest.raises(LedgerReadError):
        next_work.write_human_go("fixture")
    assert out.read_text() == "previous queue"


@pytest.mark.parametrize("reference_kind", ["evidence", "finding"])
def test_unresolved_new_reference_needs_a_fresh_pinned_verdict(tmp_path, reference_kind):
    loop = HuntLoop(base_path=tmp_path)
    ref = "EV-1" if reference_kind == "evidence" else "F-1"
    if reference_kind == "finding":
        loop.append("finding", finding_id=ref)
    loop.record_verdict("h", Verdict.CONFIRMED, ref, ["read"])
    assert loop.events[-1]["evidence"]["unresolved_at_recording"]
    proof = {"kind": "observation", "text": "controlled fixture original result"}
    if reference_kind == "evidence":
        loop.append("evidence", id=ref, evidence=proof)
    else:
        loop.append("finding", finding_id=ref, evidence=proof)
    assert loop.capsule()["capabilities"] == []
    loop.record_verdict("h", Verdict.CONFIRMED, ref, ["read"])
    assert loop.capsule()["capabilities"] == ["read"]
    changed = {"kind": "observation", "text": "controlled fixture changed result"}
    if reference_kind == "evidence":
        loop.append("evidence", id=ref, evidence=changed)
    else:
        loop.append("finding", finding_id=ref, evidence=changed)
    assert loop.capsule()["capabilities"] == []


def test_rejected_verdict_without_explicit_hypothesis_is_repair_work(target):
    asg.append_events("fixture", [("genesis", {"profile": "source-audit"}),
                                 ("verdict", {"hypothesis": "repair-me", "status": "confirmed", "evidence": "EV-missing"})])
    state = asg.read_state("fixture")
    assert state["paths"][0]["status"] == "needs_evidence"
    assert state["brief"]["next_action"].startswith("REPAIR evidence")
    assert state["brief"]["evidence_rejected"] == ["repair-me"]
    assert "repair-me" in state["capsule"]["ready_hypotheses"]
    assert any("repair-me" in str(item) for item in next_work.compute("fixture")["next_work"])


def test_valid_orphan_verdict_has_the_same_chain_and_capsule(target):
    asg.append_event("fixture", "verdict", hypothesis="implicit-valid", status="confirmed",
                     evidence={"kind": "observation", "text": "controlled fixture private record"}, provides=["read"])
    state = asg.read_state("fixture")
    assert state["paths"][0]["status"] == "confirmed"
    assert state["capsule"]["capabilities"] == ["read"]
    chain = asg.auto_chain("fixture", state=state)
    assert chain["capabilities"] == ["read"] and chain["entry_points"] == ["implicit-valid"]
    assert chain["total_confirmed"] == 1


def test_refuted_repair_candidate_is_not_reported_as_proof_work():
    loop = HuntLoop()
    loop.record_verdict("h", Verdict.CONFIRMED, "EV-missing", ["read"])
    loop.record_verdict("h", Verdict.REFUTED)
    assert loop.capsule()["evidence_rejected"] == {}
    assert resume_brief(loop)["evidence_rejected"] == []


def test_cli_project_view_reload_and_corruption_use_one_vault(target):
    import json
    import os
    import subprocess
    automation = Path(asg.__file__).parent
    proof = target / "proof.txt"
    proof.write_text("synthetic private fixture response")
    asg.append_events("fixture", [("genesis", {"profile": "source-audit"}),
                                 ("hypothesis", {"id": "pending", "requires": []}),
                                 ("finding", {"finding_id": "F-1", "poc_ref": str(proof)}),
                                 ("hypothesis", {"id": "finding:F-1", "requires": []}),
                                 ("verdict", {"hypothesis": "finding:F-1", "status": "confirmed", "evidence": "F-1", "provides": ["read"]}),
                                 ("finding", {"finding_id": "F-1", "severity": "P2"})])
    env = {**os.environ, "VAULT_ROOT": str(target.parent.parent), "BB_PROJECT_ROOT": str(target.parent.parent)}
    def cli(script, *args, success=True):
        result = subprocess.run([sys.executable, str(automation / script), *args],
                                env=env, capture_output=True, text=True)
        assert (result.returncode == 0) == success, result.stderr
        return result.stdout
    cli("asg.py", "project", "fixture")
    view = json.loads(cli("capability_view.py", "fixture", "--json"))
    queue = json.loads(cli("next_work.py", "fixture"))
    assert view["capabilities"] == ["read"]
    assert any("pending" in str(item) for item in queue["next_work"])
    assert len(view["chains"]) == 2
    asg.markdown_path("fixture").unlink()
    assert json.loads(cli("capability_view.py", "fixture", "--json"))["capabilities"] == ["read"]
    proof.write_text("changed synthetic fixture response")
    cli("asg.py", "project", "fixture")
    view = json.loads(cli("capability_view.py", "fixture", "--json"))
    assert view["capabilities"] == [] and any(p["status"] == "needs_evidence" for p in view["chains"])
    snap = json.loads(asg.snapshot_path("fixture").read_text())
    assert snap["chain_capabilities"] == 0 and snap["evidence_rejected"] == 1
    previous = (target / "next_work.json").read_bytes()
    with asg.ledger_path("fixture").open("a") as stream:
        stream.write('{malformed fixture line}\n')
    cli("next_work.py", "fixture", success=False)
    cli("asg.py", "project", "fixture", success=False)
    assert (target / "next_work.json").read_bytes() == previous
