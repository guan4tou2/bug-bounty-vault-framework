"""Research lineage must affect actual work selection without granting access."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "automation"))
import asg
import asg_research as research
import next_work
from hunt_loop import HuntLoop, RunState
from hunt_session import resume_brief
from ledger_reader import LedgerReadError


@pytest.fixture
def target(tmp_path, monkeypatch):
    root = tmp_path / "vault"
    td = root / "01 - Targets" / "fixture"
    td.mkdir(parents=True)
    monkeypatch.setattr(asg, "vault_root", lambda: root)
    asg.append_event(td, "genesis", profile="source-audit")
    return td


def node(target, kind, identifier, text, **fields):
    asg.append_event(target, "research_node", node_kind=kind, id=identifier, text=text, **fields)


def goal(target, purpose="validation"):
    node(target, "goal", "G1", "Establish the bounded result", purpose=purpose,
         criteria=[{"id": "C1", "text": "Result has reproducible evidence"}])


def intent(target, identifier="I1", **fields):
    node(target, "intent", identifier, "One bounded research step", goals=["goal:G1"], **fields)


def fact(target, identifier="F1", **fields):
    fields.setdefault("basis", "observed")
    fields.setdefault("evidence", {"kind": "observation", "text": "Controlled local fixture produced the expected output"})
    node(target, "fact", identifier, "Observed bounded result", **fields)


def state(target, ref, to):
    asg.append_event(target, "research_state", ref=ref, state=to, reason="Controlled fixture transition")


def proof(target, source="fact:F1"):
    asg.append_event(target, "goal_proof", goal="goal:G1", criterion="C1", source=source,
                     reason="Fixture reviewer assessed the named acceptance criterion")


def graph(target):
    return asg.read_state(target)["research"]


def test_work_and_proof_survive_reload_and_drive_native_entrypoints(target):
    goal(target)
    intent(target)
    assert next_work.compute("fixture")["items"][0]["ref"] == "intent:I1"
    state(target, "intent:I1", "running")
    fact(target, intent="intent:I1")
    state(target, "intent:I1", "done")
    before = HuntLoop.load(asg.ledger_path(target))
    assert before.run_state() == RunState.REPLANNING
    with pytest.raises(ValueError, match="accepted goals"):
        before.complete("Nothing else queued")
    proof(target)
    loop = HuntLoop.load(asg.ledger_path(target))
    loop.complete("All explicit acceptance criteria supported")
    assert loop.run_state() == RunState.COMPLETED
    assert graph(target)["summary"]["met_goals"] == ["goal:G1"]
    assert loop.capsule()["capabilities"] == []
    assert resume_brief(loop)["research"]["goals"][0]["effective_state"] == "met"
    assert {(e["src"], e["rel"], e["dst"]) for e in graph(target)["edges"]} >= {
        ("root", "spawns", "goal:G1"), ("goal:G1", "spawns", "intent:I1"),
        ("intent:I1", "yields", "fact:F1"), ("fact:F1", "proves", "goal:G1"),
    }
    generated = asg.project_markdown(target)
    assert "G1" in generated.read_text()


def test_intent_prerequisites_block_dispatch_until_work_and_capability_exist(target):
    goal(target)
    asg.append_event(target, "hypothesis", id="H1", requires=[])
    intent(target, "R1")
    intent(target, "T1", depends_on=["intent:R1"], requires=["local-fixture-access"], hypothesis="hypothesis:H1")
    assert "H1" not in asg.read_state(target)["capsule"]["ready_hypotheses"]
    with pytest.raises(ValueError, match="prerequisites"):
        state(target, "intent:T1", "running")
    state(target, "intent:R1", "running")
    fact(target, intent="intent:R1")
    state(target, "intent:R1", "done")
    assert "intent:T1" not in graph(target)["summary"]["ready_intents"]
    asg.append_events(target, [("hypothesis", {"id": "access", "requires": []}),
        ("verdict", {"hypothesis": "access", "status": "confirmed", "provides": ["local-fixture-access"],
                     "evidence": {"kind": "observation", "text": "Controlled fixture established access"}})])
    assert graph(target)["summary"]["ready_intents"] == ["intent:T1"]
    assert "H1" in asg.read_state(target)["capsule"]["ready_hypotheses"]
    asg.append_event(target, "revoke", cap="local-fixture-access", reason="Fixture access revoked")
    assert "intent:T1" in graph(target)["summary"]["blocked_intents"]
    assert "H1" not in asg.read_state(target)["capsule"]["ready_hypotheses"]


@pytest.mark.parametrize("basis", ["inferred", "unknown", "source-claimed"])
def test_validation_goal_rejects_nonobserved_claims(target, basis):
    goal(target)
    fact(target, basis=basis, source="https://example.com/original", checked_at="2026-10-19T00:00:00Z")
    with pytest.raises(ValueError, match="eligible"):
        proof(target)
    assert graph(target)["summary"]["open_goals"] == ["goal:G1"]


def test_source_research_goal_needs_pinned_read_evidence(target):
    goal(target, purpose="research")
    artifact = target / "source.txt"
    artifact.write_text("Captured source excerpt for an offline fixture")
    fact(target, basis="source-claimed", source="https://example.com/original",
         checked_at="2026-10-19T00:00:00Z", evidence=str(artifact))
    proof(target)
    assert graph(target)["summary"]["met_goals"] == ["goal:G1"]
    artifact.write_text("Changed source bytes")
    assert graph(target)["summary"]["open_goals"] == ["goal:G1"]
    assert not next(e for e in graph(target)["edges"] if e["rel"] == "proves")["valid"]


def test_revising_acceptance_or_withdrawing_fact_invalidates_prior_proof(target):
    goal(target)
    fact(target)
    proof(target)
    state(target, "fact:F1", "withdrawn")
    assert graph(target)["summary"]["open_goals"] == ["goal:G1"]
    state(target, "fact:F1", "active")
    proof(target)
    node(target, "goal", "G1", "Changed acceptance definition", amend=True)
    assert graph(target)["summary"]["open_goals"] == ["goal:G1"]


def test_hints_are_scoped_and_cannot_prove_or_grant_capabilities(target):
    goal(target)
    node(target, "hint", "N1", "Prioritize source research", goal="goal:G1")
    assert resume_brief(HuntLoop.load(asg.ledger_path(target)))["research"]["hints"][0]["ref"] == "hint:N1"
    with pytest.raises(ValueError, match="eligible"):
        proof(target, "hint:N1")
    assert asg.read_state(target)["capsule"]["capabilities"] == []
    state(target, "hint:N1", "consumed")
    assert graph(target)["summary"]["active_hints"] == []


def test_invalid_identity_relation_and_causal_cycle_append_nothing(target):
    goal(target)
    intent(target)
    fact(target, intent="intent:I1")
    original = asg.ledger_path(target).read_bytes()
    attempts = [
        ("research_node", {"node_kind": "intent", "id": "bad", "text": "Invalid parent", "goals": ["goal:missing"]}),
        ("research_link", {"src": "fact:F1", "rel": "derived_from", "dst": "intent:I1"}),
        ("research_link", {"src": "fact:F1", "rel": "spawns", "dst": "goal:G1"}),
        ("research_link", {"src": "fact:F1", "rel": "proves", "dst": "goal:G1"}),
    ]
    for kind, data in attempts:
        with pytest.raises(ValueError):
            asg.append_event(target, kind, **data)
        assert asg.ledger_path(target).read_bytes() == original


def test_duplicate_node_requires_explicit_amendment_and_state_machine(target):
    goal(target)
    intent(target)
    with pytest.raises(ValueError, match="already exists"):
        intent(target)
    with pytest.raises(ValueError, match="invalid intent transition"):
        state(target, "intent:I1", "done")
    state(target, "intent:I1", "running")
    with pytest.raises(ValueError, match="outputs"):
        state(target, "intent:I1", "done")


def test_digest_retains_originals_expands_and_becomes_stale_on_new_live_branch(target, capsys):
    goal(target)
    intent(target)
    state(target, "intent:I1", "running")
    fact(target, intent="intent:I1")
    with pytest.raises(ValueError, match="cold"):
        asg.append_event(target, "research_digest", id="D1", members=["intent:I1", "fact:F1"])
    state(target, "intent:I1", "done")
    original = asg.ledger_path(target).read_bytes()
    asg.append_event(target, "research_digest", id="D1", members=["intent:I1", "fact:F1"])
    assert asg.ledger_path(target).read_bytes().startswith(original)
    assert graph(target)["digests"][0]["state"] == "active"
    assert research.cli([str(target), "expand", "digest:D1"]) == 0
    expanded = json.loads(capsys.readouterr().out)
    assert {n["ref"] for n in expanded["nodes"]} == {"intent:I1", "fact:F1"}
    assert research.brief(graph(target))["recent_facts"] == []
    assert {n["ref"] for n in graph(target)["nodes"]} >= {"intent:I1", "fact:F1"}
    with pytest.raises(ValueError, match="eligible"):
        proof(target, "digest:D1")
    intent(target, "I2", parents=["fact:F1"])
    assert graph(target)["digests"][0]["state"] == "stale"
    assert research.brief(graph(target))["recent_facts"][0]["ref"] == "fact:F1"


def test_existing_finding_is_linked_without_duplicate_research_identity(target):
    goal(target)
    intent(target)
    asg.record_finding(target, "F-001", intent_id="I1")
    g = graph(target)
    assert len([n for n in g["nodes"] if n["ref"] == "finding:F-001"]) == 1
    assert any(e == {"src": "intent:I1", "rel": "yields", "dst": "finding:F-001"} for e in g["edges"])
    with pytest.raises(ValueError, match="eligible"):
        proof(target, "finding:F-001")


def test_malformed_research_events_fail_strict_read_contract(target):
    asg.ledger_path(target).write_text('{"type":"research_node","kind":"goal","id":"bad"}\n')
    with pytest.raises(LedgerReadError, match="invalid research event"):
        asg.read_state(target)


@pytest.mark.parametrize("event", [
    {"type": "research_node", "node_kind": "goal", "id": "bad", "text": "Missing original definition", "amend": True},
    {"type": "research_node", "node_kind": "intent", "id": "bad", "text": "Unknown goal", "goals": ["goal:missing"]},
    {"type": "research_state", "ref": "intent:missing", "state": "done", "reason": "No original work"},
])
def test_corrupt_research_history_is_unavailable_not_an_empty_queue(target, event):
    asg.ledger_path(target).write_text(json.dumps(event) + "\n")
    with pytest.raises(LedgerReadError, match="invalid research event"):
        asg.read_state(target)


def test_cli_creates_a_replayable_workflow_and_expands_digest(target, monkeypatch, capsys):
    monkeypatch.setenv("VAULT_ROOT", str(target.parents[1]))
    prefix = ["fixture"]
    assert research.cli(prefix + ["goal", "G1", "--text", "Read public source", "--purpose", "research", "--criterion", "C1=Capture source evidence"]) == 0
    assert research.cli(prefix + ["intent", "I1", "--text", "Read upstream documentation", "--goal", "G1", "--priority", "0"]) == 0
    assert next(n for n in graph(target)["nodes"] if n["ref"] == "intent:I1")["priority"] == 0
    result = subprocess.run([sys.executable, str(ROOT / "automation/asg.py"), "research", "fixture", "show"],
                            env=__import__("os").environ, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["summary"]["ready_intents"] == ["intent:I1"]
    assert research.cli(prefix + ["prove", "G1", "C1", "hint:missing", "--reason", "No proof"]) == 2


def test_explicit_dependency_link_changes_work_selection(target):
    goal(target)
    intent(target, "R1")
    intent(target, "T1")
    asg.append_event(target, "research_link", src="intent:R1", rel="depends_on", dst="intent:T1")
    assert graph(target)["summary"]["ready_intents"] == ["intent:R1"]
    state(target, "intent:R1", "running")
    fact(target, intent="intent:R1")
    state(target, "intent:R1", "done")
    assert graph(target)["summary"]["ready_intents"] == ["intent:T1"]


def test_abandoned_goal_is_distinct_from_evidence_based_completion(target):
    goal(target)
    state(target, "goal:G1", "abandoned")
    summary = graph(target)["summary"]
    assert summary["abandoned_goals"] == ["goal:G1"]
    assert summary["met_goals"] == []


def test_native_research_is_handed_to_runner_before_any_test_dispatch(target):
    from hunt_autodrive import autodrive, Budget
    from logic_vuln_loop import Env
    goal(target)
    intent(target, "R1")
    loop = HuntLoop.load(asg.ledger_path(target))
    def forbidden(*args):
        pytest.fail("Plain-language research must not be sent to the bounded exploit executor")
    report = autodrive(loop, current_env=Env("fixture", "operator", "local"),
                       dispatch=forbidden, propose=forbidden, budget=Budget(2, 2))
    assert "native research work pending: intent:R1" in report.handoff_reason
    assert report.interventions == 0
    assert loop.run_state() == RunState.RUNNING


def test_bounded_runner_carries_lineage_and_persists_actual_output(target):
    from hunt_autodrive import autodrive, Budget
    from logic_vuln_loop import Env, LogicHypothesis, Observation
    goal(target)
    asg.append_event(target, "hypothesis", id="H1", requires=[])
    intent(target, "T1", hypothesis="hypothesis:H1")
    node(target, "hint", "N1", "Use only the controlled fixture", intent="intent:T1")
    env = Env("fixture", "operator", "local")
    hyp = LogicHypothesis(hyp_id="H1", dimension="read", invariant="Controlled private marker remains protected",
        applies_env=env, precondition="fixture", expected_normal="denied", test_action="fixture-test",
        control_action="fixture-control", violation_outcome="private_marker", expected_normal_outcome="denied")
    seen = []
    def dispatch(task):
        seen.extend(task.research_context)
        evidence = {"kind": "observation", "text": "Controlled fixture returned the private marker"}
        return (Observation("fixture-test", True, "private_marker", evidence),
                Observation("fixture-control", True, "denied", evidence))
    loop = HuntLoop.load(asg.ledger_path(target))
    loop.asg = {"findings": [], "recon_dimensions": {"passive_osint": {"status": "completed"}}}
    report = autodrive(loop, current_env=env, dispatch=dispatch, ready_hyp=lambda _: hyp,
                       propose=lambda *_: None, budget=Budget(3, 2))
    assert any("hint:N1" in text for text in seen), report
    assert any("acceptance C1" in text for text in seen)
    result = research.project(loop.events, target, cap=loop.capsule())
    assert next(n for n in result["nodes"] if n["ref"] == "intent:T1")["state"] == "done"
    outputs = [n for n in result["nodes"] if n["kind"] == "fact"]
    assert len(outputs) == 1 and "TEST=private_marker" in outputs[0]["text"]
    assert result["summary"]["open_goals"] == ["goal:G1"]
    assert "acceptance" in report.handoff_reason


def test_research_canvas_is_deterministic_and_only_projects_ledger(target):
    import render_surface_graph_canvas as canvas
    goal(target)
    intent(target)
    fact(target, intent="intent:I1")
    before = asg.ledger_path(target).read_bytes()
    first = canvas.build_research_canvas(target)
    assert first == canvas.build_research_canvas(target)
    assert asg.ledger_path(target).read_bytes() == before
    assert {n["id"] for n in first["nodes"]} >= {"goal:G1", "intent:I1", "fact:F1"}
    assert {e["label"] for e in first["edges"]} >= {"spawns", "yields"}
    assert json.loads(asg.write_snapshot(target).read_text())["research"]["open_goals"] == ["goal:G1"]
    assert Path(asg.project_all(target)["research_canvas"]).is_file()


def test_all_acceptance_criteria_are_required_and_source_url_alone_is_not_proof(target):
    node(target, "goal", "G1", "Research both source and applicability", purpose="research",
         criteria=[{"id": "C1", "text": "Read source"}, {"id": "C2", "text": "Check applicability"}])
    fact(target, "F1", basis="source-claimed", source="https://example.com/source",
         checked_at="2026-10-19T00:00:00Z", evidence=None)
    with pytest.raises(ValueError, match="eligible"):
        proof(target)
    fact(target, "F2")
    proof(target, "fact:F2")
    assert graph(target)["summary"]["open_goals"] == ["goal:G1"]
    asg.append_event(target, "goal_proof", goal="goal:G1", criterion="C2", source="fact:F2", reason="Independent assessment of C2")
    assert graph(target)["summary"]["met_goals"] == ["goal:G1"]


def test_research_never_silently_migrates_legacy_authority(target):
    legacy = target.parent / "legacy"
    legacy.mkdir()
    md = legacy / "Attack Surface Graph - legacy.md"
    md.write_text('```yaml\nnodes:\n- id: old\n  identifier: old-surface\n```\n')
    original = md.read_bytes()
    with pytest.raises(ValueError, match="explicitly migrate"):
        goal(legacy)
    assert not asg.ledger_path(legacy).exists()
    assert md.read_bytes() == original
    assert asg.read_state(legacy)["source"] == "legacy"


@pytest.mark.parametrize("fields", [{"goals": "G1"}, {"goals": [1]}, {"goals": ["goal:G1"], "parents": 42}])
def test_invalid_structured_input_does_not_leave_partial_events(target, fields):
    goal(target)
    original = asg.ledger_path(target).read_bytes()
    with pytest.raises(ValueError):
        node(target, "intent", "I1", "Bad fixture input", **fields)
    assert asg.ledger_path(target).read_bytes() == original


def test_legacy_capability_strings_do_not_prove_a_finding_goal(target):
    goal(target)
    asg.record_finding(target, "ACME-001")
    asg.append_events(target, [
        ("finding_state", {"finding_id": "ACME-001", "to": "adversary-verified"}),
        ("verdict", {"hypothesis": "ACME-001", "status": "confirmed", "provides": [],
                     "evidence": "missing-evidence-reference", "confidence": "reproduced"}),
    ])
    assert "ACME-001" in HuntLoop.load(asg.ledger_path(target)).capsule()["confirmed"]
    with pytest.raises(ValueError, match="eligible"):
        proof(target, "finding:ACME-001")


def test_existing_finding_proof_pins_actual_legacy_artifact_bytes(target):
    goal(target)
    artifact = target / "proof.txt"
    artifact.write_text("First controlled evidence bytes")
    asg.record_finding(target, "ACME-001")
    asg.append_events(target, [
        ("finding_state", {"finding_id": "ACME-001", "to": "adversary-verified"}),
        ("verdict", {"hypothesis": "ACME-001", "status": "confirmed", "provides": [],
                     "evidence": str(artifact), "confidence": "reproduced"}),
    ])
    proof(target, "finding:ACME-001")
    assert graph(target)["summary"]["met_goals"] == ["goal:G1"]
    artifact.write_text("Changed controlled evidence bytes")
    assert graph(target)["summary"]["open_goals"] == ["goal:G1"]


def test_record_finding_cli_normalizes_intent_reference(target, capsys):
    goal(target)
    intent(target)
    assert asg._main(["record-finding", str(target), "ACME-001", "--intent", "intent:I1"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"]
    finding = next(n for n in graph(target)["nodes"] if n["ref"] == "finding:ACME-001")
    assert finding["intent_id"] == "I1"
    assert asg.status(target)["research"]["ready_intents"] == ["intent:I1"]


@pytest.mark.parametrize("event", [
    {"type": "research_link", "src": "goal:G1", "rel": "yields", "dst": "goal:G1"},
    {"type": "goal_proof", "goal": "goal:G1", "criterion": "C1", "source": "fact:missing",
     "reason": "Invalid source", "source_sha256": "a" * 64, "goal_sha256": "b" * 64},
    {"type": "research_digest", "id": "D1", "text": "Invalid summary", "members": ["fact:missing", "intent:missing"],
     "member_hashes": {"fact:missing": "a" * 64, "intent:missing": "b" * 64}},
    {"type": "research_node", "node_kind": "intent", "id": "I1", "text": "Invalid goal type", "goals": ["root"]},
])
def test_strict_replay_rejects_invalid_typed_lineage(target, event):
    goal(target)
    path = asg.ledger_path(target)
    path.write_text(path.read_text() + json.dumps(event) + "\n")
    with pytest.raises(LedgerReadError, match="invalid research event"):
        asg.read_state(target)


@pytest.mark.parametrize("kind, fields", [
    ("goal", {"criteria": [{"id": "C1", "text": "Retained evidence"}]}),
    ("intent", {"goals": ["goal:G1"]}),
    ("fact", {"basis": "observed"}),
    ("hint", {}),
])
def test_amend_missing_node_does_not_corrupt_a_fresh_read(target, kind, fields):
    goal(target)
    path = asg.ledger_path(target)
    before = path.read_bytes()
    with pytest.raises(ValueError, match="does not exist"):
        node(target, kind, "missing", "Unknown amended record", amend=True, **fields)
    assert path.read_bytes() == before
    assert graph(target)["summary"]["open_goals"] == ["goal:G1"]
    assert all(n["id"] != "missing" for n in graph(target)["nodes"])


@pytest.mark.parametrize("amend", ["true", "false", 0, 1, [], {}])
def test_amend_requires_a_real_boolean_without_changing_the_ledger(target, amend):
    goal(target)
    path = asg.ledger_path(target)
    before = path.read_bytes()
    with pytest.raises(ValueError):
        node(target, "goal", "G1", "Invalid amendment declaration", amend=amend)
    assert path.read_bytes() == before
    assert graph(target)["summary"]["open_goals"] == ["goal:G1"]


@pytest.mark.parametrize("kind, fields", [
    ("goal", {"criteria": [{"id": "C1", "text": "Retained evidence"}]}),
    ("intent", {"goals": ["goal:G1"]}),
    ("fact", {"basis": "observed"}),
    ("hint", {}),
])
def test_creation_cannot_bypass_transitions_with_an_initial_state(target, kind, fields):
    goal(target)
    path = asg.ledger_path(target)
    before = path.read_bytes()
    with pytest.raises(ValueError, match="separate transition"):
        node(target, kind, "bad-state", "State must use its transition event", state="done", **fields)
    assert path.read_bytes() == before
    assert graph(target)["summary"]["open_goals"] == ["goal:G1"]


def test_invalid_amendment_rolls_back_the_whole_locked_batch(target):
    goal(target)
    path = asg.ledger_path(target)
    before = path.read_bytes()
    with pytest.raises(ValueError, match="does not exist"):
        asg.append_events(target, [
            ("research_node", {"node_kind": "hint", "id": "N1", "text": "Valid pending hint"}),
            ("research_node", {"node_kind": "hint", "id": "missing", "text": "Unknown hint", "amend": True}),
        ])
    assert path.read_bytes() == before
    assert graph(target)["summary"]["active_hints"] == []


def test_comparison_evidence_pins_and_requires_both_branches(target):
    goal(target)
    test_artifact = target / "test.txt"
    control_artifact = target / "control.txt"
    test_artifact.write_text("Controlled test returned denial")
    control_artifact.write_text("Normal control returned denial")
    fact(target, evidence={"kind": "comparison", "test": str(test_artifact), "control": str(control_artifact)})
    retained = next(n for n in graph(target)["nodes"] if n["ref"] == "fact:F1")["evidence"]
    assert retained["test"]["sha256"]
    assert retained["control"]["sha256"]
    proof(target)
    assert graph(target)["summary"]["met_goals"] == ["goal:G1"]
    control_artifact.write_text("Changed control output")
    assert graph(target)["summary"]["open_goals"] == ["goal:G1"]


def test_comparison_with_a_missing_control_is_not_a_proof(target):
    goal(target)
    fact(target, evidence={"kind": "comparison", "test": {"kind": "observation", "text": "Expected test outcome"},
                           "control": "missing-control-reference"})
    with pytest.raises(ValueError, match="eligible"):
        proof(target)


@pytest.mark.parametrize("value", ["missing capture.txt", "missing capture/no-extension", "untyped observation prose"])
def test_missing_spaced_paths_and_untyped_prose_cannot_become_observations(target, value):
    goal(target)
    fact(target, evidence=value)
    retained = next(n for n in graph(target)["nodes"] if n["ref"] == "fact:F1")
    assert retained["evidence"]["kind"] != "observation"
    assert not retained["evidence_valid"]
    with pytest.raises(ValueError, match="eligible"):
        proof(target)


_KIND_FIELD_EXAMPLES = {
    "goal": {"criteria": [{"id": "C1", "text": "Retained evidence"}], "purpose": "research", "parent_goal": "goal:MISSING"},
    "intent": {"goals": ["goal:MISSING"], "parents": ["fact:MISSING"], "depends_on": ["intent:MISSING"],
               "requires": ["missing-capability"], "hypothesis": "hypothesis:MISSING", "priority": 3},
    "fact": {"intent": "intent:MISSING", "basis": "observed", "source": "https://example.com/source",
             "checked_at": "2026-10-19T00:00:00Z", "source_revision": "fixture-revision",
             "evidence": {"kind": "observation", "text": "Explicit fixture observation"},
             "environment": {"build": "fixture"}},
    "hint": {"goal": "goal:MISSING", "intent": "intent:MISSING"},
}
_FIELD_EXAMPLES = {field: value for fields in _KIND_FIELD_EXAMPLES.values() for field, value in fields.items()}


@pytest.mark.parametrize("kind, field, value", [
    (kind, field, value) for kind in _KIND_FIELD_EXAMPLES
    for field, value in _FIELD_EXAMPLES.items() if field not in _KIND_FIELD_EXAMPLES[kind]
])
@pytest.mark.parametrize("amend", [False, True])
def test_cross_kind_fields_cannot_write_a_ledger_the_reader_rejects(target, kind, field, value, amend):
    goal(target)
    defaults = {"goal": {"criteria": [{"id": "C1", "text": "Evidence exists"}]},
                "intent": {"goals": ["goal:G1"]}, "fact": {"basis": "observed"}, "hint": {}}
    if amend:
        node(target, kind, "wrong-kind-field", "Original record", **defaults[kind])
    path = asg.ledger_path(target)
    before = path.read_bytes()
    before_capsule = HuntLoop.load(path).capsule()
    before_graph = graph(target)
    fields = {**defaults[kind], field: value}
    with pytest.raises(ValueError, match="unsupported for its kind"):
        node(target, kind, "wrong-kind-field", "Reject fields from a different node kind", amend=amend, **fields)
    assert path.read_bytes() == before
    # Replay through a new loop instance; a cached projection cannot hide damage.
    fresh = HuntLoop.load(path)
    assert fresh.capsule() == before_capsule
    assert graph(target) == before_graph


def test_same_kind_fields_survive_creation_and_text_only_amendment(target):
    goal(target)
    intent(target)
    fact(target, intent="intent:I1")
    node(target, "hint", "N1", "Scoped hint", goal="goal:G1", intent="intent:I1")
    for kind, identifier in (("goal", "G1"), ("intent", "I1"), ("fact", "F1"), ("hint", "N1")):
        node(target, kind, identifier, "Amended text retains same-kind fields", amend=True)
    assert len([n for n in graph(target)["nodes"] if n["kind"] in {"goal", "intent", "fact", "hint"}]) == 4


def test_canonical_finding_amendment_cannot_create_a_causal_cycle(target):
    goal(target)
    intent(target, "I1")
    asg.record_finding(target, "ACME-001", intent_id="I1")
    intent(target, "I2", parents=["finding:ACME-001"])
    path = asg.ledger_path(target)
    before, before_graph = path.read_bytes(), graph(target)
    with pytest.raises(ValueError, match="cycle"):
        asg.append_event(target, "finding", finding_id="ACME-001", intent_id="intent:I2")
    assert path.read_bytes() == before
    assert HuntLoop.load(path).capsule()["research"]["ready_intents"] == ["intent:I1", "intent:I2"]
    assert graph(target) == before_graph


@pytest.mark.parametrize("keep_explicit_yield", [False, True])
def test_legal_finding_reparent_preserves_explicit_yields_and_single_identity(target, keep_explicit_yield):
    goal(target)
    intent(target, "I1")
    intent(target, "I2")
    asg.record_finding(target, "ACME-001", intent_id="intent:I1")
    old_edge = {"src": "intent:I1", "rel": "yields", "dst": "finding:ACME-001"}
    if keep_explicit_yield:
        asg.append_event(target, "research_link", **old_edge)
    asg.append_event(target, "finding", finding_id="ACME-001", intent_id="I2", title="Amended canonical finding")
    result = graph(target)
    assert (old_edge in result["edges"]) is keep_explicit_yield
    assert {"src": "intent:I2", "rel": "yields", "dst": "finding:ACME-001"} in result["edges"]
    assert len([n for n in result["nodes"] if n["ref"] == "finding:ACME-001"]) == 1
    assert next(n for n in result["nodes"] if n["ref"] == "finding:ACME-001")["intent_id"] == "I2"


@pytest.mark.parametrize("event", [
    {"type": "finding", "finding_id": "ACME-001", "intent_id": "I2"},
    {"type": "research_link", "src": "finding:ACME-001", "rel": "derived_from", "dst": "intent:I1"},
])
def test_strict_replay_rejects_cycles_through_canonical_finding_yields(target, event):
    goal(target)
    intent(target, "I1")
    asg.record_finding(target, "ACME-001", intent_id="I1")
    intent(target, "I2", parents=["finding:ACME-001"])
    path = asg.ledger_path(target)
    path.write_text(path.read_text() + json.dumps(event) + "\n")
    with pytest.raises(LedgerReadError, match="invalid"):
        HuntLoop.load(path)
