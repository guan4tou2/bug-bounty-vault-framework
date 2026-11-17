"""Normative offline schemas and capability dependency semantics."""

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
import attack_flow_export as af
from hunt_loop import HuntLoop, Verdict


def setup(tmp_path):
    loop = HuntLoop(base_path=tmp_path)
    proof = tmp_path / "proof.txt"
    proof.write_text("owned fixture observation")
    loop.add_hypothesis("a")
    loop.record_verdict("a", Verdict.CONFIRMED, evidence=str(proof), provides=["read"])
    loop.add_hypothesis("b", requires=["read", "role"])
    return loop, proof


def test_default_is_supported_only_and_read_only(tmp_path):
    loop, _ = setup(tmp_path)
    before = copy.deepcopy(loop.events)
    bundle = af.export(loop, "fixture")
    assert af.validate_bundle(bundle)
    assert [o["name"] for o in bundle["objects"] if o["type"] == "attack-action"] == ["a"]
    assert loop.events == before


def test_pending_and_multiple_requirements_have_explicit_conditions(tmp_path):
    loop, _ = setup(tmp_path)
    bundle = af.export(loop, "fixture", include_pending=True)
    actions = {o["name"]: o for o in bundle["objects"] if o["type"] == "attack-action"}
    assert actions["b"]["x_vault_state"] == "blocked"
    assert actions["b"]["confidence"] == 0
    operators = [o for o in bundle["objects"] if o["type"] == "attack-operator"]
    assert operators[0]["operator"] == "AND"
    assert operators[0]["effect_refs"] == [actions["b"]["id"]]
    assert actions["b"]["id"] not in actions["a"].get("effect_refs", [])


def test_stale_evidence_cannot_export_as_supported(tmp_path):
    loop, proof = setup(tmp_path)
    proof.write_text("changed")
    with pytest.raises(ValueError, match="no supported"):
        af.export(loop, "fixture")


def test_latest_requirements_win_and_dangling_reference_rejected(tmp_path):
    loop, _ = setup(tmp_path)
    loop.add_hypothesis("b", requires=["new"])
    bundle = af.export(loop, "fixture", include_pending=True)
    assert {o["x_vault_capability"] for o in bundle["objects"] if o["type"] == "attack-condition"} == {"new"}
    flow = next(o for o in bundle["objects"] if o["type"] == "attack-flow")
    flow["start_refs"] = ["attack-action--00000000-0000-4000-8000-000000000000"]
    with pytest.raises(ValueError, match="dangling"):
        af.validate_bundle(bundle)


def test_missing_required_stix_property_rejected(tmp_path):
    loop, _ = setup(tmp_path)
    bundle = af.export(loop, "fixture")
    del next(o for o in bundle["objects"] if o["type"] == "attack-action")["name"]
    with pytest.raises(ValueError, match="official schema"):
        af.validate_bundle(bundle)
