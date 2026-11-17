"""GraphWalker planning never executes product operations."""

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
import flow_model as fm
import graphwalker_adapter as gw

from tests import test_flow_model as fixtures


@pytest.fixture
def setup(tmp_path):
    return fixtures.setup.__wrapped__(tmp_path)


def test_bounded_adapter_records_only_a_plan(setup, tmp_path, monkeypatch):
    loop, definition, _ = setup
    binary = tmp_path / "graphwalker"
    binary.touch()
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if "--version" in argv:
            return SimpleNamespace(stdout="graphwalker 1.0.4 (git fixture)")
        if "offline" in argv:
            return SimpleNamespace(stdout='{"modelId":"sharing","currentElementId":"create"}')
        return SimpleNamespace(stdout="valid")

    monkeypatch.setattr(gw.subprocess, "run", run)
    plan = fm.plan_graphwalker(loop, "sharing", binary)
    assert plan["stage"] == "planned" and plan["transition_ids"] == ["create"]
    assert fm.project(loop.events, loop.base_path)["external_plans"][0]["stale"] is False
    assert not any(e["type"] in {"action_started", "verdict", "flow_trace_started"} for e in loop.events)
    assert len(calls) == 3
    with pytest.raises(ValueError, match="bounded"):
        gw.generate(definition, binary, length=201)


@pytest.mark.skipif(not os.getenv("VAULT_GRAPHWALKER_BIN"), reason="optional pinned external runtime")
def test_real_runtime_offline_import(setup):
    _, definition, _ = setup
    plan = gw.generate(definition, os.environ["VAULT_GRAPHWALKER_BIN"], length=20, seed=42)
    assert plan["stage"] == "planned" and plan["transition_ids"]
    assert set(plan["transition_ids"]) <= {t["id"] for t in definition["transitions"]}
