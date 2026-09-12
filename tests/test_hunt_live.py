"""hunt_live — autodrive as the autonomous live driver.

Proves the loop DRIVES ITSELF through the spawn seam: given only a `spawn(prompt,
model)` primitive, autodrive proposes the next hypothesis, dispatches a worker,
adjudicates by control comparison, and hands back on a stop — with NO human
dispatching each step. A stub spawn stands in for headless `claude -p` so the
self-drive is deterministic and offline.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from hunt_autodrive import Budget  # noqa: E402
from hunt_live import run_live  # noqa: E402
from logic_vuln_loop import Env  # noqa: E402


def test_autodrive_self_drives_through_spawn(tmp_path):
    calls = {"propose": 0, "worker": 0}

    def stub_spawn(prompt, model):
        # the loop's planning brain asks for the next hypothesis...
        if "planning brain" in prompt:
            calls["propose"] += 1
            if calls["propose"] == 1:
                return ('{"dimension":"roles","invariant":"unauth must not read admin",'
                        '"precondition":"none","expected_normal":"denied",'
                        '"test_action":"GET /admin","control_action":"GET /admin anon",'
                        '"violation_outcome":"leaked","expected_normal_outcome":"403"}')
            return '{"stop":true,"reason":"surface exhausted"}'
        # ...and dispatches a worker to run the GET test+control
        if "isolated hunt worker" in prompt:
            calls["worker"] += 1
            return ('```json\n{"test":{"ok":true,"outcome":"leaked","evidence_ref":"poc/a"},'
                    '"control":{"ok":true,"outcome":"403"}}\n```')
        return "{}"

    ledger = tmp_path / "live.jsonl"
    rep, loop = run_live(
        ledger, owner="A", scope_desc="controlled", hosts=["t.example"],
        env=Env(), spawn=stub_spawn,
        budget=Budget(max_actions=5, max_replans=3, max_retries_per_hyp=2),
    )

    # the loop turned on its own: proposed, dispatched a worker, confirmed, then
    # proposed again -> stop -> one clean hand-back. No human dispatched anything.
    assert calls["propose"] >= 2 and calls["worker"] == 1
    assert rep.rounds >= 1
    assert rep.interventions == 1                      # the clean hand-back
    cap = loop.capsule()
    assert cap["confirmed"]                            # the differential confirmed it
    assert cap["capabilities"] == []                   # provides empty -> no capability


def test_stub_stop_hands_back_immediately(tmp_path):
    # propose says stop right away -> autodrive hands back, zero rounds, no worker.
    def stub_spawn(prompt, model):
        if "planning brain" in prompt:
            return '{"stop":true,"reason":"nothing in scope"}'
        return "{}"

    rep, loop = run_live(
        tmp_path / "l.jsonl", owner="A", scope_desc="x", hosts=["h"], env=Env(),
        spawn=stub_spawn, budget=Budget(max_actions=3, max_replans=2))
    assert rep.rounds == 0 and rep.interventions == 1


def test_cg_chaining_unauth_no_account(tmp_path):
    """CG chaining without any account: an unauth finding grants a capability, the
    capability-aware propose leverages it, and the capsule's least-fixed-point only
    stands up the chained capability because its precondition was earned."""
    n = {"p": 0}

    def stub_spawn(prompt, model):
        if "planning brain" in prompt:
            # discriminate on the capability being HELD (serialized into the ASG
            # state's capabilities list) — NOT on the literal example in the schema.
            if '"capabilities": ["P:cred=api"' in prompt:   # earned -> chain deeper
                n["p"] += 1
                if n["p"] == 1:
                    return ('{"dimension":"trust","invariant":"admin api needs auth",'
                            '"test_action":"GET /admin/api with leaked api cred",'
                            '"control_action":"GET /admin/api anon","violation_outcome":"admin_data",'
                            '"expected_normal_outcome":"403","provides":["P:read=admin"],'
                            '"requires":["P:cred=api"]}')
                return '{"stop":true,"reason":"chain exhausted"}'
            # first: an UNAUTH config disclosure that leaks an api credential
            return ('{"dimension":"trust","invariant":"config must not expose creds",'
                    '"test_action":"GET /config.json","control_action":"GET /nonexistent-xyz",'
                    '"violation_outcome":"cred_leaked","expected_normal_outcome":"404",'
                    '"provides":["P:cred=api"],"requires":[]}')
        if "isolated hunt worker" in prompt:
            if "admin" in prompt:
                return '```json\n{"test":{"ok":true,"outcome":"admin_data","evidence_ref":"poc/b"},"control":{"ok":true,"outcome":"403"}}\n```'
            return '```json\n{"test":{"ok":true,"outcome":"cred_leaked","evidence_ref":"poc/a"},"control":{"ok":true,"outcome":"404"}}\n```'
        return "{}"

    rep, loop = run_live(
        tmp_path / "chain.jsonl", owner="A", scope_desc="unauth-chain",
        hosts=["t.example"], env=Env(), spawn=stub_spawn,
        budget=Budget(max_actions=6, max_replans=4, max_retries_per_hyp=2))

    cap = loop.capsule()
    # both capabilities held — and P:read=admin ONLY stands because P:cred=api (its
    # requires) was earned first (least fixed point): that IS the CG chain.
    assert cap["capabilities"] == ["P:cred=api", "P:read=admin"]
    assert len(cap["confirmed"]) == 2
    # the chained hypothesis recorded its precondition in the ledger
    reqs = [e.get("requires") for e in loop.events if e["kind"] == "hypothesis"]
    assert any(r == ["P:cred=api"] for r in reqs)


def test_propose_is_primed_with_kb_deep_patterns(tmp_path):
    """The depth lever: when kb_tags name the stack, the vault KB's matching
    deep-pattern lessons are injected INTO the proposal prompt so the loop
    proposes a pattern-instantiating hypothesis, not a generic checklist item."""
    kb = tmp_path / "kb"
    kb.mkdir()
    (kb / "LL-999-deep.md").write_text(
        "---\ntitle: Unauth Write checklist\n"
        "summary: try mass-assign, boundary, dup, cross-entity, state-skip on every write\n"
        "tags: [electron, write5, state-transition]\n---\nbody\n", encoding="utf-8")
    seen = {"prompt": ""}

    def stub_spawn(prompt, model):
        if "planning brain" in prompt:
            seen["prompt"] = prompt
            return '{"stop":true,"reason":"done"}'
        return "{}"

    run_live(tmp_path / "d.jsonl", owner="A", scope_desc="x", hosts=["h"], env=Env(),
             spawn=stub_spawn, budget=Budget(max_actions=2, max_replans=1),
             kb_tags=["write5", "electron"], kb_dir=kb)

    # the deep pattern reached the DECISION step, not just the worker...
    assert "KNOWN DEEP PATTERNS" in seen["prompt"]
    assert "LL-999: Unauth Write checklist" in seen["prompt"]
    # ...carrying the LL 思路 (summary), not just the title
    assert "mass-assign, boundary, dup, cross-entity, state-skip" in seen["prompt"]


def test_propose_without_kb_tags_has_no_depth_hint(tmp_path):
    seen = {"prompt": ""}

    def stub_spawn(prompt, model):
        if "planning brain" in prompt:
            seen["prompt"] = prompt
            return '{"stop":true,"reason":"done"}'
        return "{}"

    run_live(tmp_path / "d.jsonl", owner="A", scope_desc="x", hosts=["h"], env=Env(),
             spawn=stub_spawn, budget=Budget(max_actions=2, max_replans=1))
    assert "KNOWN DEEP PATTERNS" not in seen["prompt"]
