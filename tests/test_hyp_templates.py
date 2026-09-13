"""hyp_templates — deterministic surface->hypothesis + capability->hypothesis (Gaps 1/2/3)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from logic_vuln_loop import Env  # noqa: E402
from hunt_loop import HuntLoop  # noqa: E402
import hyp_templates as H  # noqa: E402


def test_classify_surface_maps_node_ids_to_types():
    assert H.classify_surface("account-graphql-introspection") == "graphql"
    assert H.classify_surface("webapp-markdown-protocol-allowlist") == "protocol"
    assert H.classify_surface("emerald-azure-subdomain-takeover") == "dns"
    assert H.classify_surface("rma-svc-api-v1-companies") == "api"
    assert H.classify_surface("something-unlabelled") == "generic"


def test_surface_templates_are_depth_primed_not_checklist():
    # every template carries a control action for the oracle + a real invariant
    for kind, specs in H.SURFACE_TEMPLATES.items():
        for s in specs:
            assert s["control_action"] and s["test_action"] and s["invariant"]
            assert s["violation_outcome"]
    # dns template bakes in the LL-299 refute pattern (served-content verification)
    dns = H.hypotheses_for_surface(Env(), "x-subdomain-takeover")[0]
    assert "REFUTE" in dns.expected_normal or "NXDOMAIN" in dns.expected_normal


def test_capability_template_requires_the_held_capability():
    hyps = H.hypotheses_for_capability(Env(), "P:cred=api")
    assert hyps and hyps[0].requires == ["P:cred=api"]
    assert "{cap}" not in hyps[0].test_action  # substituted


def test_templater_seeds_untested_surface_into_the_queue(tmp_path):
    """Gap 1/2: an untested surface with NO hypothesis is auto-covered — templated
    hypotheses are seeded onto the ledger so they enter ready_hypotheses."""
    led = tmp_path / "t.jsonl"
    loop = HuntLoop.load(led)
    loop.add_surface("account-graphql-introspection", untested=True)
    registry = {}
    tp = H.make_templater(Env(), registry)
    cap = loop.capsule()
    assert cap["ready_hypotheses"] == []          # nothing to work yet
    first = tp(loop, cap)
    assert first is not None and first.hyp_id.startswith("tpl:")
    cap2 = loop.capsule()
    # seeded hypotheses split: the unauth introspection probe is READY now; the IDOR
    # probe is BLOCKED on R:auth=session (CG info-retention grows without hand-thinking)
    seeded = cap2["ready_hypotheses"] + cap2["blocked_hypotheses"]
    assert len(seeded) >= 2
    assert all(registry[h].surface_id == "account-graphql-introspection" for h in seeded)
    assert cap2["ready_hypotheses"] and cap2["blocked_hypotheses"]


def test_surface_template_prefills_requires_for_info_retention(tmp_path):
    """CG info-retention layer: an api surface auto-seeds an unauth probe (ready) AND
    authed probes BLOCKED on R:auth=session — so the ledger records 'blocked on account'
    without the operator manually declaring it, and provisioning readies them."""
    loop = HuntLoop.load(tmp_path / "a.jsonl")
    loop.add_surface("rma-svc-api-v1-companies", untested=True)
    registry = {}
    tp = H.make_templater(Env(), registry)
    tp(loop, loop.capsule())
    cap = loop.capsule()
    # unauth-read probe runs immediately; IDOR + WRITE-5 wait on a session
    ready_req = [registry[h].requires for h in cap["ready_hypotheses"]]
    blocked_req = [registry[h].requires for h in cap["blocked_hypotheses"]]
    assert [] in ready_req                               # unauth probe is not blocked
    assert all(r == ["R:auth=session"] for r in blocked_req) and blocked_req
    # the R: capability requirement is now recorded on the ledger (info retention)
    reqs = [e.get("requires") for e in loop.events if e["kind"] == "hypothesis"]
    assert ["R:auth=session"] in reqs


def test_templater_leverages_a_held_capability(tmp_path):
    """Gap 3: a held capability gets a downstream leverage hypothesis (requires=cap)."""
    led = tmp_path / "c.jsonl"
    loop = HuntLoop.load(led)
    registry = {}
    tp = H.make_templater(Env(), registry)
    fake_cap = {"capabilities": ["P:cred=api"], "untested_surface": []}
    h = tp(loop, fake_cap)
    assert h is not None and h.requires == ["P:cred=api"]
    # seeded onto the ledger -> ready because its required capability is (would be) held
    reqs = [e.get("requires") for e in loop.events if e["kind"] == "hypothesis"]
    assert ["P:cred=api"] in reqs


def test_templater_returns_none_when_nothing_left(tmp_path):
    loop = HuntLoop.load(tmp_path / "e.jsonl")
    tp = H.make_templater(Env(), {})
    assert tp(loop, {"capabilities": [], "untested_surface": []}) is None
