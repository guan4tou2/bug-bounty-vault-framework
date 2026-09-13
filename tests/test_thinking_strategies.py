"""thinking_strategies — meta-cognitive prompts for hypothesis creativity."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from thinking_strategies import (STRATEGIES, format_strategies,  # noqa: E402
                                  load_methodology_hints, compute_strategy_stats)


def test_strategies_have_required_fields():
    assert len(STRATEGIES) >= 5
    for s in STRATEGIES:
        assert s["name"] and s["move"] and s["example"]
        assert len(s["move"]) > 40


def test_format_strategies_produces_prompt_section():
    section = format_strategies()
    assert "THINKING STRATEGIES" in section
    for s in STRATEGIES:
        assert s["name"] in section
        assert "e.g." in section


def test_format_strategies_has_refutation_mining_and_anti_checklist():
    """The prompt must tell the LLM to mine refuted hypotheses for creative fuel
    and reject hypotheses that don't reference the ASG state."""
    section = format_strategies()
    assert "REFUTATION MINING" in section
    assert "APPLY TO CURRENT STATE" in section
    assert "without reading the state" in section


def test_format_strategies_includes_methodology_hints():
    hints = ["LL-296: about:blank inherits contextBridge", "LL-299: SPA catch-all refutation"]
    section = format_strategies(methodology_hints=hints)
    assert "METHODOLOGY" in section
    assert "LL-296" in section
    assert "LL-299" in section


def test_format_strategies_without_hints_has_no_methodology_section():
    section = format_strategies(methodology_hints=None)
    assert "METHODOLOGY" not in section


def test_strategies_always_injected_in_propose(tmp_path):
    """The strategies section appears in the propose prompt even when kb_tags is
    empty — strategies are universal thinking moves, not stack-specific patterns."""
    seen = {"prompt": ""}

    def stub_spawn(prompt, model):
        if "planning brain" in prompt:
            seen["prompt"] = prompt
            return '{"stop":true,"reason":"done"}'
        return "{}"

    from hunt_live import run_live
    from logic_vuln_loop import Env
    from hunt_autodrive import Budget

    run_live(tmp_path / "s.jsonl", owner="A", scope_desc="x", hosts=["h"], env=Env(),
             spawn=stub_spawn, budget=Budget(max_actions=2, max_replans=1))
    assert "THINKING STRATEGIES" in seen["prompt"]
    assert "ARCHITECTURE_CONFUSION" in seen["prompt"]
    assert "CHAIN_ESCALATION" in seen["prompt"]
    assert "FEATURE_INTERACTION" in seen["prompt"]
    assert "PRIORITY ORDER" in seen["prompt"]
    assert "strategy_used" in seen["prompt"]
    assert "REFUTATION MINING" in seen["prompt"]


def test_strategies_coexist_with_depth_patterns(tmp_path):
    """Both layers appear in the prompt when kb_tags are provided: strategies
    (how to think) + patterns (what to instantiate)."""
    kb = tmp_path / "kb"
    kb.mkdir()
    (kb / "LL-999-deep.md").write_text(
        "---\ntitle: Test deep pattern\n"
        "summary: test mass-assign angles\n"
        "tags: [electron, write5]\n---\nbody\n", encoding="utf-8")
    seen = {"prompt": ""}

    def stub_spawn(prompt, model):
        if "planning brain" in prompt:
            seen["prompt"] = prompt
            return '{"stop":true,"reason":"done"}'
        return "{}"

    from hunt_live import run_live
    from logic_vuln_loop import Env
    from hunt_autodrive import Budget

    run_live(tmp_path / "d.jsonl", owner="A", scope_desc="x", hosts=["h"], env=Env(),
             spawn=stub_spawn, budget=Budget(max_actions=2, max_replans=1),
             kb_tags=["write5", "electron"], kb_dir=kb)
    assert "THINKING STRATEGIES" in seen["prompt"]
    assert "KNOWN DEEP PATTERNS" in seen["prompt"]
    assert "ARCHITECTURE_CONFUSION" in seen["prompt"]
    assert "LL-999" in seen["prompt"]


def test_load_methodology_hints_from_kb(tmp_path):
    """Methodology hints are extracted from methodology-tagged LLs."""
    kb = tmp_path / "kb"
    kb.mkdir()
    (kb / "LL-500-method.md").write_text(
        "---\ntitle: Updater trust chain audit\n"
        "summary: draw trust chain first then grep guardrails\n"
        "tags: [methodology, updater]\n---\nbody\n", encoding="utf-8")
    (kb / "LL-501-pattern.md").write_text(
        "---\ntitle: CORS reflection\n"
        "summary: check ACAO reflects origin\n"
        "tags: [cors, web]\n---\nbody\n", encoding="utf-8")
    hints = load_methodology_hints(kb)
    assert any("LL-500" in h for h in hints)
    assert not any("LL-501" in h for h in hints)


# ── Strategy Effectiveness Feedback Loop (UCCU-inspired auto-improvement) ──


def test_compute_strategy_stats_empty():
    """No events → no stats."""
    assert compute_strategy_stats([]) == {}


def test_compute_strategy_stats_basic():
    """Strategy→verdict correlation produces correct counts and rates."""
    events = [
        {"kind": "hypothesis", "hyp_id": "h1", "strategy": "CHAIN_ESCALATION"},
        {"kind": "hypothesis", "hyp_id": "h2", "strategy": "CHAIN_ESCALATION"},
        {"kind": "hypothesis", "hyp_id": "h3", "strategy": "SEMANTIC_GAP"},
        {"kind": "hypothesis", "hyp_id": "h4"},  # no strategy
        {"kind": "verdict", "hyp_id": "h1", "verdict": "confirmed"},
        {"kind": "verdict", "hyp_id": "h2", "verdict": "refuted"},
        {"kind": "verdict", "hyp_id": "h3", "verdict": "confirmed"},
        {"kind": "verdict", "hyp_id": "h4", "verdict": "confirmed"},  # no strategy → ignored
    ]
    stats = compute_strategy_stats(events)
    assert "CHAIN_ESCALATION" in stats
    assert stats["CHAIN_ESCALATION"]["confirmed"] == 1
    assert stats["CHAIN_ESCALATION"]["refuted"] == 1
    assert stats["CHAIN_ESCALATION"]["total"] == 2
    assert stats["CHAIN_ESCALATION"]["rate"] == 0.5
    assert "SEMANTIC_GAP" in stats
    assert stats["SEMANTIC_GAP"]["confirmed"] == 1
    assert stats["SEMANTIC_GAP"]["rate"] == 1.0
    assert "h4" not in str(stats)  # no-strategy hyps don't appear


def test_compute_strategy_stats_inconclusive():
    """INCONCLUSIVE verdicts are counted but don't affect the confirmation rate."""
    events = [
        {"kind": "hypothesis", "hyp_id": "h1", "strategy": "DEFENSE_INVERSION"},
        {"kind": "verdict", "hyp_id": "h1", "verdict": "inconclusive"},
    ]
    stats = compute_strategy_stats(events)
    assert stats["DEFENSE_INVERSION"]["inconclusive"] == 1
    assert stats["DEFENSE_INVERSION"]["rate"] == 0.0  # no decided verdicts


def test_format_strategies_with_effectiveness():
    """Effectiveness stats are injected into the prompt as inline annotations."""
    eff = {
        "CHAIN_ESCALATION": {"total": 3, "confirmed": 2, "refuted": 1,
                             "inconclusive": 0, "rate": 0.6667},
        "SEMANTIC_GAP": {"total": 2, "confirmed": 1, "refuted": 1,
                         "inconclusive": 0, "rate": 0.5},
    }
    section = format_strategies(effectiveness=eff)
    assert "[2/3 confirmed (66%)]" in section
    assert "EFFECTIVENESS RANKING" in section
    assert "CHAIN_ESCALATION (66%)" in section


def test_format_strategies_no_effectiveness_no_ranking():
    """Without effectiveness data, no ranking section appears."""
    section = format_strategies(effectiveness=None)
    assert "EFFECTIVENESS RANKING" not in section


def test_format_strategies_effectiveness_needs_minimum_samples():
    """Strategies with < 2 total verdicts are excluded from the ranking line."""
    eff = {
        "CHAIN_ESCALATION": {"total": 1, "confirmed": 1, "refuted": 0,
                             "inconclusive": 0, "rate": 1.0},
    }
    section = format_strategies(effectiveness=eff)
    assert "EFFECTIVENESS RANKING" not in section


def test_strategy_recorded_on_ledger(tmp_path):
    """The strategy_used from LLM propose is persisted in the ledger event."""
    seen = {"prompt": ""}

    def stub_spawn(prompt, model):
        if "planning brain" in prompt:
            seen["prompt"] = prompt
            return ('{"strategy_used":"ARCHITECTURE_CONFUSION",'
                    '"dimension":"trust","invariant":"x","test_action":"GET /a",'
                    '"control_action":"GET /b","violation_outcome":"v",'
                    '"expected_normal_outcome":"401"}')
        return "{}"

    from hunt_live import run_live
    from logic_vuln_loop import Env
    from hunt_autodrive import Budget

    _, loop = run_live(
        tmp_path / "s.jsonl", owner="A", scope_desc="x", hosts=["h"], env=Env(),
        spawn=stub_spawn, budget=Budget(max_actions=1, max_replans=1))

    hyp_events = [e for e in loop.events if e["kind"] == "hypothesis"]
    assert any(e.get("strategy") == "ARCHITECTURE_CONFUSION" for e in hyp_events)


def test_effectiveness_feeds_back_into_format():
    """After computing stats from events, format_strategies annotates the prompt."""
    events = [
        {"kind": "hypothesis", "hyp_id": "h1", "strategy": "CHAIN_ESCALATION"},
        {"kind": "hypothesis", "hyp_id": "h2", "strategy": "CHAIN_ESCALATION"},
        {"kind": "hypothesis", "hyp_id": "h3", "strategy": "DEFENSE_INVERSION"},
        {"kind": "hypothesis", "hyp_id": "h4", "strategy": "DEFENSE_INVERSION"},
        {"kind": "verdict", "hyp_id": "h1", "verdict": "confirmed"},
        {"kind": "verdict", "hyp_id": "h2", "verdict": "confirmed"},
        {"kind": "verdict", "hyp_id": "h3", "verdict": "refuted"},
        {"kind": "verdict", "hyp_id": "h4", "verdict": "refuted"},
    ]
    stats = compute_strategy_stats(events)
    section = format_strategies(effectiveness=stats)
    assert "[2/2 confirmed (100%)]" in section
    assert "CHAIN_ESCALATION" in section
    assert "EFFECTIVENESS RANKING" in section
    assert "CHAIN_ESCALATION (100%) > DEFENSE_INVERSION (0%)" in section
