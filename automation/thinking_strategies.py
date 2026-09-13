#!/usr/bin/env python3
"""thinking_strategies.py — meta-cognitive prompts for hypothesis CREATIVITY.

The hunt loop has two kinds of knowledge injection:
  1. PATTERNS (kb_connector) — "here are known bug shapes to instantiate" → coverage
  2. STRATEGIES (this module) — "here are thinking MOVES for generating NON-OBVIOUS
     hypotheses" → DISCOVERY POWER

These are fundamentally different. A pattern says "test WRITE-5 angles on every write
endpoint" (breadth). A strategy says "the defense mechanism itself is the attack surface
— does the WAF have its own parsing bug?" (depth/creativity).

Sourced from:
  - Orange Tsai HITCON 2026 Edge sandbox escape (4 logic bugs chained, $175K)
  - Vault cross-target experience
  - LL-296 (browser logic chain → Electron mapping)
  - LL-297 (thin bootstrapper decoy)
  - LL-298 (updater trust chain audit)
  - LL-299 (blackbox mature target false positive refutation)

Each strategy is a meta-cognitive prompt: it tells the LLM HOW to think, not WHAT to
look for. The strategies are always injected (not tag-gated) because creative thinking
applies to every stack.
"""
from __future__ import annotations

from typing import Optional
from pathlib import Path

STRATEGIES: list[dict] = [
    {
        "name": "ARCHITECTURE_CONFUSION",
        "move": (
            "Two subsystems interpret the SAME input with different trust assumptions. "
            "Ask: 'Component A treats {input} as {meaning_A}; Component B treats it as "
            "{meaning_B} — can I route A's output into B to cross a trust boundary?'"
        ),
        "example": (
            "Edge CA Guidance treats a URL as a navigation hint; the renderer treats "
            "javascript: as executable code → UXSS (Orange, CVE-2026-45495)"
        ),
    },
    {
        "name": "FEATURE_INTERACTION",
        "move": (
            "Two individually-safe features produce an unsafe outcome when triggered "
            "together or in sequence. Neither is a bug alone. "
            "Ask: 'Features F1 and F2 are safe alone — what happens if I trigger F1→F2?'"
        ),
        "example": (
            "Profile switch + javascript: URI + tab race = sandbox escape; "
            "OAuth redirect_uri validation + open redirect on a whitelisted domain = token theft"
        ),
    },
    {
        "name": "TRUST_INHERITANCE",
        "move": (
            "An unusual execution context inherits permissions from its parent/creator "
            "that the developer never intended it to have. "
            "Ask: 'Context C was created by P. Does C get P's full permissions? Should it?'"
        ),
        "example": (
            "about:blank inherits full contextBridge (116 methods) because parent had "
            "isInternal=true — the check is on the parent, not the child (LL-282/LL-296)"
        ),
    },
    {
        "name": "DEFENSE_INVERSION",
        "move": (
            "The defense mechanism itself is the attack surface — it has its own parsing, "
            "validation, or state that can be bypassed or exploited. "
            "Ask: 'Defense D (blocklist/WAF/rate-limit/validator) — does D have its own bugs?'"
        ),
        "example": (
            "URL scheme denylist misses smb:/ftp:/search-ms: → UNC auth theft; "
            "rate-limit keyed on token → re-fetch token resets counter (LL-203)"
        ),
    },
    {
        "name": "IMPLICIT_STATE",
        "move": (
            "After action A, the system enters a state where B's security properties "
            "differ from what B's own authorization check assumed. The check ran in "
            "state S0 but B executes in state S1. "
            "Ask: 'After A, is the system in a state where B behaves differently?'"
        ),
        "example": (
            "After enabling auto-start + disabling exit-on-close + changing the "
            "server endpoint on a desktop app, it becomes a persistent C2 beacon — "
            "each state change is benign alone, the combination is persistent compromise"
        ),
    },
    {
        "name": "CHAIN_ESCALATION",
        "move": (
            "A single finding is low-severity alone, but CHAINING it with another "
            "reachable feature/bug escalates to critical. Don't dismiss low-severity. "
            "Ask: 'Finding F is low. Is there a reachable feature G where F+G → critical?'"
        ),
        "example": (
            "Config disclosure (info) → leaked API key → admin endpoint → RCE (critical); "
            "Orange's Edge escape: 4 minor logic bugs → $175K Pwn2Own sandbox escape"
        ),
    },
    {
        "name": "SEMANTIC_GAP",
        "move": (
            "What LOOKS like a security property is actually its absence — the name, "
            "type, or structure implies enforcement that doesn't exist. "
            "Ask: 'This is named/typed as {X}. Does the system ACTUALLY enforce {X}?'"
        ),
        "example": (
            "SPA catch-all returns 200 for /admin — looks like admin endpoint, it's "
            "just the app shell (LL-299); Content-Type says JSON but server parses "
            "as form-urlencoded; 'private' API key in client config is public-by-design"
        ),
    },
]


def compute_strategy_stats(events: list[dict]) -> dict[str, dict]:
    """Compute per-strategy effectiveness from ledger events.

    Correlates hypothesis events (which record strategy) with verdict events
    to produce {strategy_name: {total, confirmed, refuted, inconclusive, rate}}.
    This is the feedback loop: real-world results rank strategies so the LLM
    self-adjusts (read log → find root cause → iterate)."""
    hyp_strategy: dict[str, str] = {}
    for e in events:
        if e.get("kind") == "hypothesis" and e.get("strategy"):
            hyp_strategy[e["hyp_id"]] = e["strategy"]

    stats: dict[str, dict] = {}
    for e in events:
        if e.get("kind") != "verdict":
            continue
        strat = hyp_strategy.get(e.get("hyp_id", ""))
        if not strat:
            continue
        if strat not in stats:
            stats[strat] = {"total": 0, "confirmed": 0, "refuted": 0, "inconclusive": 0}
        s = stats[strat]
        v = e.get("verdict", "")
        s["total"] += 1
        if v == "confirmed":
            s["confirmed"] += 1
        elif v == "refuted":
            s["refuted"] += 1
        else:
            s["inconclusive"] += 1

    for s in stats.values():
        decided = s["confirmed"] + s["refuted"]
        s["rate"] = s["confirmed"] / decided if decided > 0 else 0.0

    return stats


def format_strategies(strategies: Optional[list[dict]] = None,
                      methodology_hints: Optional[list[str]] = None,
                      effectiveness: Optional[dict[str, dict]] = None) -> str:
    """Format strategies as a prompt section for the LLM propose call.

    `methodology_hints` (optional): concrete methodology hints from LLs, injected
    as "here's how these strategies played out in real targets" — bridges the gap
    between abstract thinking moves and concrete hypothesis generation."""
    strats = strategies or STRATEGIES
    lines = [
        "THINKING STRATEGIES — BEFORE proposing, scan the refuted/blocked/capabilities "
        "lists below and apply AT LEAST ONE of these thinking moves. A hypothesis that "
        "applies a strategy to the CURRENT state is worth 10× a generic checklist item.\n"
        "\n"
        "REFUTATION MINING: each refuted hypothesis is NOT just a dead end — it is "
        "CONFIRMED INFORMATION. A 401 on /admin confirms admin EXISTS. A catch-all 200 "
        "confirms the router SHAPE. Use refuted results as stepping stones:\n"
        "  - What did the refutation REVEAL about the system's internals?\n"
        "  - Can a different strategy turn that revealed fact into an attack?\n"
    ]
    for s in strats:
        eff_tag = ""
        if effectiveness and s["name"] in effectiveness:
            e = effectiveness[s["name"]]
            pct = int(e["rate"] * 100)
            eff_tag = f" [{e['confirmed']}/{e['total']} confirmed ({pct}%)]"
        lines.append(f"  [{s['name']}]{eff_tag} {s['move']}")
        lines.append(f"    e.g. {s['example']}")
    if effectiveness:
        ranked = sorted(effectiveness.items(), key=lambda kv: -kv[1]["rate"])
        top = [f"{n} ({int(s['rate']*100)}%)" for n, s in ranked if s["total"] >= 2]
        if top:
            lines.append(f"\n  EFFECTIVENESS RANKING (from this hunt): {' > '.join(top)}")
    lines.append(
        "\nAPPLY TO CURRENT STATE: replace {input}/{meaning_A}/{meaning_B}/etc with "
        "CONCRETE values from the ASG state below — surface names, refuted paths, held "
        "capabilities. Do NOT output a hypothesis that could be generated without reading "
        "the state — that means you're running a checklist, not thinking.\n"
    )
    if methodology_hints:
        lines.append("METHODOLOGY HINTS from prior hunts (concrete applications):")
        for h in methodology_hints[:8]:
            lines.append(f"  - {h}")
        lines.append("")
    return "\n".join(lines)


def load_methodology_hints(kb_dir: Optional[Path] = None) -> list[str]:
    """Extract one-line methodology hints from methodology-tagged LLs in the KB.

    These are concrete examples of how the abstract strategies played out in
    real targets — they bridge "think creatively" to "here's what creative
    thinking looks like on a real codebase." Only methodology/craft class LLs
    are included; pattern-matching/checklist LLs stay in the depth_hint path."""
    try:
        from kb_connector import kb_lessons
        hits = kb_lessons(["methodology", "craft"], kb_dir)
        out = []
        for h in hits:
            if h.get("summary"):
                out.append(f"{h['lesson_id']}: {h['summary'][:200]}")
        return out[:12]
    except Exception:
        return []
