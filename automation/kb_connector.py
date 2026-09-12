#!/usr/bin/env python3
"""kb_connector.py — connect the hunt loop's lesson retrieval to the EXISTING
vault KB (the 137 Lessons/, not just the loop's own lesson events).

Step 3 of the plan: "retrieve relevant experience BEFORE testing." The loop's
own `retrieve_lessons` (hunt_integration) only sees lessons recorded in this
ledger. A real hunt should also consult the accumulated KB. This reads the vault
`09 - Knowledge Base/Lessons/LL-*.md` frontmatter tags and returns tag-matched
lessons, then records a `kb_consulted` event so "which prior knowledge informed
this hypothesis" is auditable.

Honest limit: this logs what was CONSULTED (retrieval + which lessons). Whether a
lesson actually CHANGED the decision is marked by the operator/agent via
mark_influence(), not auto-measured — a retrieval count is not an influence proof.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

_TAGS_INLINE_RE = re.compile(r"^tags:\s*\[(.*?)\]\s*$", re.MULTILINE)
# block form:  tags:\n  - foo\n  - bar   (>half the KB uses this — the inline-only
# parser silently missed 70/137 lessons, which is why merged tags "vanished")
_TAGS_BLOCK_RE = re.compile(r"^tags:\s*\n((?:[ \t]*-[ \t]*\S.*(?:\n|$))+)", re.MULTILINE)
_BLOCK_ITEM_RE = re.compile(r"^[ \t]*-[ \t]*(.+?)\s*$", re.MULTILINE)
_TITLE_RE = re.compile(r'^title:\s*"?(.*?)"?\s*$', re.MULTILINE)
_SUMMARY_RE = re.compile(r'^summary:\s*"?(.*?)"?\s*$', re.MULTILINE)
_ID_RE = re.compile(r"(LL-[0-9A-Za-z]+)")


def _default_kb() -> Path:
    return Path(__file__).resolve().parents[1] / "09 - Knowledge Base" / "Lessons"


def _clean(items: list[str]) -> list[str]:
    return [t.strip().strip('"').strip("'") for t in items if t.strip()]


def _parse_tags(front: str) -> list[str]:
    """Parse both inline (`tags: [a, b]`) and block (`tags:\n  - a\n  - b`) YAML
    tag lists — the KB uses both, and the inline-only parser missed every
    block-format lesson."""
    m = _TAGS_INLINE_RE.search(front)
    if m:
        return _clean(m.group(1).split(","))
    b = _TAGS_BLOCK_RE.search(front)
    if b:
        return _clean(_BLOCK_ITEM_RE.findall(b.group(1)))
    return []


def kb_lessons(tags: list[str], kb_dir: Optional[Path] = None) -> list[dict]:
    """Return vault-KB lessons whose frontmatter tags overlap `tags`."""
    kb_dir = Path(kb_dir) if kb_dir else _default_kb()
    want = {t.lower() for t in tags}
    out: list[dict] = []
    if not kb_dir.is_dir():
        return out
    for f in sorted(kb_dir.glob("LL-*.md")):
        text = f.read_text(encoding="utf-8", errors="ignore")
        front = text.split("---", 2)[1] if text.startswith("---") else text[:800]
        ltags = _parse_tags(front)
        if want & {t.lower() for t in ltags}:
            idm = _ID_RE.search(f.name)
            tm = _TITLE_RE.search(front)
            sm = _SUMMARY_RE.search(front)
            title = tm.group(1) if tm else f.stem
            summary = sm.group(1) if sm else ""
            # the LL's actual 思路 lives in the body; when there is no distinct
            # summary, fall back to the first non-heading body line so retrieval
            # carries the method, not just the name.
            if not summary or summary == title:
                body = text.split("---", 2)[2] if text.count("---") >= 2 else text
                for ln in body.splitlines():
                    s = ln.strip().lstrip("#").strip()
                    if s and not s.startswith("#") and s != title:
                        summary = s[:200]
                        break
            out.append({
                "lesson_id": idm.group(1) if idm else f.stem,
                "title": title,
                "summary": summary,
                "tags": ltags,
                "path": str(f),
                "source": "vault-kb",
            })
    return out


def retrieve_all(loop, hyp_id: str, tags: list[str], kb_dir: Optional[Path] = None) -> dict:
    """Consult BOTH the ledger's own lessons and the vault KB before testing;
    record an auditable `kb_consulted` event tying the consulted KB lessons to
    this hypothesis."""
    from hunt_integration import retrieve_lessons  # ledger-local lessons
    ledger_hits = retrieve_lessons(loop, hyp_id, tags)      # also logs lesson_retrieval
    kb_hits = kb_lessons(tags, kb_dir)
    loop.append("kb_consulted", hyp_id=hyp_id, tags=sorted(set(tags)),
                kb_lesson_ids=[h["lesson_id"] for h in kb_hits])
    return {"ledger": ledger_hits, "kb": kb_hits}


def mark_influence(loop, hyp_id: str, lesson_id: str, changed_decision: bool, note: str = "") -> None:
    """Record whether a consulted lesson actually changed the plan for this
    hypothesis (operator/agent judgement — NOT inferred from retrieval)."""
    loop.append("lesson_influence", hyp_id=hyp_id, lesson_id=lesson_id,
                changed_decision=bool(changed_decision), note=note)


def record_lesson_effect(loop, hyp_id: str, lesson_id: str, outcome: str,
                         avoided_retread: bool = False, note: str = "") -> None:
    """Record the OUTCOME after consulting a lesson — closing the loop from
    'consulted' to 'did it help'. `avoided_retread`=True means the lesson steered
    us off a path that was already dead. This is the measurable-learning signal
    the retrieval count alone can't provide."""
    loop.append("lesson_effect", hyp_id=hyp_id, lesson_id=lesson_id,
                outcome=outcome, avoided_retread=bool(avoided_retread), note=note)


def lesson_effect_report(loop) -> dict:
    """Aggregate, per lesson, whether consulting it correlates with better outcomes:
    how often it was consulted, how often it changed a decision, how often the
    hypothesis that consulted it reached a DECISIVE verdict (confirmed/refuted) vs
    stayed inconclusive, and how often it avoided a re-tread.

    Honest limit: 'decisive_after' is CORRELATIONAL (the consult preceded a decisive
    verdict), not proof of causation. Learning is judged by these moving in the right
    direction across cases — never by the number of lessons written."""
    from collections import defaultdict
    verdict_of: dict = {}
    for e in loop.events:
        if e["kind"] in ("logic_verdict", "verdict"):
            verdict_of[e.get("hyp_id")] = e.get("verdict")

    rep: dict = defaultdict(lambda: {"consulted": 0, "changed_decision": 0,
                                     "decisive_after": 0, "inconclusive_after": 0,
                                     "avoided_retread": 0})
    for e in loop.events:
        k = e["kind"]
        if k in ("kb_consulted", "lesson_retrieval"):
            v = verdict_of.get(e.get("hyp_id"))
            for lid in (e.get("kb_lesson_ids") or e.get("lesson_ids") or []):
                r = rep[lid]
                r["consulted"] += 1
                if v in ("confirmed", "refuted"):
                    r["decisive_after"] += 1
                elif v == "inconclusive":
                    r["inconclusive_after"] += 1
        elif k == "lesson_influence" and e.get("changed_decision"):
            rep[e["lesson_id"]]["changed_decision"] += 1
        elif k == "lesson_effect" and e.get("avoided_retread"):
            rep[e["lesson_id"]]["avoided_retread"] += 1
    return dict(rep)
