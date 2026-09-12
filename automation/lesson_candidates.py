#!/usr/bin/env python3
"""lesson_candidates.py — auto-DRAFT LL candidates from a target's ASG ledger.

Closes the experience->KB loop at policy A (auto-draft, human-promote): the hunt loop
already records what it learned as ledger events (refuted paths, dead-ends with a
generalisable cause + reopen scope), but that knowledge stayed per-target and only
reached the curated KB if a human ran lessons-miner + bb-knowledge-capture. This reads
those events and writes candidate stubs to a STAGING dir — never into the curated
`Lessons/LL-*.md` (so retrieval is not polluted and quality stays human-gated).

A candidate is drafted from a REFUTED verdict or a dead_end whose cause is generalisable
(refuted / inconclusive-exhausted) — i.e. reusable "this is not a vuln because X" /
"couldn't prove it, reopen when Z" knowledge, exactly the anti-false-positive material
the KB values. BLOCKED (env-gated) and CONFIRMED (a finding, different flow) are skipped.

Honest scope: this produces mechanical STUBS with source linkage, not polished lessons.
The value is that nothing learned is silently lost; a human/bb-knowledge-capture refines
and promotes (rename CAND-*.md -> Lessons/LL-NNN-*.md).

    python3 automation/lesson_candidates.py <target>      # write staging candidates
    python3 automation/lesson_candidates.py <target> --dry # list, write nothing
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import asg
from hunt_loop import HuntLoop

# generalisable dead-end causes -> worth a lesson; env-gated blocked is not.
_GENERALISABLE = {"refuted", "inconclusive-exhausted", "disputed", "invalidated"}
_TAG_FOR_CAUSE = {
    "refuted": ["false-positive", "verification"],
    "inconclusive-exhausted": ["methodology", "verification"],
    "disputed": ["verification", "adversarial-verification"],
    "invalidated": ["methodology"],
}


def _staging_dir() -> Path:
    return asg.vault_root() / "09 - Knowledge Base" / "Lesson Candidates"


def _slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", s).strip("-").lower()[:48] or "x"


def draft_candidates(target: str | Path) -> list[dict]:
    """Pure read over the target's ASG ledger; returns candidate dicts. Never writes."""
    led = asg.ledger_path(target)
    if not led.exists():
        return []
    loop = HuntLoop.load(led)
    lh: dict[str, dict] = {}     # hyp_id -> logic_hypothesis
    lv: dict[str, dict] = {}     # hyp_id -> logic_verdict
    verdicts: dict[str, str] = {}
    evidence: dict[str, str] = {}   # hyp_id -> verdict event's evidence_ref (the 思路
                                    # for hand-recorded / non-logic-loop verdicts)
    dead: dict[str, dict] = {}
    for e in loop.events:
        k, hid = e.get("kind"), e.get("hyp_id")
        if not hid:
            continue
        if k == "logic_hypothesis":
            lh[hid] = e
        elif k == "logic_verdict":
            lv[hid] = e
        elif k == "verdict":
            verdicts[hid] = e.get("verdict")
            if e.get("evidence_ref"):
                evidence[hid] = e["evidence_ref"]
        elif k == "dead_end":
            dead[hid] = e            # last one wins

    out: list[dict] = []
    seen: set[str] = set()
    # union of refuted verdicts + generalisable dead-ends
    hyp_ids = [h for h, v in verdicts.items() if v == "refuted"]
    hyp_ids += [h for h, d in dead.items() if d.get("cause") in _GENERALISABLE]
    for hid in hyp_ids:
        if hid in seen:
            continue
        seen.add(hid)
        h = lh.get(hid, {})
        v = lv.get(hid, {})
        d = dead.get(hid, {})
        cause = d.get("cause") or ("refuted" if verdicts.get(hid) == "refuted" else "inconclusive-exhausted")
        dimension = h.get("dimension", "invariant")
        invariant = h.get("invariant", "") or (h.get("surface_id") or hid)
        reason = v.get("reason", "") or evidence.get(hid, "")
        t_out, c_out = v.get("test_outcome"), v.get("control_outcome")
        differential = (f"test→{t_out} vs control→{c_out}" if t_out or c_out else "")
        reopen = d.get("reopen_when", "")
        scope = d.get("scope") or h.get("applies_env") or {}
        # a lesson needs reusable content: a differential, a stated reason, or a reopen
        # condition. A bare refuted hypothesis with none of these is not worth a stub.
        if not (reason or differential or reopen):
            continue
        title = f"[{dimension}] {invariant}"[:120]
        # the drafted 思路 (rule): why it did not stand + how to generalise + reopen
        rule = (
            f"假設「{invariant}」({dimension}) 結論 = {cause.upper()}。"
            + (f" 差異證據：{differential}。" if differential else "")
            + (f" 判定理由：{reason}。" if reason else "")
            + f" 推廣：測 {dimension} 類假設前，先確認觀察到的行為不是預設/設計行為（control 比較），"
              "不要把 ran_ok 當 confirmed。"
            + (f" Reopen 條件：{reopen}。" if reopen else "")
            + (f" 適用範圍：{scope}。" if scope else "")
        )
        out.append({
            "hyp_id": hid,
            "cause": cause,
            "title": title,
            "rule": rule,
            "tags": sorted(set(["bb-lesson", "auto-draft", _slug(dimension)] + _TAG_FOR_CAUSE.get(cause, []))),
            "source_ledger": str(led),
            "reopen_when": reopen,
        })
    return out


def _existing_ll_titles() -> list[str]:
    """Titles + summaries of curated LLs, lower-cased, for crude dedup."""
    try:
        from kb_connector import kb_lessons
        # broad pull: every lesson carries bb-lesson
        hits = kb_lessons(["bb-lesson"])
    except Exception:
        return []
    return [f"{h.get('title','')} {h.get('summary','')}".lower() for h in hits]


def _covered(title: str, existing: list[str]) -> bool:
    """Crude token-overlap dedup: skip a candidate an existing LL already covers."""
    toks = {t for t in re.findall(r"[a-z0-9]+", title.lower()) if len(t) > 3}
    if not toks:
        return False
    for e in existing:
        etoks = set(re.findall(r"[a-z0-9]+", e))
        if len(toks & etoks) >= max(2, len(toks) * 2 // 3):
            return True
    return False


def write_candidates(target: str | Path, *, dry: bool = False) -> list[Path]:
    """Draft + write staging candidate files. Idempotent (filename keyed on hyp_id).
    Dedups against curated LLs by crude title overlap. Returns written/would-write paths."""
    cands = draft_candidates(target)
    if not cands:
        return []
    existing = _existing_ll_titles()
    tgt = asg._basename(target)
    out_dir = _staging_dir()
    written: list[Path] = []
    for c in cands:
        if _covered(c["title"], existing):
            continue
        fp = out_dir / f"CAND-{tgt}-{_slug(c['hyp_id'])}.md"
        body = (
            "---\n"
            "type: lesson-candidate\n"
            "status: candidate\n"          # human/bb-knowledge-capture flips to promote
            f"title: \"{c['title']}\"\n"
            f"summary: \"{c['rule'][:180].replace(chr(34), chr(39))}\"\n"
            f"source_target: {tgt}\n"
            f"source_hyp_id: {c['hyp_id']}\n"
            f"source_ledger: \"{c['source_ledger']}\"\n"
            "tags:\n" + "".join(f"  - {t}\n" for t in c["tags"]) +
            "---\n\n"
            f"# LL candidate — {c['title']}\n\n"
            f"{c['rule']}\n\n"
            "> Auto-drafted from the ASG ledger (policy A: auto-draft, human-promote). "
            "Refine and promote via `bb-knowledge-capture` — rename to "
            "`09 - Knowledge Base/Lessons/LL-NNN-*.md` once reviewed. Delete if not useful.\n"
        )
        if dry:
            written.append(fp)
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        fp.write_text(body, encoding="utf-8")
        written.append(fp)
    return written


def _main(argv: list[str]) -> int:
    if not argv:
        print("usage: lesson_candidates.py <target> [--dry]", file=sys.stderr)
        return 2
    dry = "--dry" in argv
    target = argv[0]
    paths = write_candidates(target, dry=dry)
    verb = "would write" if dry else "wrote"
    print(f"{verb} {len(paths)} LL candidate(s) for {target}:")
    for p in paths:
        print(f"  - {p}")
    if not paths:
        print("  (none — no generalisable refuted/dead-end material, or all covered by existing LLs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
