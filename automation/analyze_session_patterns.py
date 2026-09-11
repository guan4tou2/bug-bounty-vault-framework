#!/usr/bin/env python3
"""Analyze session artifacts for recurring action patterns.

Reads HANDOFF.md and Attempts/*.md files across targets, extracts
action sequences (checklist items, numbered steps), groups similar
sequences using string similarity, and outputs candidate patterns
as JSON for the skill-synthesizer agent.

Uses only stdlib — no external dependencies.

Usage:
    python3 automation/analyze_session_patterns.py
    python3 automation/analyze_session_patterns.py --min-frequency 3
    python3 automation/analyze_session_patterns.py --target gitlab
    python3 automation/analyze_session_patterns.py --min-frequency 2 --target acme --output proposals.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from difflib import SequenceMatcher
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS_DIR = ROOT / "01 - Targets"
# Honour an external workspace (VAULT_WORKSPACE), consistent with
# start_session.py / end_session.py; fall back to the in-repo workspace/.
_ext_ws = os.environ.get("VAULT_WORKSPACE")
WORKSHOP_DIR = (Path(_ext_ws) / "workshop") if _ext_ws else (ROOT / "workspace" / "workshop")

# Patterns that identify action lines in markdown
ACTION_PATTERNS = [
    re.compile(r"^- \[[ x]\] (.+)$"),          # checklist items
    re.compile(r"^\d+\.\s+(.+)$"),              # numbered steps
    re.compile(r"^- (?:TODO|FIXME|DEFERRED):\s*(.+)$", re.IGNORECASE),  # deferred items
    re.compile(r"^>\s*(?:Step|Action|Check):\s*(.+)$", re.IGNORECASE),  # quoted steps
]

# Patterns to strip target-specific info for generalization
STRIP_PATTERNS = [
    re.compile(r"https?://[^\s)]+"),            # URLs
    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),  # IPs
    re.compile(r"[A-Z]+-\d{3,}"),               # Finding IDs like LD-027
]


def extract_actions(filepath: Path) -> list[dict]:
    """Extract action lines from a markdown file.

    Returns a list of dicts with keys: text, line, source, type.
    """
    actions: list[dict] = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return actions

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        for pattern in ACTION_PATTERNS:
            m = pattern.match(stripped)
            if m:
                actions.append({
                    "text": m.group(1).strip(),
                    "line": line_num,
                    "source": str(filepath.relative_to(ROOT)),
                    "type": _classify_action(stripped),
                })
                break
    return actions


def _classify_action(line: str) -> str:
    """Classify an action line by type."""
    lower = line.lower()
    if "- [x]" in lower:
        return "completed"
    if "- [ ]" in lower:
        return "pending"
    if any(kw in lower for kw in ("todo", "fixme", "deferred")):
        return "deferred"
    if re.match(r"^\d+\.", line):
        return "step"
    return "action"


def generalize_text(text: str) -> str:
    """Strip target-specific info to enable cross-target matching."""
    result = text
    for pattern in STRIP_PATTERNS:
        result = pattern.sub("<REDACTED>", result)
    # Collapse whitespace
    result = re.sub(r"\s+", " ", result).strip()
    return result


def find_handoff_files(target: str | None = None) -> list[Path]:
    """Find all HANDOFF.md files, optionally scoped to a target."""
    files: list[Path] = []

    if target:
        search_dirs = [
            TARGETS_DIR / target,
            WORKSHOP_DIR / target,
        ]
    else:
        search_dirs = [TARGETS_DIR, WORKSHOP_DIR]

    for search_dir in search_dirs:
        if search_dir.is_dir():
            files.extend(search_dir.rglob("HANDOFF*.md"))

    return files


def find_attempt_files(target: str | None = None) -> list[Path]:
    """Find all Attempts/*.md files, optionally scoped to a target."""
    files: list[Path] = []

    if target:
        attempts_dir = TARGETS_DIR / target / "Attempts"
        if attempts_dir.is_dir():
            files.extend(attempts_dir.glob("*.md"))
    else:
        for attempts_dir in TARGETS_DIR.rglob("Attempts"):
            if attempts_dir.is_dir():
                files.extend(attempts_dir.glob("*.md"))

    return files


def group_similar_actions(
    actions: list[dict],
    threshold: float = 0.7,
) -> list[dict]:
    """Group actions by text similarity.

    Returns groups with count >= 1, each containing:
    - representative: the most common text variant
    - generalized: target-stripped version
    - count: number of similar actions
    - sources: list of source files
    - members: list of original action dicts
    """
    if not actions:
        return []

    # Generalize all texts first
    for action in actions:
        action["generalized"] = generalize_text(action["text"])

    # Group by generalized similarity
    groups: list[dict] = []
    assigned = set()

    for i, action_a in enumerate(actions):
        if i in assigned:
            continue

        group_members = [action_a]
        assigned.add(i)

        for j, action_b in enumerate(actions):
            if j in assigned:
                continue
            ratio = SequenceMatcher(
                None,
                action_a["generalized"].lower(),
                action_b["generalized"].lower(),
            ).ratio()
            if ratio >= threshold:
                group_members.append(action_b)
                assigned.add(j)

        # Pick representative (most common exact text)
        text_counts: dict[str, int] = defaultdict(int)
        for member in group_members:
            text_counts[member["generalized"]] += 1
        representative = max(text_counts, key=text_counts.get)  # type: ignore[arg-type]

        sources = sorted(set(m["source"] for m in group_members))

        groups.append({
            "representative": representative,
            "count": len(group_members),
            "sources": sources,
            "source_count": len(sources),
            "members": [
                {"text": m["text"], "source": m["source"], "type": m["type"]}
                for m in group_members
            ],
        })

    return groups


def extract_sequences(filepath: Path, min_length: int = 3) -> list[list[dict]]:
    """Extract consecutive action sequences from a file.

    A sequence is a run of 3+ consecutive action lines (checklists,
    numbered steps). These represent multi-step workflows.
    """
    actions = extract_actions(filepath)
    if len(actions) < min_length:
        return []

    sequences: list[list[dict]] = []
    current_seq: list[dict] = []

    for i, action in enumerate(actions):
        if not current_seq:
            current_seq.append(action)
        elif action["line"] - current_seq[-1]["line"] <= 2:
            # Consecutive or near-consecutive lines
            current_seq.append(action)
        else:
            if len(current_seq) >= min_length:
                sequences.append(current_seq)
            current_seq = [action]

    if len(current_seq) >= min_length:
        sequences.append(current_seq)

    return sequences


def group_similar_sequences(
    all_sequences: list[list[dict]],
    threshold: float = 0.6,
) -> list[dict]:
    """Group similar multi-step sequences across files.

    Each sequence is compared as a joined string of generalized actions.
    """
    if not all_sequences:
        return []

    # Build fingerprint for each sequence
    fingerprints: list[tuple[str, list[dict]]] = []
    for seq in all_sequences:
        fp = " → ".join(generalize_text(a["text"]) for a in seq)
        fingerprints.append((fp, seq))

    groups: list[dict] = []
    assigned = set()

    for i, (fp_a, seq_a) in enumerate(fingerprints):
        if i in assigned:
            continue

        group_seqs = [seq_a]
        assigned.add(i)

        for j, (fp_b, seq_b) in enumerate(fingerprints):
            if j in assigned:
                continue
            ratio = SequenceMatcher(None, fp_a.lower(), fp_b.lower()).ratio()
            if ratio >= threshold:
                group_seqs.append(seq_b)
                assigned.add(j)

        sources = sorted(set(
            a["source"] for seq in group_seqs for a in seq
        ))

        groups.append({
            "fingerprint": fingerprints[i][0],
            "step_count": len(seq_a),
            "occurrence_count": len(group_seqs),
            "sources": sources,
            "source_count": len(sources),
            "steps": [generalize_text(a["text"]) for a in seq_a],
        })

    return groups


def classify_pattern(group: dict) -> str:
    """Classify a pattern group into a skill type."""
    text = group.get("fingerprint", group.get("representative", "")).lower()

    if any(kw in text for kw in ("check", "verify", "confirm", "validate", "before")):
        return "gate"
    if any(kw in text for kw in ("then", "next", "after", "chain", "→")):
        return "chain"
    if any(kw in text for kw in ("if", "when", "unless", "decide", "choose")):
        return "decision-tree"
    if any(kw in text for kw in ("curl", "grep", "fetch", "scan", "run")):
        return "tool-combo"
    return "workflow"


def analyze(
    target: str | None = None,
    min_frequency: int = 3,
) -> dict:
    """Run full analysis and return structured results."""
    # Collect files
    handoff_files = find_handoff_files(target)
    attempt_files = find_attempt_files(target)
    all_files = handoff_files + attempt_files

    # Extract all actions
    all_actions: list[dict] = []
    for f in all_files:
        all_actions.extend(extract_actions(f))

    # Extract all sequences
    all_sequences: list[list[dict]] = []
    for f in all_files:
        all_sequences.extend(extract_sequences(f))

    # Group similar individual actions
    action_groups = group_similar_actions(all_actions)
    frequent_actions = [
        g for g in action_groups if g["count"] >= min_frequency
    ]
    frequent_actions.sort(key=lambda g: g["count"], reverse=True)

    # Group similar sequences
    sequence_groups = group_similar_sequences(all_sequences)
    frequent_sequences = [
        g for g in sequence_groups if g["occurrence_count"] >= min_frequency
    ]
    frequent_sequences.sort(
        key=lambda g: g["occurrence_count"], reverse=True
    )

    # Classify patterns
    for group in frequent_actions:
        group["pattern_type"] = classify_pattern(group)
    for group in frequent_sequences:
        group["pattern_type"] = classify_pattern(group)

    # Build candidate patterns (sequences are higher value than single actions)
    candidates: list[dict] = []

    for seq_group in frequent_sequences:
        candidates.append({
            "type": "sequence",
            "pattern_type": seq_group["pattern_type"],
            "representative": seq_group["fingerprint"],
            "steps": seq_group["steps"],
            "step_count": seq_group["step_count"],
            "frequency": seq_group["occurrence_count"],
            "sources": seq_group["sources"],
            "source_count": seq_group["source_count"],
            "score": seq_group["occurrence_count"] * seq_group["step_count"],
            "skill_worthy": seq_group["step_count"] >= 5,
        })

    for action_group in frequent_actions:
        # Single actions become candidates only if very frequent
        candidates.append({
            "type": "single_action",
            "pattern_type": action_group["pattern_type"],
            "representative": action_group["representative"],
            "steps": [action_group["representative"]],
            "step_count": 1,
            "frequency": action_group["count"],
            "sources": action_group["sources"],
            "source_count": action_group["source_count"],
            "score": action_group["count"],
            "skill_worthy": False,  # single actions are KB entries
        })

    candidates.sort(key=lambda c: c["score"], reverse=True)

    # Remove members field from action groups (too verbose for JSON)
    for group in frequent_actions:
        group.pop("members", None)

    return {
        "metadata": {
            "target": target or "all",
            "min_frequency": min_frequency,
            "files_scanned": {
                "handoff": len(handoff_files),
                "attempts": len(attempt_files),
                "total": len(all_files),
            },
            "actions_extracted": len(all_actions),
            "sequences_extracted": len(all_sequences),
        },
        "candidates": candidates,
        "frequent_actions": frequent_actions[:20],  # top 20
        "frequent_sequences": frequent_sequences[:10],  # top 10
        "summary": {
            "total_candidates": len(candidates),
            "skill_worthy": sum(1 for c in candidates if c["skill_worthy"]),
            "kb_entries": sum(1 for c in candidates if not c["skill_worthy"]),
            "by_type": _count_by_key(candidates, "pattern_type"),
        },
    }


def _count_by_key(items: list[dict], key: str) -> dict[str, int]:
    """Count items grouped by a key."""
    counts: dict[str, int] = defaultdict(int)
    for item in items:
        counts[item.get(key, "unknown")] += 1
    return dict(counts)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze session artifacts for recurring action patterns.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
    %(prog)s                          # analyze all targets, min frequency 3
    %(prog)s --min-frequency 2        # lower threshold
    %(prog)s --target gitlab          # scope to one target
    %(prog)s --output patterns.json   # write to specific file
""",
    )
    parser.add_argument(
        "--min-frequency",
        type=int,
        default=3,
        help="Minimum occurrences to consider a pattern (default: 3)",
    )
    parser.add_argument(
        "--target",
        type=str,
        default=None,
        help="Scope analysis to a specific target name",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path (default: stdout)",
    )

    args = parser.parse_args()

    results = analyze(
        target=args.target,
        min_frequency=args.min_frequency,
    )

    output = json.dumps(results, indent=2, ensure_ascii=False)

    if args.output:
        outpath = Path(args.output)
        outpath.parent.mkdir(parents=True, exist_ok=True)
        outpath.write_text(output + "\n", encoding="utf-8")
        print(f"Results written to {outpath}", file=sys.stderr)
    else:
        print(output)

    # Print summary to stderr for quick review
    meta = results["metadata"]
    summary = results["summary"]
    print(
        f"\n--- Summary ---\n"
        f"Files scanned: {meta['files_scanned']['total']} "
        f"({meta['files_scanned']['handoff']} HANDOFF, "
        f"{meta['files_scanned']['attempts']} Attempts)\n"
        f"Actions extracted: {meta['actions_extracted']}\n"
        f"Sequences extracted: {meta['sequences_extracted']}\n"
        f"Candidate patterns: {summary['total_candidates']}\n"
        f"  Skill-worthy (5+ steps): {summary['skill_worthy']}\n"
        f"  KB entries (simpler): {summary['kb_entries']}\n"
        f"  By type: {summary['by_type']}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
