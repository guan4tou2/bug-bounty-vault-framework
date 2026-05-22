#!/usr/bin/env python3
"""Render a framework note template with generic placeholders."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

TEMPLATES = {
    "target": "templates/target.md",
    "recon-note": "templates/recon-note.md",
    "finding": "templates/finding.md",
    "review-note": "templates/review-note.md",
    "submission": "templates/submission.md",
    "form": "templates/form.md",
    "handoff": "templates/handoff.md",
    "operation-log": "templates/operation-log.md",
    "scope": "templates/scope.yaml",
}


def slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-")
    return cleaned or "untitled"


def default_filename(note_type: str, target: str, topic: str) -> str:
    safe_target = slug(target)
    safe_topic = slug(topic)
    names = {
        "target": f"Target - {safe_target}.md",
        "recon-note": f"Recon - {safe_target} - {safe_topic}.md",
        "finding": f"Finding - {safe_target} - {safe_topic}.md",
        "review-note": f"Review - {safe_target} - {safe_topic}.md",
        "submission": f"Submission - {safe_target} - {safe_topic}.md",
        "form": f"FORM - {safe_target} - {safe_topic}.md",
        "handoff": "HANDOFF.md",
        "operation-log": "OPERATION_LOG.md",
        "scope": f"scope-{safe_target}.yaml",
    }
    return names[note_type]


def render_template(note_type: str, replacements: dict[str, str]) -> str:
    template_path = ROOT / TEMPLATES[note_type]
    text = template_path.read_text(encoding="utf-8")
    for key, value in replacements.items():
        text = text.replace(f"<{key}>", value)
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--type", required=True, choices=sorted(TEMPLATES))
    parser.add_argument("--target", required=True)
    parser.add_argument("--program", default="sample-program")
    parser.add_argument("--topic", default="initial")
    parser.add_argument("--output-dir", help="Optional destination directory. Defaults to stdout.")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)

    today = date.today().isoformat()
    replacements = {
        "target": args.target,
        "program": args.program,
        "topic": args.topic,
        "date": today,
        "YYYY-MM-DD": today,
        "finding_id": f"FINDING-{slug(args.target)}-{slug(args.topic)}",
        "review_id": f"REVIEW-{slug(args.target)}-{slug(args.topic)}",
        "submission_id": f"SUBMISSION-{slug(args.target)}-{slug(args.topic)}",
        "form_id": f"FORM-{slug(args.target)}-{slug(args.topic)}",
        "scope name": f"{args.program}-{args.target}",
        "owner or program": args.program,
        "ignored workspace path": f"workspace/workshop/{slug(args.target)}",
        "private notes path": f"targets/{slug(args.target)}",
        "session_id": f"{slug(args.target)}-{slug(args.topic)}",
        "status": "draft",
        "timestamp": today,
        "scope_file": "bbflow/scope.example.yaml",
        "summary": "session summary placeholder",
        "knowledge_capture": "generic lesson placeholder",
    }
    rendered = render_template(args.type, replacements)

    if not args.output_dir:
        print(rendered)
        return 0

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / default_filename(args.type, args.target, args.topic)

    if output_path.exists() and not args.overwrite:
        print(f"[fail] output exists, pass --overwrite: {output_path}", file=sys.stderr)
        return 1

    output_path.write_text(rendered, encoding="utf-8")
    print(f"[ok] wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
