#!/usr/bin/env python3
"""Verify this architecture-only public skeleton contains no operational data."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

required_files = [
    "README.md",
    "LICENSE",
    ".gitignore",
    "AGENTS.md",
    "CLAUDE.md",
    "CODEX.md",
    "GEMINI.md",
    "AGENTS_QUICK.md",
    ".obsidian/app.json",
    ".obsidian/appearance.json",
    ".obsidian/community-plugins.json",
    ".obsidian/core-plugins.json",
    ".obsidian/graph.json",
    ".obsidian/plugins/README.md",
    ".obsidian/templates.json",
    "agents/README.md",
    "agents/authorized-security-researcher.md",
    "agents/recon-analyst.md",
    "agents/triage-reviewer.md",
    "bbflow/README.md",
    "bbflow/flow.md",
    "bbflow/knowledge-capture-hook.md",
    "bbflow/output-contract.md",
    "bbflow/scope.example.yaml",
    "bbflow/safety-boundary.md",
    "bbflow/configs/README.md",
    "bbflow/configs/nuclei.profile.example.yaml",
    "bbflow/configs/osmedeus.profile.example.yaml",
    "bbflow/configs/bbot.profile.example.yaml",
    "docs/architecture.md",
    "docs/adoption-model.md",
    "docs/prompting-model.md",
    "docs/workflow.md",
    "docs/sop.md",
    "docs/llm-wiki-framework.md",
    "docs/obsidian-setup.md",
    "docs/public-safety.md",
    "docs/session-lifecycle.md",
    "docs/fresh-start.md",
    "hooks/README.md",
    "hooks/preflight-scope-guard.md",
    "hooks/post-run-knowledge-capture.md",
    "hooks/pre-public-sync.md",
    "templates/target.md",
    "templates/recon-note.md",
    "templates/finding.md",
    "templates/review-note.md",
    "templates/submission.md",
    "templates/form.md",
    "templates/handoff.md",
    "templates/operation-log.md",
    "templates/scope.yaml",
    "prompts/README.md",
    "prompts/authorized-security-researcher.md",
    "prompts/recon-analyst.md",
    "prompts/triage-reviewer.md",
    "prompts/report-writer.md",
    "prompts/knowledge-curator.md",
    "prompts/vault-maintainer.md",
    "prompts/automation-runner.md",
    "prompts/workflow-coach.md",
    "scripts/bootstrap_private_vault.py",
    "scripts/check_vault.py",
    "scripts/end_session.py",
    "scripts/new_note.py",
    "scripts/start_session.py",
    "scripts/validate_scope_file.py",
    "skills/README.md",
    "skills/authorized-workflow/SKILL.md",
    "skills/knowledge-capture/SKILL.md",
    "workspace/README.md",
    "workspace/.gitignore",
    "workspace/workshop/.gitkeep",
    "workspace/tools/.gitkeep",
    "workspace/reports/.gitkeep",
    "workspace/logs/.gitkeep",
]

forbidden_dirs = [
    "targets",
    ".workspace",
    ".vault-workspace",
    "reports",
    "scan_results",
    "poc",
    "evidence",
    "rootfs",
    "firmware_analysis",
    "extractions",
    "logs",
    "memory",
    "graphify-out",
]

forbidden_strings = [
    "BEGIN PRIVATE KEY",
    "PRIVATE KEY-----",
    "api_key",
    "access_token",
    "sessionid",
    "HITCON",
    "TWCERT",
    "Bugcrowd",
    "HackerOne",
    "Intigriti",
    "YesWeHack",
    "ZeroDay",
    "No target data",
]

forbidden_patterns = [
    re.compile(r"/Users/[^/\s]+"),
    re.compile(r"(?i)cookie\s*:"),
    re.compile(r"(?i)authorization\s*:"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]+"),
]

allowed_workspace_files = {
    "workspace/README.md",
    "workspace/.gitignore",
    "workspace/workshop/.gitkeep",
    "workspace/tools/.gitkeep",
    "workspace/reports/.gitkeep",
    "workspace/logs/.gitkeep",
}


def iter_public_files():
    ignored = {".git", ".pytest_cache", "__pycache__", "tests"}
    for path in ROOT.rglob("*"):
        if path == Path(__file__).resolve():
            continue
        if path.is_file() and not ignored.intersection(path.parts):
            yield path


def fail(message: str) -> None:
    print(f"[fail] {message}", file=sys.stderr)
    raise SystemExit(1)


def verify_workspace_scaffold() -> None:
    workspace_root = ROOT / "workspace"
    if not workspace_root.exists():
        return

    for path in workspace_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel not in allowed_workspace_files:
            fail(f"forbidden workspace runtime file: {rel}")


def main() -> int:
    for rel in required_files:
        if not (ROOT / rel).exists():
            fail(f"missing required file: {rel}")

    for rel in forbidden_dirs:
        if (ROOT / rel).exists():
            fail(f"forbidden operational directory present: {rel}")

    verify_workspace_scaffold()

    for path in iter_public_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for needle in forbidden_strings:
            if needle != "No target data" and needle in text:
                fail(f"forbidden string in {path.relative_to(ROOT)}: {needle}")
        for pattern in forbidden_patterns:
            if pattern.search(text):
                fail(f"forbidden private pattern in {path.relative_to(ROOT)}: {pattern.pattern}")

    print("[ok] architecture-only public skeleton verified")
    print("[ok] No target data or operational artifact directories found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
