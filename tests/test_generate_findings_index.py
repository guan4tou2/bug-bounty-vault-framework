"""Tests for automation/generate_findings_index.sh using a synthetic target tree (never touches real targets)."""
import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "automation" / "generate_findings_index.sh"


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _build(tmp_path: Path):
    targets, ws = tmp_path / "targets", tmp_path / "workshop"
    t = targets / "acme"
    _write(t / "Findings" / "Finding - acme - ACM-001.md",
           '---\nfinding_id: "ACM-001"\ntitle: "Reflected XSS in search"\nstatus: verified\nseverity: P3\n'
           'host: app.acme.test\nprovides: ["session_theft"]\nrequires: []\n---\nbody\n')
    # same finding_id in a second file -> must be de-duplicated (first wins), not double-counted
    _write(t / "Findings" / "ACM-001-duplicate.md",
           '---\nfinding_id: "ACM-001"\ntitle: "dup"\nstatus: verified\n---\n')
    _write(t / "Findings" / "_index.md", "---\nfinding_id: X\n---\n")          # underscore files are skipped
    _write(t / "Attempts" / "Attempt - acme - login.md",
           "---\nresult: not_vulnerable\ntitle: Login brute force\n---\n")
    _write(t / "Submissions" / "Submission - acme - ACM-001.md",
           '---\nfinding_id: "ACM-001"\ntitle: "XSS report"\nstatus: submitted\nseverity: P3\n'
           'artifacts:\n  - "/search?q="\n  - "ACM-001"\n---\n')
    _write(t / "Submissions" / "Submission - acme - ACM-002.md",
           '---\nfinding_id: "ACM-002"\ntitle: "No artifacts here"\nstatus: ready\n---\n')
    # copies of documents that were sent out must not be indexed
    _write(t / "Submissions" / "Forms" / "vendor" / "COVER_EMAIL.md", "---\nfinding_id: SENT-1\n---\n")
    _write(t / "Submissions" / "FORM - acme - ACM-001.md", "---\nfileClass: form\nfinding_id: FORM-1\n---\n")
    return targets, ws


def _run(targets: Path, ws: Path, *args):
    env = dict(os.environ, TARGETS_DIR=str(targets), WORKSHOP_ROOT=str(ws))
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env)


def test_generates_both_copies_with_expected_counts(tmp_path):
    targets, ws = _build(tmp_path)
    r = _run(targets, ws, "acme")
    assert r.returncode == 0, r.stdout + r.stderr
    vault_copy = targets / "acme" / "FINDINGS_QUICK_REF.md"
    ws_copy = ws / "acme" / "FINDINGS_QUICK_REF.md"
    assert vault_copy.exists() and ws_copy.exists()
    text = vault_copy.read_text(encoding="utf-8")
    # 1 finding (duplicate id collapsed) + 1 attempt + 2 submissions (Forms/ copy and fileClass: form skipped)
    assert "**Total: 1 Findings | 1 Attempts | 2 Submissions = 4 entries**" in text
    assert "duplicate finding_id ACM-001" in r.stderr
    assert "SENT-1" not in text and "FORM-1" not in text
    assert text == ws_copy.read_text(encoding="utf-8")


def test_known_identifiers_and_missing_artifacts_warning(tmp_path):
    targets, ws = _build(tmp_path)
    _run(targets, ws, "acme")
    text = (targets / "acme" / "FINDINGS_QUICK_REF.md").read_text(encoding="utf-8")
    assert "`/search?q=`" in text
    assert "1 Submission(s) have no `artifacts:` field" in text and "`#ACM-002`" in text


def test_manual_block_survives_regeneration(tmp_path):
    targets, ws = _build(tmp_path)
    _run(targets, ws, "acme")
    ref = targets / "acme" / "FINDINGS_QUICK_REF.md"
    ref.write_text(ref.read_text(encoding="utf-8").replace(
        "---\n\n## Submissions",
        "<!-- MANUAL:BEGIN -->\nKEEP ME: vendor is slow to answer\n<!-- MANUAL:END -->\n---\n\n## Submissions", 1),
        encoding="utf-8")
    r = _run(targets, ws, "acme")
    assert "[manual block preserved]" in r.stdout
    assert "KEEP ME: vendor is slow to answer" in ref.read_text(encoding="utf-8")


def test_unknown_target_exits_2(tmp_path):
    targets, ws = _build(tmp_path)
    r = _run(targets, ws, "does-not-exist")
    assert r.returncode == 2
