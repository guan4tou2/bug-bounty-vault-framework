"""cleanup_ledger_gate.sh: the status parse must work with BSD sed (macOS) and GNU sed.

The original used `\\s` in sed, which BSD sed does not understand, so the 'open' status
was silently never detected on macOS. These tests run the real script against a
synthetic engagement target.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

GATE = Path(__file__).resolve().parents[1] / "automation" / "cleanup_ledger_gate.sh"


@pytest.fixture
def root(tmp_path):
    (tmp_path / "automation").mkdir()
    shutil.copy(GATE, tmp_path / "automation" / GATE.name)
    state = tmp_path / "01 - Targets" / "demo" / ".state"
    state.mkdir(parents=True)
    (state / "asg-events.jsonl").write_text(
        json.dumps({"type": "genesis", "profile": "engagement"}) + "\n", encoding="utf-8")
    return tmp_path


def run(root):
    tdir = root / "01 - Targets" / "demo"
    return subprocess.run(["bash", str(root / "automation" / GATE.name)],
                          capture_output=True, text=True, cwd=tdir)


def write_ledger(root, body):
    (root / "01 - Targets" / "demo" / "Cleanup Ledger - demo.md").write_text(body, encoding="utf-8")


def test_warns_when_no_ledger(root):
    assert "NO cleanup ledger" in run(root).stderr


@pytest.mark.parametrize("line", [
    "status: open",
    "status:   open   # allowed: open | closed",
    'status: "open"',
    "  status: open",
])
def test_warns_when_status_open(root, line):
    write_ledger(root, f"---\ntype: cleanup_ledger\n{line}\n---\n")
    assert "still 'open'" in run(root).stderr, line


def test_silent_when_closed(root):
    write_ledger(root, "---\nstatus: closed\n---\n")
    assert run(root).stderr.strip() == ""


def test_prose_status_does_not_shadow_frontmatter(root):
    """A later prose line containing 'status:' must not be read instead of the field."""
    write_ledger(root, "---\nstatus: closed\n---\nnote: the old status: open entry was removed\n")
    assert run(root).stderr.strip() == ""


def test_non_engagement_target_is_ignored(root):
    ev = root / "01 - Targets" / "demo" / ".state" / "asg-events.jsonl"
    ev.write_text(json.dumps({"type": "genesis", "profile": "web"}) + "\n", encoding="utf-8")
    assert run(root).stderr.strip() == ""
