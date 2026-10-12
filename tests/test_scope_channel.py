"""Tests for automation/check_scope_channel.py using a synthetic workshop + targets directory.

Each design rule gets a test:
  * a canonical Target page that already records a platform/channel is NOT a gap (do not judge a stale copy)
  * planned / closed / parked targets are exempt; recon / hunting are not
  * a target present only in the workshop is reported but does not fail the check
  * the canonical SCOPE.md wins over the workshop copy
  * a BLANK scope file laid out exactly like the one `init_target.sh` writes IS a gap (values must not be read
    across a newline: an empty `- Platform:` followed by `- Program URL:` is empty, not "- Program URL:")
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "automation" / "check_scope_channel.py"

# Same field order as the scope file written by automation/init_target.sh (extra fields FOLLOW the two we check).
BLANK_SCOPE = "# Scope\n\n## Platform\n\n- Platform:\n- Program URL:\n- Bounty range:\n"
FILLED_SCOPE = ("# Scope\n\n## Platform\n\n- Platform: platform-a\n"
                "- Program URL: https://example.test/program\n- Bounty range:\n")
HALF_FILLED_SCOPE = "# Scope\n\n## Platform\n\n- Platform: platform-a\n- Program URL:\n- Bounty range:\n"


def _target_page(status: str, extra: str = "") -> str:
    return '---\ntype: target\nstatus: "%s"\n%s---\n# t\n' % (status, extra)


def _build(tmp_path: Path):
    ws, canon = tmp_path / "workshop", tmp_path / "targets"

    def add_ws(name, scope):
        (ws / name).mkdir(parents=True)
        (ws / name / "SCOPE.md").write_text(scope, encoding="utf-8")

    def add_canon(name, status, extra=""):
        (canon / name).mkdir(parents=True)
        (canon / name / ("Target - %s.md" % name)).write_text(_target_page(status, extra), encoding="utf-8")

    add_ws("gap_hunting", BLANK_SCOPE);        add_canon("gap_hunting", "hunting")
    add_ws("gap_half_filled", HALF_FILLED_SCOPE); add_canon("gap_half_filled", "recon")
    add_ws("covered_by_page", BLANK_SCOPE);    add_canon("covered_by_page", "hunting", 'platform: "platform-a"\n')
    add_ws("covered_by_channel", BLANK_SCOPE); add_canon("covered_by_channel", "recon", 'channel: "vendor-direct"\n')
    add_ws("filled_scope", FILLED_SCOPE);      add_canon("filled_scope", "hunting")
    add_ws("parked_gap", BLANK_SCOPE);         add_canon("parked_gap", "parked")
    add_ws("closed_gap", BLANK_SCOPE);         add_canon("closed_gap", "closed")
    add_ws("workshop_only", BLANK_SCOPE)       # no canonical Target page
    return ws, canon


def _run(ws, canon, *args):
    env = dict(os.environ, WORKSHOP_ROOT=str(ws), TARGETS_DIR=str(canon))
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env)


def test_only_real_gaps_fail(tmp_path):
    ws, canon = _build(tmp_path)
    r = _run(ws, canon, "--json")
    rows = json.loads(r.stdout)
    real = sorted(x["target"] for x in rows if not x["workspace_only"])
    assert real == ["gap_half_filled", "gap_hunting"], rows
    assert r.returncode == 1


def test_blank_template_layout_is_a_gap_not_read_across_newlines(tmp_path):
    """Regression: `- Platform:` (empty) + next line `- Program URL:` must not read as Platform='- Program URL:'."""
    ws, canon = _build(tmp_path)
    rows = {x["target"]: x for x in json.loads(_run(ws, canon, "--json").stdout)}
    assert rows["gap_hunting"]["platform"] == "" and rows["gap_hunting"]["url"] == ""
    assert rows["gap_half_filled"]["platform"] == "platform-a" and rows["gap_half_filled"]["url"] == ""


def test_workspace_only_target_is_reported_but_does_not_count(tmp_path):
    ws, canon = _build(tmp_path)
    rows = json.loads(_run(ws, canon, "--json").stdout)
    assert [x["target"] for x in rows if x["workspace_only"]] == ["workshop_only"]
    text = _run(ws, canon).stdout
    assert "workshop_only" in text and "2 / " in text.split("\n")[0]


def test_inactive_and_covered_targets_are_not_flagged(tmp_path):
    ws, canon = _build(tmp_path)
    names = {x["target"] for x in json.loads(_run(ws, canon, "--json").stdout)}
    for ok in ("covered_by_page", "covered_by_channel", "filled_scope", "parked_gap", "closed_gap"):
        assert ok not in names, ok


def test_passes_when_no_real_gap_remains(tmp_path):
    ws, canon = _build(tmp_path)
    for name in ("gap_hunting", "gap_half_filled"):
        (canon / name / ("Target - %s.md" % name)).write_text(
            _target_page("hunting", 'platform: "platform-b"\n'), encoding="utf-8")
    r = _run(ws, canon)
    assert r.returncode == 0, r.stdout


def test_canonical_scope_wins_over_workshop_copy(tmp_path):
    ws, canon = _build(tmp_path)
    (canon / "gap_hunting" / "SCOPE.md").write_text(FILLED_SCOPE, encoding="utf-8")
    names = {x["target"] for x in json.loads(_run(ws, canon, "--json").stdout) if not x["workspace_only"]}
    assert "gap_hunting" not in names
