"""Discrimination tests for automation/check_poc_controls.sh (synthetic corpus; independent of any real workshop).

Why a real file cannot be the control:
    A positive control of the form "<a real PoC> must be flagged" disappears by itself the day that file gets
    its control group added — a control that points at a file that will eventually be fixed is no control at
    all. The real corpus then reads as "all files have a control", the gate prints its own "degenerate ratio"
    warning, and nothing can answer "is the corpus clean, or is the matcher broken?". A synthetic fixture is
    the stable answer: it always contains one file that definitely has no control.

This test answers that question, so the gate's ratio warning points here.
"""
import os
import subprocess
from pathlib import Path

import pytest

GATE = Path(__file__).resolve().parents[1] / "automation" / "check_poc_controls.sh"

# Verdict marker + no validity marker  -> MUST be flagged.
# ⚠️ This text itself must not contain ANY word the gate treats as a validity marker (see CONTROL_RE in the
#    script): if a fixture comment uses one, the fixture makes the test green by itself. Test data stepping on
#    the criterion under test is an easy false-green to miss.
UNCONTROLLED = """#!/bin/bash
# direct measurement, prints a verdict marker
run_probe() { :; }
if run_probe; then echo "  ✅ pass"; else echo "  🔴 fail"; fi
"""

# Verdict marker + a control group -> must NOT be flagged.
CONTROLLED = """#!/bin/bash
# run the control group first: one case known to hold + one case known not to
prime() { :; }
prime || exit 1
if run_probe; then echo "  ✅ pass"; else echo "  🔴 fail"; fi
"""

# Verdict marker + explicit escape hatch -> must NOT be flagged (but must be counted as exempt).
EXEMPTED = """#!/bin/bash
# no-control-needed: pure inventory, makes no judgement
echo "  ✅ inventory written"
"""

# No verdict at all -> must not even be counted.
SILENT = """#!/bin/bash
find . -name '*.c' | sort
"""

# PASS/FAIL appear only inside identifiers -> not a verdict, must NOT be flagged
# (PASSWORD is not PASS, DECRYPTION_FAILED is not FAIL).
WORD_BOUNDARY = """#!/usr/bin/env python3
PASSWORD = "hunter2"
sentinel = b"DECRYPTION_FAILED"
print(PASSWORD, sentinel)
"""

# Past-tense forms are verdicts too -> MUST be flagged. (DECRYPTION_FAILED stays an identifier, see above.)
PAST_TENSE_VERDICT = """#!/bin/bash
probe_target
echo FAILED
"""

# Words that merely SOUND like a validity marker must not count as one -> still MUST be flagged.
LOOSE_WORDS_ONLY = """#!/bin/bash
# talks to the Oracle database, mentions invalidity, uses a sanity word in a name: none of this is a control
probe_target
echo PASS
"""

# A verdict word at the very END of a line (and at the very START of one) is still a verdict -> MUST be flagged.
# This is the commonest shell shape; a matcher that needs a non-letter on both sides of the word misses it.
LINE_EDGE_VERDICT = """#!/bin/bash
probe_target
echo PASS
"""


@pytest.fixture
def ws(tmp_path):
    d = tmp_path / "synth"
    (d / "poc").mkdir(parents=True)
    # ⚠️ File names must not be substrings of each other: with `uncontrolled.sh` and `controlled.sh`, an
    #    assertion "must not flag controlled.sh" is wrongly violated by the line naming uncontrolled.sh.
    #    Same shape as PASS ⊂ PASSWORD.
    for name, body in (("bare_probe.sh", UNCONTROLLED),
                       ("calibrated_probe.sh", CONTROLLED),
                       ("exempted.sh", EXEMPTED),
                       ("silent.sh", SILENT),
                       ("edge_verdict.sh", LINE_EDGE_VERDICT),
                       ("past_tense.sh", PAST_TENSE_VERDICT),
                       ("loose_words.sh", LOOSE_WORDS_ONLY),
                       ("wordboundary.py", WORD_BOUNDARY)):
        (d / "poc" / name).write_text(body, encoding="utf-8")
    return tmp_path


def run(ws_root, *args):
    env = dict(os.environ, WORKSHOP_ROOT=str(ws_root))
    return subprocess.run(["bash", str(GATE), *args], capture_output=True, text=True, env=env)


def test_flags_the_uncontrolled_file(ws):
    r = run(ws, "synth")
    assert "bare_probe.sh" in r.stdout
    assert r.returncode != 0, "an uncontrolled measuring file must fail (the gate is not advisory)"


@pytest.mark.parametrize("name", ["past_tense.sh", "loose_words.sh"])
def test_flags_past_tense_verdicts_and_loose_validity_words(ws, name):
    r = run(ws, "synth")
    flagged = [l for l in r.stdout.splitlines() if l.strip().startswith("- ")]
    assert any(name in l for l in flagged), f"expected {name} to be flagged\n{r.stdout}"


def test_flags_a_verdict_word_at_the_edge_of_a_line(ws):
    """`echo PASS` has no character after PASS; the matcher must still see it as a verdict."""
    r = run(ws, "synth")
    assert "edge_verdict.sh" in r.stdout, r.stdout


@pytest.mark.parametrize("name", ["calibrated_probe.sh", "exempted.sh", "silent.sh", "wordboundary.py"])
def test_does_not_flag_these(ws, name):
    r = run(ws, "synth")
    flagged = [l for l in r.stdout.splitlines() if l.strip().startswith("- ")]
    assert not any(name in l for l in flagged), f"false positive: {name}\n{r.stdout}"


def test_passes_when_every_measurement_is_controlled(ws):
    """Remove the uncontrolled file and it must PASS — otherwise the gate is 'always red', and always red
    carries no more signal than always green."""
    for uncontrolled in ("bare_probe.sh", "edge_verdict.sh", "past_tense.sh", "loose_words.sh"):
        (ws / "synth" / "poc" / uncontrolled).unlink()
    r = run(ws, "synth")
    assert r.returncode == 0, r.stdout


def test_exempt_is_counted_separately_not_silently_dropped(ws):
    """The escape hatch must be auditable: the number of exemptions is printed, never silently dropped."""
    r = run(ws, "synth")
    assert "plus 1 explicitly exempt" in r.stdout, r.stdout


def test_discrimination_is_not_degenerate(ws):
    """One corpus containing both a caught file and an uncaught file is what 'has discrimination' means.
    A green run on a real workshop only means the corpus is clean; only this synthetic test can say the
    matcher is alive."""
    r = run(ws, "synth")
    assert "measuring file" in r.stdout
    assert "bare_probe.sh" in r.stdout            # catches it
    assert "calibrated_probe.sh" not in r.stdout  # does not over-catch
