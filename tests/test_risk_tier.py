"""Tests for risk_tier.py — the single risk classifier."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "automation"))
import risk_tier as rt  # noqa: E402


def test_text_tiers():
    assert rt.classify_text("compare response A vs B") == "reads_only"
    assert rt.classify_text("enumerate all users") == "state_query"
    assert rt.classify_text("create a new account") == "writes_data"
    assert rt.classify_text("fuzz the endpoint") == "service_impact"


def test_explicit_declared_tier_wins():
    assert rt.classify_text("delete the object", explicit="reads_only") == "reads_only"
    assert rt.classify_command("curl -X POST /search", explicit="state_query") == "state_query"


def test_command_method_is_one_signal_not_the_rule():
    assert rt.classify_command("curl https://x/api/users") == "reads_only"
    assert rt.classify_command("curl -X POST https://x/login -d u=a") == "writes_data"
    assert rt.classify_command("curl --data-raw '{}' https://x/api") == "writes_data"
    # a GET that is semantically destructive is NOT reads_only (method-based guessing misses this)
    assert rt.classify_command("curl https://x/jolokia/exec/reboot") == "service_impact"
    assert rt.classify_command("ffuf -w list -u https://x/FUZZ") == "service_impact"


def test_impact_beats_write():
    assert rt.classify_command("curl -X POST https://x/admin/wipe") == "service_impact"


def test_state_changing_verbs_covered():
    assert rt.classify_command("curl https://x/api/account/purge?id=7") == "writes_data"
    assert rt.classify_command("curl -X POST https://x/user/42/suspend") == "writes_data"
    assert rt.classify_command("curl https://x/admin/flush-all-sessions") == "service_impact"


def test_invalid_explicit_ignored():
    assert rt.classify_text("create account", explicit="not_a_tier") == "writes_data"
    assert rt.classify_text("", explicit=None) == "reads_only"
