"""Tests for curl_gate.py — the outbound-request risk gate."""
import json
import subprocess
import sys
from pathlib import Path

GATE = Path(__file__).resolve().parent.parent / "automation" / "curl_gate.py"


def _run(cmd: str, env_prefix: str = "") -> int:
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": env_prefix + cmd}})
    p = subprocess.run([sys.executable, str(GATE)], input=payload,
                       capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    _run.last = p.stderr  # type: ignore[attr-defined]
    return p.returncode


def test_reads_allowed():
    assert _run("curl https://other.com/api/users") == 0


def test_writes_warn_but_allow():
    assert _run("curl -X POST https://other.com/x -d a=1") == 0
    assert "writes_data" in _run.last


def test_service_impact_blocked():
    assert _run("curl https://other.com/jolokia/exec/reboot") == 2
    assert "service_impact" in _run.last


def test_risk_skip_override():
    assert _run("curl https://other.com/jolokia/exec/reboot", "BB_SKIP_RISK_GATE=1 ") == 0


def test_declared_tier_override():
    assert _run("curl -X POST https://other.com/search", "BB_RISK=state_query ") == 0
    assert "writes_data" not in _run.last


def test_localhost_exempt():
    assert _run("curl http://localhost:3000 -X DELETE") == 0


def test_non_request_ignored():
    assert _run("grep reboot /var/log/x") == 0
