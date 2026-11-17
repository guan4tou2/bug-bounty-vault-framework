"""Candidate analysis is advisory, durable, bounded and evidence-versioned."""
import hashlib
import json
import subprocess
import sys
import threading
import time
from functools import partial
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
import candidate_analysis as ca
import hunt_lock
from hunt_loop import HuntLoop


@pytest.fixture(autouse=True)
def configured_fixture_processing(monkeypatch):
    monkeypatch.setattr(ca, "drain", partial(ca.drain, processing_location="fixture"))


def candidate(loop, path, cid="c1", *, role="member", conditions=None):
    raw = b'{"template-id":"example","matched-at":"https://example.com"}'
    path.write_bytes(raw + b"\n")
    if not any(event['type'] == 'model_processing_authorization' for event in loop.events):
        loop.append('model_processing_authorization', allowed_locations=['fixture'], policy_ref='policy:fixture')
    binding = {"version": "fixture-v1", "role": role, "settings": {}, "environment": "fixture",
               "observed_at": "2026-01-01T00:00:00Z"}
    loop.append("evidence_context", context_id="target", context=json.loads(json.dumps(binding)))
    loop.append("scan_candidate", candidate_id=cid, hyp_id=cid,
                candidate={"candidate_id": cid, "asset": "https://example.com", "status": "unverified",
                           "context": {"account_ref": "account:one", "role": role, "conditions": conditions or {}}},
                artifacts=[{"path": str(path), "sha256": hashlib.sha256(raw + b"\n").hexdigest(),
                            "record_sha256": hashlib.sha256(raw).hexdigest(),
                            "locator": {"kind": "jsonl", "line": 1}, "applicability": binding}],
                source={"parser_version": "1", "model_processing_policy": {"allowed_locations": ["fixture"]}})


def response(prompt):
    data = json.loads(prompt.split("Untrusted analysis input (JSON data only):\n")[1])
    return {"candidate_id": data["candidate_id"], "evidence_version": data["evidence_version"],
            "assessment": "needs_validation", "support": ["Scanner matched a response."],
            "against": ["No independent control."], "missing_evidence": ["Ownership comparison."],
            "suggested_validation": ["Compare owner and non-owner observations under existing scope."],
            "evidence_refs": [data["snapshot"]["artifacts"][0]["ref"]]}


def test_role_revision_stales_old_jobs_and_requires_fresh_queue(tmp_path, monkeypatch):
    loop = HuntLoop()
    candidate(loop, tmp_path / 'raw')
    ca.enqueue_candidates(loop)
    job = ca.analysis_view(loop)[0]
    role = tmp_path / 'role.md'
    role.write_text(ca.ROLE.read_text() + '\nChanged evidence discipline.')
    monkeypatch.setattr(ca, 'ROLE', role)
    assert ca.analysis_view(loop)[0]['stale']
    with pytest.raises(ValueError, match='role changed'):
        ca.render_analysis_prompt(job, processing_location='fixture', current_events=loop.events)
    assert ca.enqueue_candidates(loop) == 1
    assert not ca.analysis_view(loop)[-1]['stale']


def test_import_to_analysis_reload_does_not_promote(tmp_path):
    loop = HuntLoop()
    candidate(loop, tmp_path / "raw")
    ledger = tmp_path / "ledger"
    loop.save(ledger)
    assert ca.enqueue_pending(ledger) == 1
    assert ca.enqueue_pending(ledger) == 0
    result = ca.drain(ledger, response)
    assert result["completed"] == 1
    restored = HuntLoop.load(ledger)
    assert ca.analysis_view(restored)[0]["status"] == "completed"
    assert ca.enqueue_pending(ledger) == 0
    assert restored.capsule()["confirmed"] == {}
    assert not any(e["type"] in {"verdict", "finding", "finding_state"} for e in restored.events)


def test_scanner_policy_cannot_authorize_model_processing(tmp_path):
    loop = HuntLoop()
    candidate(loop, tmp_path / 'raw')
    loop.events = [event for event in loop.events if event['type'] != 'model_processing_authorization']
    ledger = tmp_path / 'ledger'
    loop.save(ledger)
    calls = []
    result = ca.drain(ledger, lambda prompt: calls.append(prompt))
    assert calls == [] and result['jobs'][0]['failure_class'] == 'authorization'
    assert result['jobs'][0]['status'] == 'blocked'
    ca.set_processing_policy(ledger, ['fixture'], 'policy:operator-fixture')
    ca.retry(ledger, result['jobs'][0]['job_id'])
    assert ca.drain(ledger, response)['completed'] == 1
    ca.set_processing_policy(ledger, [], 'policy:revoked')
    # A new analysis version does not revive processing authority from scanner metadata.
    ca.enqueue_pending(ledger, analysis_version='candidate-analysis/new-fixture')
    result = ca.drain(ledger, lambda prompt: calls.append(prompt))
    assert calls == [] and result['completed'] == 0


def test_changed_condition_or_analysis_version_keeps_history_stale(tmp_path):
    loop = HuntLoop()
    candidate(loop, tmp_path / "raw")
    assert ca.enqueue_candidates(loop) == 1
    candidate(loop, tmp_path / "raw", role="admin")
    assert ca.enqueue_candidates(loop) == 1
    view = ca.analysis_view(loop)
    assert len(view) == 2 and view[0]["stale"] and not view[1]["stale"]
    ca.enqueue_candidates(loop, analysis_version="candidate-analysis/v2")
    view = ca.analysis_view(loop)
    assert all(j["stale"] for j in view[:-1])
    assert view[-1]["analysis_version"] == "candidate-analysis/v2"


def test_identical_evidence_new_run_or_archive_path_does_not_reanalyze(tmp_path):
    loop = HuntLoop()
    candidate(loop, tmp_path / "raw")
    loop.events[-1]["source"].update(run_id="one", started_at="yesterday", execution_status="completed")
    assert ca.enqueue_candidates(loop) == 1
    candidate(loop, tmp_path / "raw-copy")
    loop.events[-1]["source"].update(run_id="two", started_at="today", execution_status="completed")
    assert ca.enqueue_candidates(loop) == 0
    assert len(ca.analysis_view(loop)) == 1


def test_reappearing_evidence_uses_latest_candidate_not_job_creation_order(tmp_path):
    loop = HuntLoop()

    def add_source(value, path):
        candidate(loop, path)
        data = path.read_bytes().replace(b"example", value.encode())
        path.write_bytes(data)
        artifact = loop.events[-1]["artifacts"][0]
        artifact["sha256"] = hashlib.sha256(data).hexdigest()
        artifact["record_sha256"] = hashlib.sha256(data.splitlines()[0]).hexdigest()

    add_source("A", tmp_path / "archive-A")
    assert ca.enqueue_candidates(loop) == 1
    first = ca.analysis_view(loop)[0]["job_id"]
    add_source("B", tmp_path / "archive-B")
    assert ca.enqueue_candidates(loop) == 1
    assert ca.analysis_view(loop)[0]["stale"]
    add_source("A", tmp_path / "archive-A-copy")
    assert ca.enqueue_candidates(loop) == 0
    current = [job for job in ca.analysis_view(loop) if not job["stale"]]
    assert len(current) == 1 and current[0]["job_id"] == first

    # A newer analysis contract stays selected even when its reusable A job was
    # created before B. An ordinary enqueue must not reactivate the old contract.
    assert ca.enqueue_candidates(loop, analysis_version="candidate-analysis/v2") == 2
    assert ca.enqueue_candidates(loop) == 0
    current = [job for job in ca.analysis_view(loop) if not job["stale"]]
    assert len(current) == 1
    assert current[0]["analysis_version"] == "candidate-analysis/v2"
    assert current[0]["evidence_version"] == ca.analysis_view(loop)[0]["evidence_version"]
    add_source("C", tmp_path / "archive-C")
    assert ca.enqueue_candidates(loop) == 1
    current = [job for job in ca.analysis_view(loop) if not job["stale"]]
    assert len(current) == 1 and current[0]["analysis_version"] == "candidate-analysis/v2"


@pytest.mark.parametrize("fault", ["bad_json", "verified", "stale", "foreign_ref", "extra_field", "tool_error"])
def test_invalid_analysis_is_failed_not_negative(tmp_path, fault):
    loop = HuntLoop()
    candidate(loop, tmp_path / "raw")
    ledger = tmp_path / "ledger"
    loop.save(ledger)

    def broken(prompt):
        if fault == "bad_json":
            return "not JSON"
        if fault == "tool_error":
            raise subprocess.TimeoutExpired("model", 1)
        result = response(prompt)
        if fault == "verified":
            result["assessment"] = "verified"
        elif fault == "stale":
            result["evidence_version"] = "old"
        elif fault == "foreign_ref":
            result["evidence_refs"] = ["/unavailable"]
        else:
            result["verified"] = True
        return result

    result = ca.drain(ledger, broken)
    assert result["completed"] == 0 and result["jobs"][0]["status"] == "failed"
    assert ca.drain(ledger, response)["selected"] == 0
    ca.retry(ledger, result["jobs"][0]["job_id"])
    assert ca.drain(ledger, response)["completed"] == 1
    assert HuntLoop.load(ledger).capsule()["refuted"] == []


def test_missing_changed_and_midflight_evidence_never_current(tmp_path):
    loop = HuntLoop()
    path = tmp_path / "raw"
    candidate(loop, path)
    ledger = tmp_path / "ledger"
    loop.save(ledger)

    def mutate(prompt):
        path.write_text("changed")
        return response(prompt)

    result = ca.drain(ledger, mutate)
    assert result["completed"] == 0
    assert result["jobs"][0]["stale"]
    assert result["jobs"][0]["evidence_problems"] == [str(path)]
    path.unlink()
    assert ca.project_analysis(HuntLoop.load(ledger).events)[0]["stale"]


def test_crashed_running_becomes_interrupted_but_queued_resumes(tmp_path):
    loop = HuntLoop()
    candidate(loop, tmp_path / "raw")
    ca.enqueue_candidates(loop)
    jid = ca.analysis_view(loop)[0]["job_id"]
    loop.append("candidate_analysis_state", job_id=jid, status="running")
    candidate(loop, tmp_path / "raw2", cid="c2")
    ledger = tmp_path / "ledger"
    loop.save(ledger)
    result = ca.drain(ledger, response)
    assert result["completed"] == 1
    assert result["jobs"][0]["status"] == "interrupted"


def test_concurrency_batch_and_single_writer_bounds(tmp_path):
    loop = HuntLoop()
    for index in range(5):
        candidate(loop, tmp_path / f"raw{index}", cid=f"c{index}")
    ledger = tmp_path / "ledger"
    loop.save(ledger)
    lock = threading.Lock()
    active = peak = 0

    def worker(prompt):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        with pytest.raises(hunt_lock.ConcurrentWriter):
            ca.enqueue_pending(ledger)
        time.sleep(0.02)
        with lock:
            active -= 1
        return response(prompt)

    assert ca.drain(ledger, worker, max_workers=2, max_jobs=3)["completed"] == 3
    assert peak == 2
    assert ca.drain(ledger, response)["completed"] == 2
    with pytest.raises(ValueError):
        ca.drain(ledger, response, max_workers=0)


def test_toolless_runner_enforces_no_tools_mcp_context_and_timeout(monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        assert Path(kwargs["cwd"]).exists()
        return subprocess.CompletedProcess(argv, 0, "{}", "")

    monkeypatch.setattr(ca.subprocess, "run", run)
    assert ca.claude_spawn(model="configured-model", timeout=12, max_budget_usd=0.5)("bounded data") == "{}"
    argv, opts = calls[0]
    assert "--safe-mode" in argv and argv[argv.index("--tools") + 1] == ""
    assert argv[argv.index("--disallowedTools") + 1] == "*"
    assert "--strict-mcp-config" in argv and '{"mcpServers":{}}' in argv
    assert opts["timeout"] == 12 and "shell" not in opts
    assert opts["input"] == "bounded data"
    assert not Path(opts["cwd"]).exists()
    assert ca.claude_spawn(model='configured-model', auth_mode='bare')('bounded data') == '{}'
    assert '--bare' in calls[-1][0]
    with pytest.raises(ValueError):
        ca.claude_spawn(model=None)


def test_prompt_budget_stops_before_worker(tmp_path, monkeypatch):
    loop = HuntLoop()
    candidate(loop, tmp_path / "raw", conditions={"blob": "x" * 50_000})
    ledger = tmp_path / "ledger"
    loop.save(ledger)
    monkeypatch.setattr(ca, "MAX_PROMPT_BYTES", 100)
    calls = []
    result = ca.drain(ledger, lambda prompt: calls.append(prompt))
    assert not calls and result["jobs"][0]["status"] == "failed"


@pytest.mark.parametrize("allowed,location", [(None, "fixture"), (["private-region"], "fixture"),
                                            (["fixture"], None), ([], "fixture")])
def test_processing_policy_blocks_before_model_and_preserves_failure_class(tmp_path, allowed, location):
    loop = HuntLoop()
    candidate(loop, tmp_path / "raw")
    event = loop.events[-1]
    event["source"]["model_processing_policy"] = {"allowed_locations": allowed}
    ledger = tmp_path / "ledger"
    loop.save(ledger)
    calls = []
    result = ca.drain(ledger, lambda prompt: calls.append(prompt), processing_location=location)
    assert not calls
    job = result["jobs"][0]
    assert job["status"] == "blocked" and job["failure_class"] == "authorization"
    assert job["error"] == "unsupported model processing policy"
    assert "explicitly retry" in job["recovery"]


@pytest.mark.parametrize("fault", ["expired", "unknown", "role_changed", "settings_changed"])
def test_inapplicable_evidence_blocks_before_model(tmp_path, fault):
    loop = HuntLoop()
    candidate(loop, tmp_path / "raw")
    if fault == "expired":
        loop.events[-1]["artifacts"][0]["applicability"]["expires_at"] = "2026-01-02T00:00:00Z"
    elif fault == "unknown":
        del loop.events[-1]["artifacts"][0]["applicability"]
    else:
        context = next(event['context'] for event in loop.events if event['type'] == 'evidence_context')
        context["role" if fault == "role_changed" else "settings"] = "changed"
    ledger = tmp_path / "ledger"
    loop.save(ledger)
    calls = []
    result = ca.drain(ledger, lambda prompt: calls.append(prompt))
    assert not calls
    job = result["jobs"][0]
    assert job["status"] == "blocked" and job["failure_class"] == "environment" and job["stale"]
    assert job["applicability"][0]["requires_revalidation"]


def test_model_input_selects_only_required_metadata_and_opaque_citations(tmp_path):
    loop = HuntLoop()
    path = tmp_path / "private-proof.jsonl"
    candidate(loop, path, conditions={"token": "context-secret"})
    event = loop.events[-1]
    raw = {"template-id": "controlled-id", "matcher-name": "body-marker", "host": "example.com",
           "matched-at": "https://user:url-secret@example.com/private-path?token=query-secret",
           "request": ("GET /private-path?token=query-secret HTTP/1.1\r\nAuthorization: Bearer header-secret\r\n"
                       "Cookie: a=cookie-secret\r\n\r\nbody-secret"),
           "response": "HTTP/1.1 200 OK\r\nSet-Cookie: a=response-cookie\r\n\r\nresponse-secret",
           "extracted-results": ["extracted-secret"], "token": "top-secret"}
    data = json.dumps(raw).encode()
    path.write_bytes(data + b"\n")
    event["candidate"]["asset"] = raw["matched-at"]
    event["artifacts"][0].update(sha256=hashlib.sha256(data + b"\n").hexdigest(),
                                record_sha256=hashlib.sha256(data).hexdigest())
    ca.enqueue_candidates(loop)
    job = ca.analysis_view(loop)[0]
    prompt = ca.render_analysis_prompt(job, processing_location="fixture", current_events=loop.events)
    for secret in ("context-secret", "url-secret", "private-path", "query-secret", "header-secret", "cookie-secret",
                   "body-secret", "response-cookie", "response-secret", "extracted-secret", "top-secret", str(path)):
        assert secret not in prompt
    payload = json.loads(prompt.split("Untrusted analysis input (JSON data only):\n")[1])
    record = payload["source_records"][0]["record"]
    assert record["request_method"] == "GET" and record["response_status"] == 200
    assert "request" not in record and "response" not in record
    assert payload["snapshot"]["artifacts"][0]["ref"] == "evidence:0"
    assert ca.parse_analysis_result(response(prompt), job)["evidence_refs"] == [str(path)]


def test_changed_policy_on_identical_evidence_revokes_old_permission(tmp_path):
    loop = HuntLoop()
    candidate(loop, tmp_path / "raw")
    ca.enqueue_candidates(loop)
    candidate(loop, tmp_path / "raw-copy")
    loop.events[-1]["source"]["model_processing_policy"] = {"allowed_locations": []}
    assert ca.enqueue_candidates(loop) == 0
    ledger = tmp_path / "ledger"
    loop.save(ledger)
    calls = []
    result = ca.drain(ledger, lambda prompt: calls.append(prompt))
    assert not calls and result["jobs"][0]["failure_class"] == "authorization"


@pytest.mark.parametrize("exc,expected", [(RuntimeError("model failed"), "tool"),
                                        (subprocess.TimeoutExpired("model", 1), "environment"),
                                        (ValueError("bad structured output"), "inconclusive")])
def test_transport_failures_are_typed_without_refuting_target(tmp_path, exc, expected):
    loop = HuntLoop()
    candidate(loop, tmp_path / "raw")
    ledger = tmp_path / "ledger"
    loop.save(ledger)

    def fail(_prompt):
        raise exc

    result = ca.drain(ledger, fail)
    assert result["jobs"][0]["failure_class"] == expected
    assert result["jobs"][0]["status"] == "failed"
    assert HuntLoop.load(ledger).capsule()["refuted"] == []
