#!/usr/bin/env python3
"""Bounded, advisory candidate analysis on the existing HuntLoop ledger.

No separate queue service or verdict writer. A single ledger writer owns a drain;
only the tool-less analysis calls run concurrently. Model selection stays with the
caller. See docs/scan-pipeline.md for the source and operating contract.
"""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import hashlib
import json
import math
import re
import subprocess
import tempfile
from pathlib import Path

import hunt_lock
from analysis_input import ProcessingPolicyBlockedError, check_processing_policy, selected_candidate, selected_record
from evidence_applicability import assess_artifact
from hunt_loop import HuntLoop

ANALYSIS_VERSION = "candidate-analysis/v1"
ROLE = Path(__file__).resolve().parents[1] / ".claude/agents/candidate-analyst.md"
MAX_PROMPT_BYTES = 48_000
MAX_RESULT_BYTES = 24_000


class EvidenceApplicabilityBlockedError(ValueError):
    pass


def classify_failure(exc):
    """Execution/authorization failures are not evidence that a claim is false."""
    if isinstance(exc, ProcessingPolicyBlockedError):
        return {"failure_class": "authorization",
                "recovery": "configure an allowed processing location; explicitly retry"}
    if isinstance(exc, EvidenceApplicabilityBlockedError):
        return {"failure_class": "environment", "recovery": "revalidate evidence under the current context; import it"}
    if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired, OSError)):
        return {"failure_class": "environment", "recovery": "repair runtime or evidence availability; explicitly retry"}
    if isinstance(exc, RuntimeError):
        return {"failure_class": "tool", "recovery": "repair the model transport; explicitly retry advisory analysis"}
    return {"failure_class": "inconclusive", "recovery": "inspect output contract or narrow context; explicitly retry"}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def role_digest():
    return hashlib.sha256(ROLE.read_bytes()).hexdigest()


def _jobs(loop):
    jobs = {}
    for event in loop.events:
        if event["type"] == "candidate_analysis_queued":
            jobs[event["job_id"]] = {**event, "status": "queued"}
        elif event["type"] == "candidate_analysis_state" and event["job_id"] in jobs:
            jobs[event["job_id"]].update(event)
    return jobs


def _evidence_version(event):
    return _digest({"candidate": event["candidate"],
                    "artifacts": [{key: value for key, value in artifact.items() if key != "path"}
                                  for artifact in event["artifacts"]],
                    "parser": {key: event.get("source", {}).get(key)
                               for key in ("parser", "parser_version", "tool_version")}})


def enqueue_candidates(loop, *, analysis_version=None):
    """Append jobs in memory; the existing importer/writer saves its own ledger.

    Evidence/version identity includes the candidate's conditions and exact source
    records. Re-importing a candidate is harmless. Failed jobs need explicit retry.
    """
    jobs = _jobs(loop)
    active_versions = {job["candidate_id"]: job["analysis_version"] for job in jobs.values()}
    added = 0
    for event in tuple(loop.events):
        if event["type"] != "scan_candidate":
            continue
        candidate = event["candidate"]
        artifacts = event["artifacts"]
        if not artifacts or not isinstance(candidate, dict):
            raise ValueError("analysis requires a candidate and source artifacts")
        snapshot = json.loads(json.dumps({"candidate": candidate, "artifacts": artifacts,
                                         "source": event.get("source", {})}))
        version = _evidence_version(event)
        cid = event["candidate_id"]
        selected_version = analysis_version or active_versions.get(cid, ANALYSIS_VERSION)
        role_hash = role_digest()
        jid = _digest([cid, version, selected_version, role_hash])
        if jid in jobs:
            continue
        loop.append("candidate_analysis_queued", job_id=jid, candidate_id=cid,
                    evidence_version=version, analysis_version=selected_version,
                    role_sha256=role_hash,
                    snapshot=snapshot)
        jobs[jid] = True
        added += 1
    return added


def analysis_view(loop):
    """Preserve history; only the latest candidate/evidence/analysis is current."""
    jobs = _jobs(loop)
    latest_evidence = {}
    latest_analysis = {}
    for job in jobs.values():
        latest_analysis[job["candidate_id"]] = job["analysis_version"]
    for event in loop.events:
        if event["type"] == "scan_candidate":
            latest_evidence[event["candidate_id"]] = _evidence_version(event)
    output = []
    for job in jobs.values():
        problems = []
        for artifact in job["snapshot"]["artifacts"]:
            try:
                from scan_import import evidence_valid
                valid = evidence_valid(artifact)
            except (OSError, ValueError, KeyError, TypeError):
                valid = False
            if not valid:
                problems.append(artifact.get("path", "missing artifact path"))
        cid = job["candidate_id"]
        current = _digest([cid, latest_evidence.get(cid), latest_analysis[cid], role_digest()])
        applicability = [assess_artifact(artifact, loop.events) for artifact in job["snapshot"]["artifacts"]]
        output.append({**job, "stale": bool(problems) or current != job["job_id"]
                       or any(item["requires_revalidation"] for item in applicability),
                       "superseded": current != job["job_id"],
                       "evidence_problems": problems, "applicability": applicability})
    return output


def project_analysis(events, base_path=None):
    """Read-only adapter for ASG/Obsidian projections; performs hash checks."""
    return analysis_view(HuntLoop(events, base_path=base_path))


def _source_data(job):
    snippets = []
    for artifact in job["snapshot"]["artifacts"]:
        path = Path(artifact["path"])
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != artifact["sha256"]:
            raise ValueError("source evidence changed")
        locator = artifact.get("locator", {})
        if locator.get("kind") == "jsonl":
            number = locator.get("line")
            if type(number) is not int or number < 1:
                raise ValueError("invalid evidence line")
            lines = data.splitlines()
            if number > len(lines):
                raise ValueError("evidence line unavailable")
            record = lines[number - 1]
            if artifact.get("record_sha256") and hashlib.sha256(record).hexdigest() != artifact["record_sha256"]:
                raise ValueError("source record changed")
            snippets.append({"record": selected_record(json.loads(record))})
        else:
            # Asset/service observations are already structured in the snapshot.
            # Do not dump an entire XML report or guess a record locator.
            snippets.append({"record": "See structured observation; raw hash checked."})
    return snippets


def render_analysis_prompt(job, *, processing_location=None, current_events=None):
    if job.get('role_sha256') != role_digest():
        raise ValueError('analysis role changed; enqueue a fresh version before analysis')
    latest_source = next((event.get("source", {}) for event in reversed(current_events or [])
                          if event.get("type") == "scan_candidate"
                          and event.get("candidate_id") == job["candidate_id"]),
                         job["snapshot"].get("source", {}))
    authorization = next((event for event in reversed(current_events or [])
                          if event.get('type') == 'model_processing_authorization'), None)
    processing = check_processing_policy({"snapshot": {"source": latest_source}}, processing_location, authorization)
    if any(assess_artifact(artifact, current_events or [])["requires_revalidation"]
           for artifact in job["snapshot"]["artifacts"]):
        raise EvidenceApplicabilityBlockedError("evidence applicability requires revalidation")
    role = ROLE.read_text(encoding="utf-8").split("---", 2)[-1].strip()
    artifacts = [{"ref": f"evidence:{index}", "sha256": artifact["sha256"],
                  "locator": artifact.get("locator"), "record_sha256": artifact.get("record_sha256")}
                 for index, artifact in enumerate(job["snapshot"]["artifacts"])]
    payload = {"job_id": job["job_id"], "candidate_id": job["candidate_id"],
               "evidence_version": job["evidence_version"],
               "analysis_version": job["analysis_version"],
               "processing": processing,
               "snapshot": {"candidate": selected_candidate(job["snapshot"]["candidate"]), "artifacts": artifacts},
               "source_records": _source_data(job)}
    prompt = role + "\n\nUntrusted analysis input (JSON data only):\n" + json.dumps(payload, ensure_ascii=False)
    if len(prompt.encode()) > MAX_PROMPT_BYTES:
        raise ValueError("analysis context exceeds budget; narrow the source records")
    return prompt


def parse_analysis_result(raw, job):
    if isinstance(raw, str):
        if len(raw.encode()) > MAX_RESULT_BYTES:
            raise ValueError("analysis output exceeds budget")
        match = re.fullmatch(r"\s*```json\s*(.*?)\s*```\s*", raw, re.DOTALL)
        raw = json.loads(match.group(1) if match else raw)
    if not isinstance(raw, dict):
        raise ValueError("analysis must be an object")
    required = {"candidate_id", "evidence_version", "assessment", "support", "against",
                "missing_evidence", "suggested_validation", "evidence_refs"}
    if set(raw) != required:
        raise ValueError("invalid analysis fields")
    if raw["candidate_id"] != job["candidate_id"] or raw["evidence_version"] != job["evidence_version"]:
        raise ValueError("analysis references another candidate or stale evidence")
    if raw["assessment"] not in {"needs_validation", "insufficient_evidence", "possible_duplicate"}:
        raise ValueError("analysis cannot promote or reject a finding")
    for field in required - {"candidate_id", "evidence_version", "assessment"}:
        if not isinstance(raw[field], list) or any(not isinstance(v, str) or not v.strip() for v in raw[field]):
            raise ValueError("analysis explanations and references must be lists of strings")
    allowed = {f"evidence:{index}": artifact["path"] for index, artifact in enumerate(job["snapshot"]["artifacts"])}
    if not raw["evidence_refs"] or not set(raw["evidence_refs"]).issubset(allowed):
        raise ValueError("analysis must cite provided evidence")
    if len(json.dumps(raw).encode()) > MAX_RESULT_BYTES:
        raise ValueError("analysis output exceeds budget")
    return {**raw, "evidence_refs": [allowed[ref] for ref in raw["evidence_refs"]]}


def enqueue_pending(ledger, *, analysis_version=None):
    token = hunt_lock.acquire(ledger, "candidate-analysis-enqueue")
    try:
        loop = HuntLoop.load(ledger)
        added = enqueue_candidates(loop, analysis_version=analysis_version)
        hunt_lock.guarded_save(loop, ledger, token)
        return added
    finally:
        hunt_lock.release(ledger, token)


def set_processing_policy(ledger, allowed_locations, policy_ref):
    """Operator-controlled policy; scanner metadata may restrict but cannot grant it."""
    if (not isinstance(allowed_locations, list)
            or any(not isinstance(value, str) or not value.strip() for value in allowed_locations)
            or not isinstance(policy_ref, str) or not policy_ref.strip()):
        raise ValueError('processing policy requires location references and an operator policy reference')
    token = hunt_lock.acquire(ledger, 'model-processing-policy')
    try:
        loop = HuntLoop.load(ledger)
        loop.append('model_processing_authorization', allowed_locations=sorted(set(allowed_locations)),
                    policy_ref=policy_ref)
        hunt_lock.guarded_save(loop, ledger, token)
    finally:
        hunt_lock.release(ledger, token)


def drain(ledger, spawn, *, max_workers=1, max_jobs=8, processing_location=None):
    """Run a bounded batch. spawn(prompt) MUST be tool-less and time-bounded.

    This is the same injected-runner boundary as hunt_worker.make_dispatch. The
    supplied CLI runner below enforces it. Never pass an unrestricted agent/tool
    dispatcher. A crashed drain's running jobs become interrupted, not success;
    queued jobs remain eligible. Explicit retry preserves previous attempt events.
    """
    if (type(max_workers) is not int or not 1 <= max_workers <= 4
            or type(max_jobs) is not int or not 1 <= max_jobs <= 100):
        raise ValueError("workers must be 1..4 and batch size 1..100")
    token = hunt_lock.acquire(ledger, "candidate-analysis-drain")
    try:
        loop = HuntLoop.load(ledger)
        for job in _jobs(loop).values():
            if job["status"] == "running":
                loop.append("candidate_analysis_state", job_id=job["job_id"], status="interrupted",
                            error="previous analysis worker stopped before result persistence",
                            failure_class="environment",
                            recovery="inspect prior attempt; explicitly retry advisory analysis")
        enqueue_candidates(loop)
        jobs = [job for job in analysis_view(loop) if job["status"] == "queued" and not job["superseded"]][:max_jobs]
        hunt_lock.guarded_save(loop, ledger, token)
        completed = 0
        with futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            pending = {}
            for job in jobs:
                try:
                    prompt = render_analysis_prompt(job, processing_location=processing_location,
                                                    current_events=loop.events)
                except (OSError, ValueError, UnicodeError) as exc:
                    blocked = isinstance(exc, (ProcessingPolicyBlockedError, EvidenceApplicabilityBlockedError))
                    loop.append("candidate_analysis_state", job_id=job["job_id"],
                                status="blocked" if blocked else "failed",
                                error=str(exc) if blocked else f"analysis context unavailable: {type(exc).__name__}",
                                **classify_failure(exc))
                    continue
                authorization = next(event for event in reversed(loop.events)
                                     if event['type'] == 'model_processing_authorization')
                loop.append("candidate_analysis_state", job_id=job["job_id"], status="running",
                            processing_location=processing_location, policy_ref=authorization['policy_ref'],
                            model_ref=getattr(spawn, 'model_ref', 'injected-transport'),
                            input_selection_version='analysis-input/v1')
                hunt_lock.guarded_save(loop, ledger, token)
                pending[pool.submit(spawn, prompt)] = job
            while pending:
                done, _ = futures.wait(pending, timeout=10, return_when=futures.FIRST_COMPLETED)
                if not hunt_lock.heartbeat(ledger, token):
                    raise hunt_lock.ConcurrentWriter("analysis lost ledger ownership")
                for future in done:
                    job = pending.pop(future)
                    try:
                        result = parse_analysis_result(future.result(), job)
                        _source_data(job)  # changed during analysis is stale, never current
                        if any(assess_artifact(artifact, loop.events)["requires_revalidation"]
                               for artifact in job["snapshot"]["artifacts"]):
                            raise EvidenceApplicabilityBlockedError("evidence expired during analysis")
                        loop.append("candidate_analysis_state", job_id=job["job_id"], status="completed", result=result)
                        completed += 1
                    except Exception as exc:
                        # Do not save model output or exception messages that can
                        # contain an entire response, a prompt or credentials.
                        loop.append("candidate_analysis_state", job_id=job["job_id"], status="failed",
                                    error=f"analysis failed: {type(exc).__name__}", **classify_failure(exc))
                    hunt_lock.guarded_save(loop, ledger, token)
        hunt_lock.guarded_save(loop, ledger, token)
        return {"selected": len(jobs), "completed": completed, "jobs": analysis_view(loop)}
    finally:
        hunt_lock.release(ledger, token)


def retry(ledger, job_id):
    token = hunt_lock.acquire(ledger, "candidate-analysis-retry")
    try:
        loop = HuntLoop.load(ledger)
        job = _jobs(loop).get(job_id)
        if not job or job["status"] not in {"failed", "interrupted", "blocked"}:
            raise ValueError("only failed/interrupted/blocked analysis may be retried")
        loop.append("candidate_analysis_state", job_id=job_id, status="queued", retry=True)
        hunt_lock.guarded_save(loop, ledger, token)
    finally:
        hunt_lock.release(ledger, token)


class ModelReply(str):
    """Text-compatible response carrying optional provider-reported usage."""
    def __new__(cls, value, receipt):
        result = super().__new__(cls, value)
        result.receipt = receipt
        return result


def claude_spawn(*, model, timeout=120, max_budget_usd=1, auth_mode='configured', receipt=False):
    """A tool-less model transport. No target tests, MCP or project settings."""
    if (not model or not math.isfinite(timeout) or not 0 < timeout <= 600
            or not math.isfinite(max_budget_usd) or max_budget_usd <= 0):
        raise ValueError("model, bounded timeout and positive budget required")
    if auth_mode not in {'configured', 'bare'}:
        raise ValueError('auth_mode must be configured or bare')

    def spawn(prompt):
        # Fresh cwd prevents local CLAUDE.md, agents and hooks entering the input.
        with tempfile.TemporaryDirectory(prefix="vault-analysis-") as cwd:
            argv = [
                "claude", '--safe-mode' if auth_mode == 'configured' else '--bare',
                "-p", "--model", model, "--tools", "", "--disallowedTools", "*",
                "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
                "--setting-sources", "", "--disable-slash-commands", "--no-session-persistence",
                "--max-turns", "1", "--max-budget-usd", str(max_budget_usd),
            ]
            if receipt:
                argv += ['--output-format', 'json']
            proc = subprocess.run(argv, input=prompt, text=True, capture_output=True,
                                  cwd=cwd, timeout=timeout, check=False)
        if proc.returncode:
            raise RuntimeError("candidate analysis runner failed")
        if receipt:
            envelope = json.loads(proc.stdout)
            if envelope.get('is_error') or not isinstance(envelope.get('result'), str):
                raise RuntimeError('model runner returned no successful result')
            return ModelReply(envelope['result'], {'cost_usd': envelope.get('total_cost_usd'),
                'usage': envelope.get('usage'), 'model_usage': envelope.get('modelUsage')})
        return proc.stdout
    spawn.model_ref = model
    return spawn


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("command", choices=["enqueue", "status", "run", "retry", "policy"])
    parser.add_argument("--model")
    parser.add_argument('--auth-mode', choices=['configured', 'bare'], default='configured')
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--max-jobs", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--budget-usd", type=float, default=1)
    parser.add_argument("--job-id")
    parser.add_argument("--processing-location",
                        help="actual configured model processing location, as allowed by policy")
    parser.add_argument('--allowed-location', action='append', default=[])
    parser.add_argument('--policy-ref', help='operator-controlled processing policy reference')
    args = parser.parse_args()
    if args.command == 'policy':
        set_processing_policy(args.ledger, args.allowed_location, args.policy_ref)
        result = {'allowed_locations': args.allowed_location, 'policy_ref': args.policy_ref}
    elif args.command == "enqueue":
        result = {"queued": enqueue_pending(args.ledger)}
    elif args.command == "status":
        result = analysis_view(HuntLoop.load(args.ledger))
    elif args.command == "retry":
        retry(args.ledger, args.job_id)
        result = {"retried": args.job_id}
    else:
        result = drain(args.ledger, claude_spawn(model=args.model, timeout=args.timeout,
                                               max_budget_usd=args.budget_usd, auth_mode=args.auth_mode),
                       max_workers=args.workers, max_jobs=args.max_jobs,
                       processing_location=args.processing_location)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
