"""Owned loopback UI fixture for a complete sharing/revocation research trace.

This intentionally broken fixture is not a deployable product. All accounts,
documents and content are synthetic. It has no outbound network client.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import flow_model as fm
from hunt_integration import handoff
from hunt_lock import acquire, guarded_save, release
from hunt_loop import HuntLoop
from logic_vuln_loop import Env, Invariant, LogicHypothesis, Observation, record_invariant

ENV = Env("browser-lab-v1", "multi-actor", "loopback")
MARKER = "SYNTHETIC PRIVATE DOCUMENT — owned browser Lab only"
SAFE_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


def definition():
    actors = {name: {"account_ref": "fixture:" + name, "role": name} for name in ("recipient", "owner", "stranger")}
    transitions = []
    for tid, before, after, actor, action in [
        ("create", "absent", "private", "owner", "create"),
        ("share", "private", "shared", "owner", "share"),
        ("read", "shared", "shared", "recipient", "read"),
        ("revoke", "shared", "revoked", "owner", "revoke"),
        ("read-after-revoke", "revoked", "revoked", "stranger", "read"),
    ]:
        transitions.append(
            {
                "id": tid,
                "from": before,
                "to": after,
                "actor": actor,
                "action": action,
                "object": "doc",
                "entry": "ui",
                "identifier_ref": "share-link",
                "preconditions": ["A revoked grant must not authorize a fresh server read."],
                "invariant_refs": ["revocation"],
            }
        )
    return {
        "flow_id": "browser-sharing",
        "title": "Owned UI sharing and revoked-link comparison",
        "environment": asdict(ENV),
        "actors": actors,
        "objects": {
            "doc": {
                "owner": "owner",
                "relationships": {"recipient": "former-grantee", "stranger": "never-granted"},
                "identifiers": {
                    "share-link": {
                        "source": "normal owner share dialog and recipient workflow",
                        "available_to": ["owner", "recipient"],
                        "attacker_availability": "observed",
                    }
                },
            }
        },
        "states": ["absent", "private", "shared", "revoked"],
        "entries": {"ui": {"interface": "browser forms"}},
        "normal_path": [t["id"] for t in transitions],
        "transitions": transitions,
    }


def import_traces(root):
    root = Path(root).resolve()
    ledger = root / "vault/01 - Targets/browser-sharing-lab/.state/asg-events.jsonl"
    token = acquire(ledger, "owned-browser-lab")
    try:
        loop = HuntLoop.load(ledger)
        if not loop.events:
            loop.append("genesis", profile="source-audit", fixture_only=True)
            loop.append(
                "evidence_context",
                context_id="target",
                context={
                    "version": ENV.version,
                    "role": ENV.role,
                    "settings": {"stale_recipient_bug": True},
                    "environment": {"host": ENV.host},
                },
            )
            rule = root / "fixture-policy.txt"
            rule.write_text("After revocation, a fresh read must deny the former recipient and any stranger.")
            record_invariant(
                loop,
                Invariant(
                    "revocation", rule.read_text(), source="code", confidence="stated", evidence_refs=[str(rule)]
                ),
            )
            fm.define_flow(loop, definition())
            fm.generate_cases(loop, "browser-sharing", focus_transition="read-after-revoke")
            loop.add_hypothesis("browser-revoked-link")
        selected = next(e for e in loop.events if e["type"] == "flow_case" and e["case_kind"] == "actor-boundary")
        for path in sorted((root / "traces").glob("*/trace.json")):
            trace = json.loads(path.read_text())
            if any(e["type"] == "flow_trace_finished" and e["trace_id"] == trace["id"] for e in loop.events):
                continue
            fm.start_trace(loop, trace["id"], selected["case_id"], trace["branch"], trace["runner"], ENV)
            existing = next(
                t for t in fm.project(loop.events, loop.base_path)["traces"] if t["trace_id"] == trace["id"]
            )
            for index, event in enumerate(trace["events"]):
                if index < existing["next_step"]:
                    continue
                expected = selected[trace["branch"]][index]
                if expected["action"] != event["action"] or expected["actor"] != event["actor"]:
                    raise ValueError("observed browser path differs from the selected bounded comparison")
                actual = {**expected, "actor": event["actor"]}
                observations = [
                    Observation(
                        event["action"] if phase == "action" else phase,
                        True,
                        event["before"] if phase == "pre" else event["outcome"],
                        event["artifacts"][phase],
                    )
                    for phase in ("pre", "action", "post")
                ]
                fm.record_step(
                    loop,
                    trace["id"],
                    actual,
                    event["before"],
                    event["after"],
                    *observations,
                    observed_at=event["observed_at"],
                )
            if trace["complete"]:
                fm.finish_trace(loop, trace["id"], "completed")
        fm.bind_case(loop, selected["case_id"], "browser-revoked-link", "revocation")
        hyp = LogicHypothesis(
            "browser-revoked-link",
            "state",
            "Revoked access must stop fresh server reads",
            ENV,
            "revoked",
            "stranger denial CONTROL",
            "read",
            "read",
            "read_allowed",
            expected_normal_outcome="blocked",
            invariant_ref="revocation",
        )
        known = {e["trace_id"] for e in loop.events if e["type"] == "flow_trace_finished"}
        if {"source-test", "source-control", "replay-test", "replay-control"} <= known:
            receipt = root / "browser-replay-receipt.json"
            receipt.write_text(
                json.dumps(
                    {
                        "fixture_only": True,
                        "browser_storage": "separate sessions",
                        "observation": (
                            "Fresh no-store server reads reproduced; not independent vulnerability verification."
                        ),
                    }
                )
            )
            fm.record_reproduction(
                loop,
                "source-test",
                "source-control",
                "replay-test",
                "replay-control",
                "replay-browser",
                str(receipt),
                hyp,
                expected_pre_state="revoked",
            )
        guarded_save(loop, ledger, token)
        (root / "handoff.json").write_text(json.dumps(handoff(loop), indent=2))
        (root / "flow-view.md").write_text(fm.markdown(loop.events, loop.base_path))
        return {"ledger": str(ledger), "summary": fm.summary(loop.events, loop.base_path)}
    finally:
        release(ledger, token)


def serve(root, port):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    sessions = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def send(self, body, status=200, cookie=None):
            payload = body.encode()
            self.send_response(status)
            for name, value in [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Cache-Control", "no-store"),
                ("Content-Length", str(len(payload))),
                (
                    "Content-Security-Policy",
                    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
                ),
            ]:
                self.send_header(name, value)
            if cookie:
                self.send_header("Set-Cookie", "fixture=" + cookie + "; HttpOnly; SameSite=Strict; Path=/")
            self.end_headers()
            self.wfile.write(payload)

        def session(self):
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            return sessions.get(cookie.get("fixture").value) if cookie.get("fixture") else None

        def page(self, message="", content=""):
            s = self.session()
            start = (
                '<form method="post" action="/start"><label>Trace ID <input name="trace" required></label>'
                '<label>Branch <select name="branch"><option>test</option><option>control</option></select></label>'
                '<label>Runner <select name="runner"><option value="source-browser">source-browser</option>'
                '<option value="replay-browser">replay-browser</option></select></label>'
                "<button>Start trace</button></form>"
            )
            if s:
                controls = "".join(
                    f'<form method="post" action="/role"><button name="role" value="{r}">Use {r}</button></form>'
                    for r in ("owner", "recipient", "stranger")
                )
                actions = "".join(
                    f'<form method="post" action="/{a}"><button>{label}</button></form>'
                    for a, label in [
                        ("create", "Create document"),
                        ("share", "Share with recipient"),
                        ("revoke", "Revoke share"),
                        ("finish", "Finish trace"),
                    ]
                )
                link = (
                    f'<a href="/document/{s["doc"]}">Open remembered document link</a>'
                    if s["doc"] and s["role"] in {"owner", "recipient"}
                    else ""
                )
                if s["doc"] and s["role"] == "stranger" and s["branch"] == "control":
                    link = f'<a href="/document/{s["doc"]}">Open harness-provided CONTROL link</a>'
                content += f"<p>Trace: {s['id']}; role: {s['role']}; state: {s['state']}</p>{controls}{actions}{link}"
            return (
                '<!doctype html><html lang="en"><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width">'
                "<title>Owned Sharing Lab</title><style>"
                "body{font:17px system-ui;max-width:760px;margin:2rem auto;padding:1rem}"
                "form,label{margin:.7rem 0}button,input,select{font:inherit;padding:.4rem}"
                "a{display:block;margin:1rem 0}</style>"
                f"<h1>Owned Sharing Lab</h1><p>Synthetic loopback fixture. Never a real target.</p>"
                f'<h2>{html.escape(message)}</h2>{content}<hr>{start}<a href="/">Back to workflow</a></html>'
            )

        def record(self, s, action, before, outcome):
            index = len(s["events"])
            directory = root / "traces" / s["id"]
            directory.mkdir(parents=True, exist_ok=True)
            event = {
                "action": action,
                "actor": s["role"],
                "before": before,
                "after": s["state"],
                "outcome": outcome,
                "doc": s["doc"],
                "observed_at": datetime.now(UTC).isoformat(),
                "cache": "no-store; fresh handler execution",
                "sequence": index,
                "identifier_source": "harness CONTROL" if s["role"] == "stranger" else "normal UI share workflow",
                "artifacts": {},
            }
            for phase in ("pre", "action", "post"):
                path = directory / f"{index}-{phase}.json"
                path.write_text(json.dumps({**event, "phase": phase}, indent=2))
                event["artifacts"][phase] = str(path)
            s["events"].append(event)
            (directory / "trace.json").write_text(json.dumps(s, indent=2))

        def do_GET(self):
            path = urlsplit(self.path).path
            s = self.session()
            if path.startswith("/document/") and s and path == "/document/" + str(s["doc"]):
                before = s["state"]
                # Deliberate fixture bug: the former recipient retains a revoked grant.
                allowed = s["role"] == "owner" or (s["role"] == "recipient" and s["state"] in {"shared", "revoked"})
                self.record(s, "read", before, "read_allowed" if allowed else "blocked")
                content = f'<p id="protected-content">{MARKER}</p>' if allowed else ""
                return self.send(
                    self.page("Protected content" if allowed else "Access denied", content), 200 if allowed else 403
                )
            if path != "/":
                return self.send("Not found", 404)
            self.send(self.page("Workflow"))

        def do_POST(self):
            data = parse_qs(self.rfile.read(min(int(self.headers.get("Content-Length", "0")), 4096)).decode())
            path = urlsplit(self.path).path
            s = self.session()
            if path == "/start":
                name = data.get("trace", [""])[0]
                branch, runner = data.get("branch", [""])[0], data.get("runner", [""])[0]
                if (
                    not SAFE_ID.fullmatch(name)
                    or branch not in {"test", "control"}
                    or runner not in {"source-browser", "replay-browser"}
                    or (root / "traces" / name).exists()
                ):
                    return self.send("Invalid or existing trace; choose a fresh trace ID", 400)
                key = uuid.uuid4().hex
                sessions[key] = {
                    "id": name,
                    "branch": branch,
                    "runner": runner,
                    "role": "owner",
                    "state": "absent",
                    "doc": None,
                    "events": [],
                    "complete": False,
                }
                self.send_response(303)
                self.send_header("Set-Cookie", "fixture=" + key + "; HttpOnly; SameSite=Strict; Path=/")
                self.send_header("Location", "/")
                return self.end_headers()
            if not s:
                return self.send("Start a trace first", 400)
            if path == "/role" and data.get("role", [""])[0] in {"owner", "recipient", "stranger"}:
                s["role"] = data["role"][0]
            elif path in {"/create", "/share", "/revoke"} and s["role"] == "owner":
                before = s["state"]
                if path == "/create" and before == "absent":
                    s["doc"], s["state"], outcome = uuid.uuid4().hex, "private", "created"
                elif path == "/share" and before == "private":
                    s["state"], outcome = "shared", "shared"
                elif path == "/revoke" and before == "shared":
                    s["state"], outcome = "revoked", "revoked"
                else:
                    return self.send("Unexpected fixture order", 409)
                self.record(s, path[1:], before, outcome)
            elif path == "/finish" and len(s["events"]) == 5:
                s["complete"] = True
                (root / "traces" / s["id"] / "trace.json").write_text(json.dumps(s, indent=2))
            else:
                return self.send("Operation not allowed", 403)
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    (root / "server.json").write_text(
        json.dumps({"url": f"http://127.0.0.1:{server.server_port}", "fixture_only": True})
    )
    print(f"Owned sharing Lab: http://127.0.0.1:{server.server_port}", flush=True)
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["serve", "import"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    if args.command == "serve":
        serve(args.root, args.port)
    else:
        print(json.dumps(import_traces(args.root), indent=2))


if __name__ == "__main__":
    main()
