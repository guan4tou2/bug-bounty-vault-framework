"""Local process lifecycle primitives; no authorization or new execution entry point.

Command arguments are deliberately omitted from ordinary telemetry. Keep replay inputs
in an access-controlled artifact and supply its reference to the caller instead.
"""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path


def timestamp():
    return datetime.now(UTC).isoformat()


def command_summary(argv):
    # Arbitrary scripts, URLs, positional values and SSH command strings can all
    # contain credentials. A blacklist cannot safely distinguish them from flags.
    return [Path(argv[0]).name, *(["<arguments redacted>"] if len(argv) > 1 else [])]


def pid_alive(pid):
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def owner_gone(event):
    # Never infer death for another machine, legacy records, or a possibly reused
    # PID. A live/reused PID is conservatively left for explicit reconciliation.
    return event.get("owner_host") == socket.gethostname() and pid_alive(event.get("owner_pid")) is False


def reconciled_actions(events):
    """Acknowledgement requires pinned evidence of stop and side-effect review."""
    from evidence_refs import artifact_hash
    resolved = set()
    for event in events:
        if event.get("type") != "action_reconciled":
            continue
        if event.get("effect_status") not in {"not-executed", "effects-checked"}:
            continue
        proof = event.get("artifact", {})
        try:
            if event.get("execution_stopped") is True and artifact_hash(proof["path"]) == proof["sha256"]:
                resolved.add(event["action_id"])
        except (OSError, KeyError, TypeError):
            continue
    return resolved


def unresolved_actions(events, hyp_id=None):
    starts = {e["action_id"]: e for e in events if e.get("type") == "action_started"}
    finished = {e["action_id"]: e for e in events if e.get("type") == "action_finished"}
    resolved = reconciled_actions(events)
    return [aid for aid, start in starts.items() if (hyp_id is None or start.get("hyp_id") == hyp_id)
            and aid not in resolved and (aid not in finished or
                finished[aid].get("execution_stop_confirmed") is False)]


def group_alive(pid):
    if os.name != "posix":
        return False
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # inaccessible is not proof of stop


def drain_output(process, stream):
    """Capture pipe bytes in the controller; children never inherit the evidence FD.

    EOF confirms all inherited pipe writers closed. Bound each drain so a noisy
    producer cannot starve the execution deadline or cancellation callback.
    """
    for _ in range(16):
        try:
            data = os.read(process.stdout.fileno(), 65536)
        except BlockingIOError:
            stream.flush()
            return False
        if not data:
            stream.flush()
            return True
        stream.write(data)
    stream.flush()
    return False


def stop_process(process, grace=0.3):
    """Stop this newly created process session and reap its direct child.

    This cannot prove that an SSH remote job or a daemon that detached into a new
    session has stopped. Callers must retain that distinction in their terminal event.
    """
    if os.name == "posix":
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGTERM)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=grace)
        # Kill remaining children even if their group leader already exited.
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGKILL)
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            return False  # failed signalling must not turn a timeout into an unbounded wait
        deadline = time.monotonic() + grace
        while group_alive(process.pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        return not group_alive(process.pid)
    process.terminate()
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    return process.returncode is not None
