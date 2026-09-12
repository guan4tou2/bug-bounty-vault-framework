#!/usr/bin/env python3
"""hunt_lock.py — the FINE, mechanical half of ledger single-writer protection.

The collision we actually hit was two SESSIONS writing the same subsystem; the
coarse half of the fix is the existing scope claim (`automation/claim.sh` +
`_lock_lib.sh`), which the live driver must call before it starts. This module is
the belt-and-suspenders: a per-ledger writer token that makes single-writer
MECHANICAL rather than advisory, so two processes cannot both `save()` the same
`.jsonl` and lose each other's appends (last-writer-wins on the atomic replace).

Contract:
  token = acquire(ledger, owner)          # O_EXCL sidecar <ledger>.lock
  guarded_save(loop, ledger, token)       # refuses if we no longer hold it
  heartbeat(ledger, token)                # extend our hold during a long run
  release(ledger, token)                  # free it when done
A holder past its TTL is considered dead and may be taken over (mirroring
claim.sh's eta/force model) — a crashed session never wedges the ledger forever.

Deliberately NOT wired into HuntLoop.save(): the pure library and its tests write
freely without locks. Only the live autonomous driver acquires + guards.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Optional


DEFAULT_TTL_S = 1800  # 30 min; a live run heartbeats to extend, a dead one expires


class ConcurrentWriter(RuntimeError):
    """Raised when a write is attempted without holding the current ledger lock."""


def _lock_path(ledger: str | Path) -> Path:
    return Path(str(ledger) + ".lock")


def _read_holder(ledger: str | Path) -> Optional[dict]:
    p = _lock_path(ledger)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None  # a corrupt lock is treated as absent (takeable)


def _write_holder(ledger: str | Path, record: dict) -> None:
    p = _lock_path(ledger)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = None, None
    import tempfile
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".lock-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(record, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def _expired(holder: dict, now: float) -> bool:
    return (now - holder.get("acquired_at", 0)) > holder.get("ttl_s", DEFAULT_TTL_S)


def acquire(ledger: str | Path, owner: str, *, ttl_s: int = DEFAULT_TTL_S,
            now: Optional[float] = None) -> str:
    """Acquire the ledger. Returns a fresh token. Raises ConcurrentWriter if a
    DIFFERENT owner holds a still-live lock. A holder past its TTL is taken over."""
    now = time.time() if now is None else now
    p = _lock_path(ledger)
    token = uuid.uuid4().hex
    record = {"token": token, "owner": owner, "pid": os.getpid(),
              "acquired_at": now, "ttl_s": ttl_s}

    # fast path: atomically create if absent
    try:
        fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(record, fh)
            fh.flush(); os.fsync(fh.fileno())
        return token
    except FileExistsError:
        pass

    holder = _read_holder(ledger)
    if holder is None or _expired(holder, now):
        # stale / crashed / corrupt -> take over
        _write_holder(ledger, record)
        return token
    raise ConcurrentWriter(
        f"ledger held by {holder.get('owner')!r} (pid {holder.get('pid')}), "
        f"{int(now - holder.get('acquired_at', now))}s ago, ttl {holder.get('ttl_s')}s; "
        f"coordinate or wait for TTL expiry instead of racing the same ledger")


def verify(ledger: str | Path, token: str) -> bool:
    """True iff `token` is the current holder of the ledger lock."""
    holder = _read_holder(ledger)
    return bool(holder and holder.get("token") == token)


def heartbeat(ledger: str | Path, token: str, *, now: Optional[float] = None) -> bool:
    """Extend our hold during a long run. No-op (False) if we no longer hold it."""
    now = time.time() if now is None else now
    holder = _read_holder(ledger)
    if not holder or holder.get("token") != token:
        return False
    holder["acquired_at"] = now
    _write_holder(ledger, holder)
    return True


def release(ledger: str | Path, token: str) -> bool:
    """Free the lock iff we hold it. Returns whether it was released."""
    holder = _read_holder(ledger)
    if holder and holder.get("token") == token:
        try:
            _lock_path(ledger).unlink()
        except OSError:
            return False
        return True
    return False


def guarded_save(loop, ledger: str | Path, token: str) -> None:
    """save() the loop ONLY while we still hold the ledger. If a concurrent writer
    took it over (or the lock vanished), refuse rather than clobber their work."""
    if not verify(ledger, token):
        raise ConcurrentWriter(
            "refusing to save: this session no longer holds the ledger lock "
            "(taken over or released) — reload the ledger and reconcile before writing")
    loop.save(ledger)
