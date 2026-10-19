"""Typed evidence and reference resolution; no verdict or severity judgement.

Artifacts bind bytes by SHA-256 when recorded. Observations remain declarations
for independent verification. References must resolve within the supplied ledger,
not merely look like an ID. No target data is modified while resolving evidence.
"""
from pathlib import Path
import hashlib
import json
import re


VAULT_ROOT = Path(__file__).resolve().parents[1]
_PATHISH = re.compile(r"[\\/]|\.(txt|json|jsonl|md|log|har|pcap|png|jpe?g|html?|xml|csv|ya?ml|pdf)$", re.I)


def artifact_path(value, base=None):
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = Path(value).expanduser()
    if candidate.is_absolute():
        return candidate if candidate.is_file() else None
    for root in (base, Path.cwd(), VAULT_ROOT):
        if root is not None and (Path(root) / candidate).is_file():
            return Path(root) / candidate
    return None


def artifact_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_evidence(value, base=None, environment=None, *, events=(), subject=None, provides=()):
    """Adapt historical strings and pin new artifact evidence without inventing env."""
    if isinstance(value, str):
        value = value.strip()
        # A real path with spaces is still an artifact, not an observation.
        if artifact_path(value, base) is not None or _PATHISH.search(value):
            value = {"kind": "artifact", "path": value}
        else:
            # Free text is not a proof declaration. Observations must use the
            # explicit typed form; strings are paths or ledger references.
            value = {"kind": "reference", "id": value}
    if not isinstance(value, dict):
        return value
    result = dict(value)
    if result.get("kind") == "comparison":
        # Preserve both sides of a discriminating test, including negative
        # outcomes. It is evidence only while both original proofs resolve.
        for branch in ("test", "control"):
            result[branch] = normalize_evidence(result.get(branch), base, environment,
                                                events=events, subject=subject, provides=provides)
    if result.get("kind") == "artifact":
        path = artifact_path(result.get("path"), base)
        if path is not None and not result.get("sha256"):
            result["sha256"] = artifact_hash(path)
    if environment is not None:
        result.setdefault("environment", environment)
    if result.get("kind") == "reference" and not result.get("proof_sha256"):
        proof = _resolved_proof(result, base, events, subject=subject, provides=provides)
        if proof is not None:
            result["proof_sha256"] = _fingerprint(proof)
        else:
            result["unresolved_at_recording"] = True
    return result


def finding_records(events):
    """Finding amendments are patches; state and omitted proof fields survive."""
    records = {}
    for event in events:
        kind = event.get("type")
        fid = event.get("finding_id")
        if fid is None or kind not in ("finding", "finding_state", "finding_doc"):
            continue
        record = records.setdefault(str(fid), {"id": str(fid), "status": "hypothesis"})
        if kind == "finding":
            record.update({k: v for k, v in event.items() if k not in ("type", "status", "at")})
        elif kind == "finding_state":
            record["status"] = event.get("to")
        else:
            record.update({k: v for k, v in event.items() if k in ("doc", "poc_ref")})
    return records


def _fingerprint(proof):
    return hashlib.sha256(json.dumps(proof, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def evidence_resolves(value, base=None, events=(), *, subject=None, provides=()):
    """Resolve a proof without granting capabilities or modifying target data."""
    return _resolved_proof(value, base, events, subject=subject, provides=provides) is not None


def _resolved_proof(value, base, events, seen=frozenset(), *, subject=None, provides=()):
    # Legacy path strings remain readable, but new references pin their resolved
    # proof fingerprint at write time so changed bytes cannot silently follow.
    if isinstance(value, str) and not re.search(r"\s", value) and not _PATHISH.search(value):
        value = {"kind": "reference", "id": value.strip()}
    else:
        value = value if isinstance(value, dict) else normalize_evidence(value, base)
    if not isinstance(value, dict):
        return None
    kind = value.get("kind")
    if kind == "artifact":
        try:
            path = artifact_path(value.get("path"), base)
            return value if path and value.get("sha256") == artifact_hash(path) else None
        except OSError:
            return None
    if kind == "observation":
        text = value.get("text")
        return value if isinstance(text, str) and len(text.strip()) >= 3 else None
    if kind == "comparison":
        resolved = {branch: _resolved_proof(value.get(branch), base, events, seen,
                                           subject=subject, provides=provides)
                    for branch in ("test", "control")}
        return {**value, **resolved} if all(v is not None for v in resolved.values()) else None
    if kind != "reference" or value.get("unresolved_at_recording"):
        return None
    ref = value.get("id")
    if not isinstance(ref, str) or not ref or ref in seen:
        return None
    seen = seen | {ref}
    proof = None
    if ref.startswith("migration:"):
        # A receipt is bound to the exact imported hypothesis and capability set.
        # Historical unbound aliases are unresolved, never a reusable exemption.
        if subject is None or value.get("subject") != subject:
            return None
        for event in reversed(events):
            if (event.get("type") == "migration" and event.get("source") == "yaml"
                    and event.get("digest") == ref.removeprefix("migration:")):
                allowed = (event.get("claims") or {}).get(subject)
                if isinstance(allowed, list) and set(provides) <= set(allowed):
                    proof = {"kind": "migration", "id": ref, "subject": subject, "provides": allowed}
                break
    elif ref.startswith("migrated:"):
        return None
    else:
        for event in reversed(events):
            if event.get("type") == "evidence" and event.get("id") == ref:
                proof = _resolved_proof(event.get("evidence"), base, events, seen,
                                        subject=subject, provides=provides)
                break
        else:
            finding = finding_records(events).get(ref, {})
            if finding.get("status") != "withdrawn":
                proof = _resolved_proof(finding.get("evidence") or finding.get("poc_ref"),
                                        base, events, seen, subject=subject, provides=provides)
    pinned = value.get("proof_sha256")
    if proof is not None and (not pinned or pinned == _fingerprint(proof)):
        return proof
    return None
