"""Offline, versioned Nmap XML / Nuclei JSONL ingestion; never executes tools.

Only explicit run metadata and actor references are accepted. Raw bytes are kept
in a content-addressed private evidence directory; scanner matches remain leads.
See docs/scan-import.md for the format research receipt and limitations.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import asg
from evidence_applicability import binding_from_scan
from hunt_lock import acquire, guarded_save, release
from hunt_loop import HuntLoop

PARSER_VERSION = "1"
FORMATS = ("nmap-xml", "nuclei-jsonl")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     allow_nan=False).encode()).hexdigest()


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _invalid_constant(_value):
    raise ValueError("invalid JSON constant")


def _nuclei(raw):
    records, errors = [], []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line.decode("utf-8"), parse_constant=_invalid_constant)
            if not isinstance(row, dict):
                raise ValueError("record must be an object")
            asset = row.get("matched-at") or row.get("host")
            if not _text(row.get("template-id")) or not _text(asset):
                raise ValueError("template-id and matched-at/host are required")
            if "matcher-status" in row and not isinstance(row["matcher-status"], bool):
                raise ValueError("matcher-status must be boolean")
            if row.get("error"):
                raise ValueError("scanner reported a record error")
            info = row.get("info") or {}
            if not isinstance(info, dict):
                raise ValueError("info must be an object")
            for key in ("matcher-name", "extractor-name", "type"):
                if key in row and not isinstance(row[key], str):
                    raise ValueError(f"{key} must be a string")
            if "severity" in info and not isinstance(info["severity"], str):
                raise ValueError("severity must be a string")
            records.append({"asset": asset, "candidate_type": "template-match",
                            "template_id": row["template-id"],
                            "matcher_name": row.get("matcher-name"),
                            "extractor_name": row.get("extractor-name"),
                            "protocol": row.get("type"),
                            "reported_severity": info.get("severity"),
                            "matched": row.get("matcher-status", True),
                            "locator": {"kind": "jsonl", "line": number},
                            "record_sha256": hashlib.sha256(line).hexdigest()})
        except (ValueError, UnicodeDecodeError) as exc:
            # Never copy malformed/raw response data into error summaries.
            errors.append({"locator": {"kind": "jsonl", "line": number},
                           "error": str(exc) if not isinstance(exc, json.JSONDecodeError)
                           else "invalid JSON"})
    return records, errors, {}


def _nmap(raw):
    # Nmap commonly writes an external nmap.dtd declaration. ElementTree does not
    # fetch it. Internal entities are unnecessary here and explicitly rejected.
    if re.search(br"<!ENTITY|<!DOCTYPE[^>]*\[", raw, re.I):
        raise ValueError("XML entities/internal DTD subsets are unsupported")
    root = ET.fromstring(raw)
    if root.tag != "nmaprun":
        raise ValueError("expected nmaprun root")
    records, errors = [], []
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        errors.append({"locator": {"kind": "xpath", "path": "./runstats/finished"},
                       "error": "scan completion is missing or not successful"})
    for hindex, host in enumerate(root.findall("host"), 1):
        if host.find("status") is None or host.find("status").get("state") != "up":
            continue
        address = next((a.get("addr") for a in host.findall("address")
                        if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not address:
            errors.append({"locator": {"kind": "xpath", "path": f"./host[{hindex}]"},
                           "error": "up host lacks an IP address"})
            continue
        try:
            ipaddress.ip_address(address)
        except ValueError:
            errors.append({"locator": {"kind": "xpath", "path": f"./host[{hindex}]/address"},
                           "error": "invalid IP address"})
            continue
        records.append({"asset": address, "observation_type": "host-up",
                        "locator": {"kind": "xpath", "path": f"./host[{hindex}]/status"}})
        for pindex, port in enumerate(host.findall("ports/port"), 1):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            locator = {"kind": "xpath", "path": f"./host[{hindex}]/ports/port[{pindex}]"}
            pid, protocol = port.get("portid", ""), port.get("protocol", "")
            if not pid.isdigit() or not 0 < int(pid) < 65536 or protocol not in ("tcp", "udp", "sctp"):
                errors.append({"locator": locator, "error": "invalid open port identity"})
                continue
            service = port.find("service")
            records.append({"asset": address, "observation_type": "open-service",
                            "port": int(pid), "protocol": protocol,
                            "service": dict(service.attrib) if service is not None else {},
                            "locator": locator})
    return records, errors, {"reported_tool_version": root.get("version")}


def parse_scan(raw, format):
    """Return records + errors; partial output is explicit, never a clean zero."""
    if format not in FORMATS:
        raise ValueError("unsupported format")
    try:
        records, errors, metadata = _nmap(raw) if format == "nmap-xml" else _nuclei(raw)
    except (ET.ParseError, ValueError, UnicodeDecodeError) as exc:
        return {"status": "failed", "records": [], "errors": [{"error": type(exc).__name__}],
                "metadata": {}}
    status = "partial" if errors and records else "failed" if errors else "success" if records else "empty"
    return {"status": status, "records": records, "errors": errors, "metadata": metadata}


def _metadata(manifest, context):
    for key in ("run_id", "scope_ref", "tool_version", "started_at", "execution_status"):
        if not _text(manifest.get(key)):
            raise ValueError(f"manifest requires {key}")
    if manifest["execution_status"] not in ("completed", "failed", "timed_out", "cancelled", "interrupted"):
        raise ValueError("unsupported execution_status")
    for key in ("account_ref", "role", "conditions"):
        if key not in context:
            raise ValueError(f"context requires {key}; use explicit unknown/anonymous references")
    if not _text(context["account_ref"]) or not _text(context["role"]) or not isinstance(context["conditions"], dict):
        raise ValueError("context requires account_ref, role and conditions mapping")
    # Context is references/conditions, never raw authentication material.
    if re.search(r'"(?:password|passwd|secret|token|cookie|authorization|credential)"\s*:',
                 json.dumps(context), re.I):
        raise ValueError("context must use controlled references, not credentials")
    return json.loads(json.dumps(manifest, allow_nan=False)), json.loads(json.dumps(context, allow_nan=False))


def _archive(raw, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / hashlib.sha256(raw).hexdigest()
    fd, temporary = tempfile.mkstemp(prefix=".scan-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Publish only complete bytes, without overwriting existing evidence.
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != raw:
                raise ValueError("archived evidence hash mismatch") from None
    finally:
        os.unlink(temporary)
    return path.resolve()


def import_scan(target, source, format, manifest, context, evidence_dir=None):
    """Import into the canonical ASG ledger under its existing single-writer lock.

    Repeating the identical run/source/context is a no-op. Same run and context
    with changed bytes is rejected; a new execution must have a new run_id.
    """
    manifest, context = _metadata(manifest, context)
    source = Path(source).resolve()
    raw = source.read_bytes()
    parsed = parse_scan(raw, format)
    if manifest["execution_status"] != "completed":
        parsed["errors"].append({"error": "execution did not complete successfully"})
        parsed["status"] = "partial" if parsed["records"] else "failed"
    ledger = asg.ledger_path(target)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    token = acquire(ledger, "scan-import")
    try:
        loop = HuntLoop.load(ledger)
        if not any(e.get("type") == "genesis" for e in loop.events):
            raise ValueError("target requires an existing genesis")
        target_identity = asg.target_dir(target).name
        identity = digest([target_identity, manifest["run_id"], format, context])
        content = hashlib.sha256(raw).hexdigest()
        fingerprint = digest([content, manifest, PARSER_VERSION])
        prior = next((e for e in loop.events if e.get("type") == "scan_import"
                      and e.get("import_id") == identity), None)
        if prior:
            if prior["fingerprint"] != fingerprint:
                raise ValueError("run identity has changed evidence or metadata; use a new run_id")
            if not evidence_valid(prior["artifacts"][0]):
                raise ValueError("archived evidence is missing or changed")
            return {**prior, "imported": 0, "duplicate": True}
        archived = _archive(raw, evidence_dir or source.parent / ".scan-evidence")
        artifact = {"path": str(archived), "sha256": content,
                    "applicability": binding_from_scan(manifest, context)}
        provenance = {**manifest, "parser": format, "parser_version": PARSER_VERSION}
        receipt = {"import_id": identity, "fingerprint": fingerprint,
                   "source_path": str(source), "source": provenance, "context": context,
                   "status": parsed["status"], "errors": parsed["errors"],
                   "metadata": parsed["metadata"], "artifacts": [artifact],
                   "record_count": len(parsed["records"])}
        loop.append("scan_import", **receipt)
        surfaces = {e.get("name") for e in loop.events if e.get("type") == "surface"}
        hypotheses = {e.get("id") for e in loop.events if e.get("type") == "hypothesis"}
        for record in parsed["records"]:
            proof = {**artifact, "locator": record["locator"]}
            if "record_sha256" in record:
                proof["record_sha256"] = record["record_sha256"]
            logical = {key: record.get(key) for key in
                       ("asset", "template_id", "matcher_name", "extractor_name", "protocol",
                        "observation_type", "port")}
            cid = "scan:" + digest([target_identity, format, context, logical])[:32]
            candidate = {k: v for k, v in record.items() if k not in ("locator", "record_sha256")}
            candidate.update(candidate_id=cid, context=context, status="unverified")
            kind = "scan_candidate" if format == "nuclei-jsonl" and record["matched"] else "scan_observation"
            loop.append(kind, candidate_id=cid, hyp_id=cid, candidate=candidate,
                        source=provenance, import_id=identity, artifacts=[proof])
            if kind == "scan_candidate" and cid not in hypotheses:
                loop.add_hypothesis(cid)
                hypotheses.add(cid)
            surface = record["asset"]
            if record.get("observation_type") == "open-service":
                host = f"[{record['asset']}]" if ":" in record["asset"] else record["asset"]
                surface = f"{record['protocol']}://{host}:{record['port']}"
            if surface not in surfaces:
                loop.append("surface", name=surface, untested=True, source="scan-import:" + identity,
                            observation_ref=cid, context=context, auto=True)
                surfaces.add(surface)
        from candidate_analysis import enqueue_candidates
        queued = enqueue_candidates(loop)
        guarded_save(loop, ledger, token)
        return {**receipt, "imported": len(parsed["records"]), "queued": queued, "duplicate": False}
    finally:
        release(ledger, token)


def evidence_valid(artifact):
    """Resolve exact JSONL line or XML node against the pinned immutable bytes."""
    try:
        raw = Path(artifact["path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
            return False
        locator = artifact.get("locator")
        if not locator:
            return True
        if locator["kind"] == "jsonl":
            line = raw.splitlines()[locator["line"] - 1]
            return locator["line"] >= 1 and hashlib.sha256(line).hexdigest() == artifact["record_sha256"]
        if locator["kind"] == "xpath":
            return ET.fromstring(raw).find(locator["path"]) is not None
        return False
    except (OSError, KeyError, IndexError, TypeError, ET.ParseError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("format", choices=FORMATS)
    parser.add_argument("source", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    result = import_scan(args.target, args.source, args.format,
                         json.loads(args.manifest.read_text()), json.loads(args.context.read_text()),
                         args.evidence_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["status"] in ("partial", "failed") else 0


if __name__ == "__main__":
    raise SystemExit(main())
