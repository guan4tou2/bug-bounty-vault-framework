"""A read-only applicability view over evidence already in the ASG ledger."""
from __future__ import annotations

import hashlib
import json

from evidence_applicability import assess_artifact


def project(events, now=None):
    rows = {}

    def visit(proof, owner):
        if not isinstance(proof, dict):
            return
        if proof.get("kind") == "comparison":
            visit(proof.get("test"), owner + ":test")
            visit(proof.get("control"), owner + ":control")
            return
        if proof.get("kind") not in (None, "artifact", "observation"):
            return
        identity = hashlib.sha256(json.dumps([owner, proof], sort_keys=True).encode()).hexdigest()[:24]
        rows[owner] = {"evidence_id": identity, "owner": owner,
                          "path": proof.get("path"), "sha256": proof.get("sha256"),
                          "locator": proof.get("locator"), "bound": "applicability" in proof,
                          **assess_artifact(proof, events, now)}

    # Latest candidate/observation revision, with the complete history still in
    # the ledger and the analysis view. Do not create repair tasks for superseded bytes.
    scans = {}
    for event in events:
        if event.get("type") in {"scan_candidate", "scan_observation"}:
            scans[event["candidate_id"]] = event
        elif event.get("type") in {"verdict", "research_node", "finding", "finding_doc"}:
            owner = str(event.get("hypothesis") or event.get("finding_id") or event.get("id") or "legacy")
            if event.get("evidence") is not None:
                visit(event["evidence"], owner)
    for owner, event in scans.items():
        for artifact in event.get("artifacts", []):
            visit(artifact, owner)
    return list(rows.values())
