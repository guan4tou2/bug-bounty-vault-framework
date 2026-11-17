"""Read-only ASG capability dependencies as a validated STIX 2.1 Attack Flow bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from evidence_refs import finding_records
from hunt_loop import HuntLoop

SCHEMAS = Path(__file__).resolve().parent / "schemas/attack-flow"
EXTENSION = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"


def validate_bundle(bundle):
    """Pinned official schemas, offline registry, and local reference integrity."""
    from jsonschema import FormatChecker
    from jsonschema.validators import validator_for
    from referencing import Registry, Resource
    from referencing.exceptions import NoSuchResource
    from referencing.jsonschema import DRAFT202012

    def unavailable(uri):
        raise NoSuchResource(ref=uri)

    registry = Registry(retrieve=unavailable)
    manifest = json.loads((SCHEMAS / "SOURCES.json").read_text())
    for source in manifest["artifacts"]:
        if hashlib.sha256((SCHEMAS / source["path"]).read_bytes()).hexdigest() != source["sha256"]:
            raise ValueError("vendored extension artifact changed")
    for source in manifest["schemas"]:
        raw = (SCHEMAS / source["path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != source["sha256"]:
            raise ValueError("vendored schema changed")
        schema = json.loads(raw)
        resource = Resource.from_contents(schema, default_specification=DRAFT202012)
        for uri in {source["uri"], source.get("id")} - {None}:
            registry = registry.with_resource(uri, resource).with_resource(uri.replace("http:", "https:"), resource)
    # The pinned upstream bundle dispatcher omits extension-definition and its
    # custom-object core/SCO oneOf rejects the official Attack Flow extension.
    # Keep the official envelope constraints, dispatch EVERY object explicitly
    # to its official schema instead of that incomplete generic dispatcher.
    envelope = json.loads((SCHEMAS / "stix/common/bundle.json").read_text())
    envelope["properties"]["objects"].pop("items")
    validations = [(envelope, bundle)]
    for obj in bundle.get("objects", []):
        kind = obj.get("type", "")
        if kind in {"attack-flow", "attack-action", "attack-condition", "attack-operator"}:
            filename = "attack/attack-flow-schema-2.0.0.json"
        elif kind == "extension-definition":
            filename = "stix/common/extension-definition.json"
        elif kind == "identity":
            filename = "stix/sdos/identity.json"
        else:
            raise ValueError(f"unsupported STIX object: {kind}")
        validations.append((json.loads((SCHEMAS / filename).read_text()), obj))
    for schema, instance in validations:
        validator = validator_for(schema)(schema, registry=registry, format_checker=FormatChecker())
        errors = list(validator.iter_errors(instance))
        if errors:
            raise ValueError(f"official schema rejected export: {errors[0].message}")
    objects = bundle["objects"]
    ids = {obj["id"] for obj in objects}
    if len(ids) != len(objects) or sum(obj["type"] == "attack-flow" for obj in objects) != 1:
        raise ValueError("unique IDs and exactly one attack-flow required")
    for obj in objects:
        references = [obj["created_by_ref"]] if "created_by_ref" in obj else []
        for key in ("start_refs", "effect_refs", "on_true_refs", "on_false_refs"):
            references += obj.get(key, [])
        if any(ref not in ids for ref in references):
            raise ValueError("export has dangling references")
    return True


def export(loop, target, *, include_pending=False):
    cap = loop.capsule()
    hypotheses, declared, proofs = {}, {}, {}
    for event in loop.events:
        if event["type"] == "hypothesis":
            hypotheses[event["id"]] = event.get("requires", [])
        elif event["type"] == "verdict":
            declared[event["hypothesis"]] = event.get("provides", [])
            proofs[event["hypothesis"]] = event.get("evidence")
    selected = set(hypotheses) if include_pending else set(cap["confirmed"])
    selected -= set(cap["withdrawn_hypotheses"])
    if not selected:
        raise ValueError("no supported subjects to export; use --include-pending for an explicitly labelled plan")
    timestamp = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    official = json.loads((SCHEMAS / "attack/attack-flow-extension-2.0.0.json").read_text())["objects"]
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--" + str(uuid.uuid4()),
        "created": timestamp,
        "modified": timestamp,
        "name": "Vault research export",
        "identity_class": "system",
    }
    objects = [*official, identity]

    def new(kind, **fields):
        obj = {
            "type": kind,
            "spec_version": "2.1",
            "id": kind + "--" + str(uuid.uuid4()),
            "created": timestamp,
            "modified": timestamp,
            "created_by_ref": identity["id"],
            "extensions": {EXTENSION: {"extension_type": "new-sdo"}},
            **fields,
        }
        objects.append(obj)
        return obj

    findings = finding_records(loop.events)
    actions, provides = {}, {}
    for hid in sorted(selected):
        status = (
            "confirmed"
            if hid in cap["confirmed"]
            else "refuted"
            if hid in cap["refuted"]
            else "disputed"
            if hid in cap["disputed"]
            else "invalidated"
            if hid in cap["invalidated_hypotheses"]
            else "blocked"
            if hid in cap["blocked_hypotheses"]
            else "hypothesis"
        )
        provides[hid] = (
            set(cap["confirmed"].get(hid, [])) & set(cap["capabilities"])
            if status == "confirmed"
            else set(declared.get(hid, []))
            if include_pending
            else set()
        )
        actions[hid] = new(
            "attack-action",
            name=hid,
            confidence=50 if status == "confirmed" else 0,
            description=f"ASG research state: {status}; not a new verification or severity decision.",
            external_references=[{"source_name": "Vault ASG", "external_id": f"{target}/{hid}"}],
            x_vault_state=status,
            x_vault_proof_descriptor_sha256=hashlib.sha256(
                json.dumps(proofs.get(hid), sort_keys=True).encode()
            ).hexdigest(),
            x_vault_evidence_mode=cap["confidence"].get(hid, "unverified"),
            x_vault_finding_status=findings.get(hid.removeprefix("finding:"), {}).get("status", "not-established"),
        )
    conditions = {}
    for capability in sorted({r for hid in selected for r in hypotheses.get(hid, [])}):
        conditions[capability] = new(
            "attack-condition",
            description=f"Required capability {capability}; currently "
            + ("available" if capability in cap["capabilities"] else "unverified/unavailable"),
            x_vault_capability=capability,
            x_vault_available=capability in cap["capabilities"],
        )
        for hid in selected:
            if capability in provides[hid]:
                actions[hid].setdefault("effect_refs", []).append(conditions[capability]["id"])
    for hid in selected:
        requirements = hypotheses.get(hid, [])
        destination = actions[hid]["id"]
        if len(requirements) > 1:
            destination = new("attack-operator", operator="AND", effect_refs=[destination])["id"]
        for capability in requirements:
            conditions[capability].setdefault("on_true_refs", []).append(destination)
    starts = [actions[hid]["id"] for hid in sorted(selected) if not hypotheses.get(hid)]
    starts += [
        condition["id"]
        for capability, condition in conditions.items()
        if not any(capability in provides[hid] for hid in selected)
    ]
    if not starts:
        raise ValueError("dependency graph has no grounded start; select a rooted research subgraph")
    new(
        "attack-flow",
        name=f"Vault research dependencies: {target}",
        description=f"Read-only ASG event cursor {cap['event_cursor']}. Dependencies express requires/provides, "
        "not chronological order. Hypotheses and missing independent verification remain labelled.",
        scope="emulation-plan" if include_pending else "other",
        start_refs=starts,
    )
    bundle = {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objects}
    validate_bundle(bundle)
    return bundle


def main():
    import asg

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--include-pending", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bundle = export(HuntLoop.load(asg.ledger_path(args.target)), args.target, include_pending=args.include_pending)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(bundle, stream, indent=2)
    print(json.dumps({"output": str(args.output), "objects": len(bundle["objects"]), "offline_schema_validated": True}))


if __name__ == "__main__":
    main()
