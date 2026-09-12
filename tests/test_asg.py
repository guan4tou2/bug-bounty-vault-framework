"""asg.py — the single-authority seam: resolver + append_event + projections.

Proves the dual-ASG convergence primitives:
  * one resolver decides every path, and it uses the CONTRACT filename
    (Attack Surface Graph - <target>.md), never the split `Attack Surface Graph.md`;
  * append_event is the sole writer (lock-guarded, append-only);
  * the Markdown/snapshot are one-way projections that PRESERVE operator content.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
import asg  # noqa: E402
from hunt_loop import HuntLoop  # noqa: E402


def test_resolver_uses_contract_filename_and_state_paths():
    md = asg.markdown_path("ExampleT")
    assert md.name == "Attack Surface Graph - ExampleT.md"      # contract, not "Attack Surface Graph.md"
    assert asg.ledger_path("ExampleT").as_posix().endswith("ExampleT/.state/asg-events.jsonl")
    # a deep path under the target resolves back to the target dir
    deep = asg.target_dir(asg.markdown_path("ExampleT"))
    assert deep.name == "ExampleT"


def test_resolver_rejects_traversal():
    with pytest.raises(ValueError):
        asg.target_dir("/etc/passwd")


def test_append_event_is_sole_writer_and_appends(tmp_path, monkeypatch):
    # redirect the vault root so we write into tmp, not the real vault
    monkeypatch.setattr(asg, "vault_root", lambda: tmp_path)
    asg.append_event("T1", "surface", node_id="ep1", untested=True)
    asg.append_event("T1", "hypothesis", hyp_id="h1", requires=[])
    led = asg.ledger_path("T1")
    assert led.is_file()
    loop = HuntLoop.load(led)
    cap = loop.capsule()
    assert cap["untested_surface"] == ["ep1"]
    assert cap["ready_hypotheses"] == ["h1"]
    assert cap["event_cursor"] == 2                             # append-only, both events


def test_projection_preserves_operator_content(tmp_path, monkeypatch):
    monkeypatch.setattr(asg, "vault_root", lambda: tmp_path)
    asg.append_event("T2", "hypothesis", hyp_id="h1", requires=[])
    from hunt_loop import Verdict
    # confirm via a direct event so the projection has a capability to show
    asg.append_event("T2", "verdict", hyp_id="h1", verdict=Verdict.CONFIRMED.value,
                     evidence_ref="poc/x", provides=["P:read=config"])

    md = asg.markdown_path("T2")
    md.parent.mkdir(parents=True, exist_ok=True)
    md.write_text("---\nfileClass: AttackSurfaceGraph\n---\n\n## Operator Notes\n\nMY HAND-WRITTEN NOTE\n")
    asg.project_markdown("T2")
    txt = md.read_text()
    assert "MY HAND-WRITTEN NOTE" in txt                        # operator content preserved
    assert asg.GEN_START in txt and asg.GEN_END in txt          # generated block appended
    assert "P:read=config" in txt                              # projected from the ledger

    # re-projecting replaces only the generated block, never duplicates it
    asg.project_markdown("T2")
    assert md.read_text().count(asg.GEN_START) == 1
    assert "MY HAND-WRITTEN NOTE" in md.read_text()


def test_snapshot_is_dataview_friendly(tmp_path, monkeypatch):
    monkeypatch.setattr(asg, "vault_root", lambda: tmp_path)
    asg.append_event("T3", "surface", node_id="ep1", untested=True)
    asg.append_event("T3", "hypothesis", hyp_id="h1", requires=[])
    snap = json.loads(asg.write_snapshot("T3").read_text())
    assert snap["target"] == "T3"
    assert snap["hypotheses_ready"] == 1
    assert snap["untested_surface"] == 1
    assert "next_action" in snap


def test_new_markdown_gets_generated_block_and_operator_section(tmp_path, monkeypatch):
    monkeypatch.setattr(asg, "vault_root", lambda: tmp_path)
    asg.append_event("T4", "surface", node_id="ep1", untested=True)
    md = asg.project_markdown("T4")                             # file did not exist
    txt = md.read_text()
    assert txt.startswith("---")                               # frontmatter
    assert "## Operator Notes" in txt
    assert asg.GEN_START in txt


def _write_yaml_asg(md: Path):
    md.parent.mkdir(parents=True, exist_ok=True)
    md.write_text('''---
fileClass: AttackSurfaceGraph
---
# Attack Surface Graph - T5

```yaml
schema_version: 2
target: T5
capability_state:
  - cap: "P:auth=admin"
    source: SDX-003
    state: confirmed
  - cap: "P:net=external"
    source: initial
    state: reachable
nodes:
  - id: ep-config
    type: endpoint
    identifier: "/api/config"
    discovered_at: "2026-09-01T00:00:00Z"
findings:
  - id: T5-001
    status: validated
    provides: ["P:read=config"]
    requires: []
edges:
  - src: a
    dst: b
    rel: exploits
    status: dead
    reason: "forgetPwd 407+406, R-11"
```

## Operator Notes
keep me
''')


def test_migration_yaml_to_ledger_is_faithful_and_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(asg, "vault_root", lambda: tmp_path)
    _write_yaml_asg(asg.markdown_path("T5"))

    r1 = asg.migrate_yaml_to_ledger("T5")
    assert r1["migrated"] > 0
    loop = HuntLoop.load(asg.ledger_path("T5"))
    cap = loop.capsule()
    # confirmed capability_state -> confirmed verdict WITH (migrated) evidence -> capability
    assert "P:auth=admin" in cap["capabilities"]
    # reachable (NOT confirmed) capability must NOT become a held capability
    assert "P:net=external" not in cap["capabilities"]
    # node -> surface ; validated finding -> confirmed hypothesis ; dead edge -> dead_end
    assert "/api/config" in cap["untested_surface"]
    assert "P:read=config" in cap["capabilities"]
    assert any(e["kind"] == "dead_end" for e in loop.events)

    # idempotent: unchanged Markdown -> no-op
    r2 = asg.migrate_yaml_to_ledger("T5")
    assert r2["migrated"] == 0 and "already migrated" in r2["reason"]


def test_migration_idempotent_even_after_projection(tmp_path, monkeypatch):
    """Regression: project_markdown() changes the Markdown file; the migration
    digest must be computed on the YAML SOURCE (not the whole file), or projecting
    would break idempotency and double-migrate."""
    monkeypatch.setattr(asg, "vault_root", lambda: tmp_path)
    _write_yaml_asg(asg.markdown_path("T6"))
    assert asg.migrate_yaml_to_ledger("T6")["migrated"] > 0
    asg.project_markdown("T6")                                   # mutates the Markdown
    r = asg.migrate_yaml_to_ledger("T6")                         # must still be a no-op
    assert r["migrated"] == 0 and "already migrated" in r["reason"]
