"""kb_connector — the loop consults the EXISTING vault KB, not just its own ledger."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from hunt_loop import HuntLoop  # noqa: E402
from kb_connector import kb_lessons, retrieve_all, mark_influence  # noqa: E402

VAULT_KB = Path(__file__).resolve().parents[1] / "09 - Knowledge Base" / "Lessons"


# logic on a controlled fixture KB (robust, not tied to live content)
def test_kb_lessons_matches_by_tag(tmp_path):
    (tmp_path / "LL-900-example.md").write_text(
        '---\ntitle: "Example"\ntags: [ssrf, oob, callback]\n---\nbody\n', encoding="utf-8")
    (tmp_path / "LL-901-other.md").write_text(
        '---\ntitle: "Other"\ntags: [xss, dom]\n---\nbody\n', encoding="utf-8")
    hits = kb_lessons(["ssrf", "idor"], kb_dir=tmp_path)
    assert [h["lesson_id"] for h in hits] == ["LL-900"]
    assert hits[0]["source"] == "vault-kb"


def test_no_match_returns_empty(tmp_path):
    (tmp_path / "LL-900.md").write_text('---\ntags: [ssrf]\n---\n', encoding="utf-8")
    assert kb_lessons(["nonexistent-tag"], kb_dir=tmp_path) == []


# >half the KB uses YAML block-format tags; the inline-only parser silently missed
# them, which is how merged tags "vanished" after consolidation. Both must parse.
def test_kb_lessons_matches_block_format_tags(tmp_path):
    (tmp_path / "LL-902-block.md").write_text(
        '---\ntitle: "Block"\ntags:\n  - auth-bypass\n  - access-control\n---\nbody\n',
        encoding="utf-8")
    (tmp_path / "LL-903-inline.md").write_text(
        '---\ntitle: "Inline"\ntags: [auth-bypass]\n---\nbody\n', encoding="utf-8")
    hits = sorted(h["lesson_id"] for h in kb_lessons(["auth-bypass"], kb_dir=tmp_path))
    assert hits == ["LL-902", "LL-903"]          # both formats found
    assert [h["lesson_id"] for h in kb_lessons(["access-control"], kb_dir=tmp_path)] == ["LL-902"]


# connection proof: against the REAL vault KB, a common tag returns real lessons.
def test_connects_to_real_vault_kb():
    if not VAULT_KB.is_dir():
        return  # KB not present in this checkout
    hits = kb_lessons(["auth-bypass"])   # a tag used by several real lessons
    assert hits, "expected the connector to find real vault lessons for 'auth-bypass'"
    assert all(h["lesson_id"].startswith("LL-") for h in hits)


# retrieve_all merges ledger + KB and records an auditable kb_consulted event.
def test_retrieve_all_records_consultation(tmp_path):
    (tmp_path / "LL-900.md").write_text('---\ntags: [payment, order]\n---\n', encoding="utf-8")
    lp = HuntLoop()
    lp.add_hypothesis("h1")
    res = retrieve_all(lp, "h1", ["payment"], kb_dir=tmp_path)
    assert [h["lesson_id"] for h in res["kb"]] == ["LL-900"]
    ev = [e for e in lp.events if e["kind"] == "kb_consulted"]
    assert ev and ev[-1]["hyp_id"] == "h1" and "LL-900" in ev[-1]["kb_lesson_ids"]


# influence is operator-marked, not inferred from retrieval.
def test_mark_influence_is_explicit(tmp_path):
    lp = HuntLoop()
    lp.add_hypothesis("h1")
    mark_influence(lp, "h1", "LL-900", changed_decision=True, note="narrowed to write-path")
    ev = [e for e in lp.events if e["kind"] == "lesson_influence"][-1]
    assert ev["changed_decision"] is True and ev["lesson_id"] == "LL-900"
