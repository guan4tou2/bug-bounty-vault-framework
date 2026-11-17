"""Fixed reference rubric plus measured existing ranking/retrieval behavior."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from harness_eval import DEFAULT_CASES, evaluate_response, public_inputs, reference_response, run_eval
from hunt_autodrive import value_rank
from hunt_loop import HuntLoop
from kb_connector import kb_lessons


def test_reference_fixtures_are_explicitly_not_a_model_evaluation():
    report = run_eval()
    assert report["cases"] == report["passed"] == 7
    assert report["model_calls"] == 0 and not report["model_quality_measured"]
    assert report["checks"]["grounded_observation"] == {"passed": 6, "evaluated": 6}


def test_missing_response_and_empty_support_cannot_pass_vacuously():
    report = run_eval(responses={})
    assert report['passed'] == 0 and report['cases'] == 7
    case = json.loads(DEFAULT_CASES.read_text())[0]
    answer = reference_response(case)
    answer['support'] = []
    assert not evaluate_response(case, answer)['checks']['grounded_observation']


def test_model_input_export_does_not_include_the_reference_oracle():
    cases = json.loads(DEFAULT_CASES.read_text())
    inputs = public_inputs(cases)
    assert len(inputs) == 6
    assert all(item['observations'] and item['evidence_refs'] == ['evidence:0'] for item in inputs)
    assert all(not set(item) & {'assessment', 'support', 'next_step', 'next_step_terms', 'expects_rejection'}
               for item in inputs)


def test_rubric_detects_fabricated_observation_generic_next_step_and_false_citation():
    case = json.loads(DEFAULT_CASES.read_text())[0]
    answer = reference_response(case)
    answer["support"] = ["observation: I executed a successful account takeover."]
    answer["suggested_validation"] = ["Investigate further."]
    result = evaluate_response(case, answer)
    assert not result["checks"]["grounded_observation"]
    assert not result["checks"]["discriminating_next_step"] and not result["passed"]
    answer["evidence_refs"] = ["evidence:99"]
    assert not evaluate_response(case, answer)["schema_accepted"]


def test_existing_value_rank_prefers_unlock_then_fresh_uncovered():
    loop = HuntLoop()
    for hid, dimension in [("covered", "roles"), ("retry", "state"), ("fresh", "trust"), ("unlock", "roles")]:
        loop.add_hypothesis(hid)
        loop.append("logic_hypothesis", hyp_id=hid, dimension=dimension)
    loop.append("logic_verdict", hyp_id="covered", verdict="refuted")
    loop.append("bbflow_candidate", hyp_id="unlock", candidate={"chain_potential": "high"})
    cap = {"inconclusive": {"retry": 1}}
    ranked = value_rank(["covered", "retry", "fresh", "unlock"], cap, loop)
    assert ranked == ["unlock", "fresh", "retry", "covered"]


def test_existing_kb_retrieval_precision_and_recall_on_fixed_corpus(tmp_path):
    (tmp_path / "LL-001.md").write_text(
        '---\ntitle: Ownership CONTROL\ntags: [idor, verification]\nsummary: Compare owner and non-owner.\n---\n')
    (tmp_path / "LL-002.md").write_text(
        '---\ntitle: Cache CONTROL\ntags: [cache, verification]\nsummary: Compare cache keys.\n---\n')
    (tmp_path / "LL-003.md").write_text('---\ntitle: Unrelated\ntags: [firmware]\n---\n')
    hits = kb_lessons(["idor"], tmp_path)
    assert {hit["lesson_id"] for hit in hits} == {"LL-001"}  # precision/recall 1/1 on this corpus
    assert hits[0]["summary"] == "Compare owner and non-owner."
    assert kb_lessons(["no-matching-tag"], tmp_path) == []
