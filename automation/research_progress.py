"""Measure evidence and resolved claims, never use Finding counts as progress."""
from __future__ import annotations

import hashlib
import json

from evidence_refs import evidence_resolves


def progress_keys(loop):
    keys = set()
    definitions = {}

    def collect(proof):
        if not isinstance(proof, dict):
            return []
        if proof.get("kind") == "comparison":
            return collect(proof.get("test")) + collect(proof.get("control"))
        if proof.get("sha256"):
            return [proof["sha256"]]
        if proof.get("kind") == "observation":
            return [hashlib.sha256(str(proof.get("text", "")).encode()).hexdigest()]
        return []

    for event in loop.events:
        kind = event.get("type")
        if kind == "surface":
            keys.add(("surface", event.get("name")))
        elif kind == "logic_hypothesis":
            definitions[event['hyp_id']] = {key: event.get(key) for key in
                ('dimension', 'invariant', 'invariant_ref', 'expected_normal', 'applies_env')}
        elif kind == "logic_verdict":
            proof = event.get("evidence")
            if event.get("execution") == "ok" and evidence_resolves(proof, loop.base_path, loop.events):
                # A new ID for the same declared claim and conditions is not a
                # new research question. Legacy declarations stay conservative.
                claim = definitions.get(event.get('hyp_id'), event.get('hyp_id'))
                item = [claim, event.get("verdict"), event.get("test_outcome"),
                        event.get("control_outcome"), sorted(collect(proof))]
                keys.add(("comparison", hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()))
    keys.update(('capability', capability) for capability in loop.capsule()['capabilities'])
    return keys


def metrics(loop):
    """Evidence/task measurements only; missing provider usage stays unknown."""
    from collections import Counter
    from work_dispatch import jobs
    from evidence_gaps import project as gaps
    from research_dependencies import project as impact
    work = jobs(loop.events)
    kinds = Counter(k[0] for k in progress_keys(loop))
    usage = [e for e in loop.events if e['type'] == 'work_usage']
    comparisons = Counter(j['comparison_key'] for j in work if j.get('comparison_key'))
    return {'valid_comparisons': kinds['comparison'], 'capabilities': kinds['capability'],
            'work_states': dict(Counter(j['state'] for j in work)),
            'gap_states': dict(Counter(g['state'] for g in gaps(loop))),
            'affected_subjects': len([r for r in impact(loop)['affected'] if not r['ref'].startswith('evidence:')]),
            'model_calls': sum(e['stage'] == 'model_started' for e in usage),
            'model_elapsed_seconds': sum(e.get('elapsed_seconds', 0) for e in usage if e['stage'] == 'model_finished'),
            'tool_calls': sum(e['type'] == 'action_started' for e in loop.events),
            'duplicate_comparison_dispatches': sum(max(0, n - 1) for n in comparisons.values()),
            'input_tokens': None, 'output_tokens': None, 'model_cost': None,
            'limit': 'Observed typed-work calls/time; provider tokens, cost and legacy model calls are not instrumented. Counts do not prove research quality.'}
