"""Read ASG verification metadata. Presence checks are not proof of exploitability."""
from pathlib import Path
import argparse
import json
import re
import sys
import yaml

class Unavailable(ValueError):
    pass

def resolve_asg(target_dir):
    root = Path(target_dir)
    paths = sorted(set(root.glob('Attack Surface Graph*.md')) | set(root.glob('ASG.md')))
    # Event-ledger dashboards are derived views, not the operator's recon document.
    try:
        paths = [p for p in paths if 'generated_from: .state/asg-events.jsonl' not in p.read_text(encoding='utf-8')[:1000]]
    except (OSError, UnicodeError) as e:
        raise Unavailable(str(e)) from e
    if len(paths) != 1:
        raise Unavailable(f'expected one ASG in {root}, found {len(paths)}; reconcile sources explicitly')
    return paths[0]

def load_asg(path):
    path = Path(path)
    try:
        text = path.read_text(encoding='utf-8')
        blocks = re.findall(r'^```ya?ml\s*\n(.*?)^```\s*$', text, re.M | re.S)
        docs = [yaml.safe_load(b) for b in blocks]
        docs = [d for d in docs if isinstance(d, dict) and any(k in d for k in ('findings','nodes','recon_dimensions'))]
        if len(docs) != 1:
            raise Unavailable('missing or ambiguous ASG YAML document')
        if not isinstance(docs[0].get('findings'), list):
            raise Unavailable('findings must be an explicit list (empty list allowed)')
        return docs[0]
    except (OSError, UnicodeError, yaml.YAMLError) as e:
        raise Unavailable(str(e)) from e

def validate(asg, base=None):
    if not isinstance(asg, dict) or not isinstance(asg.get('findings'), list):
        return {'unavailable': ['ASG findings not loaded']}
    debt = {}
    def add(key, fid): debt.setdefault(key, []).append(fid)
    def exists(ref):
        if not isinstance(ref, str) or not ref.strip(): return False
        p = Path(ref.split('#',1)[0])
        if not p.is_absolute():
            if base is None: return False
            p = Path(base) / p
        try:
            return p.is_file() and p.stat().st_size > 0
        except (OSError, ValueError):
            return False
    for f in asg['findings']:
        if not isinstance(f, dict):
            add('invalid_finding', '?'); continue
        fid = str(f.get('id', '?')); status = f.get('status')
        # Status whitelist aligned with check_asg_status_consistency.py (issue #18):
        # platform_not_applicable / structurally_inapplicable are "finding is real but
        # this platform's shipped binary can't be hit" — compatible with
        # confirmed, NOT false_positive. Omitting them here made two gates disagree.
        if status not in ('suspected','validated','refuted','invalidated','false_positive',
                          'platform_not_applicable','structurally_inapplicable'):
            add('invalid_status', fid)
        for key in ('expected_impact','verification_level','verification_risk'):
            if not f.get(key): add('missing_'+key, fid)
        if f.get('verification_level') not in ('version_match','static_confirmed','dynamic_verified'):
            add('invalid_verification_level', fid)
        if f.get('verification_risk') not in ('reads_only','state_query','writes_data','service_impact'):
            add('invalid_risk', fid)
        if status == 'suspected' and not f.get('verification_plan'): add('suspected_without_plan', fid)
        if status == 'validated':
            if f.get('verification_level') != 'dynamic_verified': add('validated_without_dynamic_verification', fid)
            if not f.get('verification_method'): add('validated_without_method', fid)
            for key in ('evidence_ref','poc_ref'):
                if not exists(f.get(key)): add('unresolved_'+key, fid)
            if f.get('impact_result') != 'achieved': add('impact_not_achieved', fid)
            env = f.get('verification_environment')
            if env not in ('stock_target','equivalent_test'): add('unproven_environment', fid)
            if env == 'equivalent_test' and not exists(f.get('environment_equivalence_ref')):
                add('missing_environment_equivalence', fid)
    return debt

def main():
    ap=argparse.ArgumentParser();ap.add_argument('target');ap.add_argument('--vault-root', type=Path, default=Path(__file__).resolve().parents[1]);ap.add_argument('--json', action='store_true');a=ap.parse_args()
    try:
        root=(a.vault_root/'01 - Targets').resolve(); td=(root/a.target).resolve()
        if td == root or root not in td.parents: raise Unavailable('target outside target root')
        p=resolve_asg(td); d=validate(load_asg(p),p.parent)
        result={'status':'debt' if d else 'clear','source':str(p),'debt':d,'note':'metadata checks only; impact requires evidence review'}
        code=1 if d else 0
    except Unavailable as e:
        result={'status':'unavailable','reason':str(e)};code=2
    print(json.dumps(result,ensure_ascii=False,indent=2));return code
if __name__=='__main__': sys.exit(main())
