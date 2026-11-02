"""Executable candidate semantics for the first immutable 100 macro rules.

Development entry point, deliberately separate from certify_native/REVIEWED.
Results describe untrusted observations. An OBSERVED computation is neither a
full semantic certification nor MG0; natural-language interpretation, source
completeness and observation authenticity still require independent review.

CLI: python c07_macro100_semantics.py --inventory INV --observations OBS
     --blobs DIR --output REPORT
DIR contains original observation files named by their SHA256, not PASS maps.
No network, upload, paid API or application execution is performed.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from real_work_intake import audit_check, strict_json
from c07_macro100_domain import (Context, Finding, evaluate, require, verdict,
                                 instant, ids, number, range_covered)
from c07_macro100_behavior import BEHAVIOR, b007, b014, b017
from c07_macro100_regressions import REGRESSIONS
from c07_macro100_production import PRODUCTION, a004, c024
from c07_macro100_evidence_gate import BATCH_IDS

BEHAVIOR_ALL = {**BEHAVIOR, **REGRESSIONS}
CLAUSE_BINDINGS = json.loads(Path(__file__).with_name('c07_macro100_clause_bindings.json').read_text(encoding='utf8'))


def combine(results, reason):
    failed = {k: asdict(v) for k, v in results.items() if v.result == 'FAIL'}
    unknown = {k: asdict(v) for k, v in results.items() if v.result == 'UNKNOWN'}
    return Finding('FAIL' if failed else 'UNKNOWN' if unknown else 'OBSERVED', reason,
                   {'failed': failed, 'unknown': unknown, 'evaluated': len(results)})


def error_registry(c):
    return combine({rid: evaluate(fn, c) for rid, fn in BEHAVIOR_ALL.items()},
                   'all 110 error/prevention predicates; no majority-vote or omitted child success')


def reading(c):
    sources = c.rows('required_sources')
    reads = c.rows('source_reads')
    first = min(instant(r['at']) for r in c.actions())
    for source in sources:
        raw = c.blob(source['sha256'])
        ranges = [r['byte_range'] for r in reads if r['sha256'] == source['sha256']
                  and r['source_kind'] == 'CANONICAL_FILE' and instant(r['at']) < first]
        if not ranges or not range_covered(ranges, len(raw)):
            return verdict(False, 'required original source not read completely before action', source['id'])
    return verdict(True, 'complete source-file read ranges precede action')


def analysis(c):
    proposal = c.get('proposal')
    analyses = c.rows('analyses')
    required = {'CAUSE', 'DEPENDENCIES', 'STATE', 'CONSTRAINTS', 'REGRESSIONS', 'IMPLICATIONS'}
    if {r['dimension'] for r in analyses} != required:
        return verdict(False, 'pre-proposal analysis omits a required dimension')
    for row in analyses:
        sources = row['source_sha256']
        require(type(sources) is list and bool(sources), 'analysis has no source observations')
        for sha in sources:
            c.blob(sha)
        if row['objective_id'] != proposal['objective_id'] or instant(row['at']) >= instant(proposal['at']):
            return verdict(False, 'analysis follows proposal or concerns different objective')
    return verdict(True, 'all six analysis dimensions source-bound before same-objective proposal')


def append_only(c):
    snapshot = c.get('audit_snapshots')
    before, after = c.blob(snapshot['before_sha256']), c.blob(snapshot['after_sha256'])
    previous, _ = audit_check(before, snapshot['asset'])
    current, tail = audit_check(after, snapshot['asset'])
    return verdict(current[:len(previous)] == previous and len(current) >= len(previous)
                   and tail == snapshot['state_tail'],
                   'entire prior audit prefix retained and current chain aligns with state')


def adversarial(c):
    cases = c.rows('adversarial_cases')
    runs = c.runs()
    defects = c.rows('quality_issues')
    for case in cases:
        run = runs[case['run_id']]
        c.blob(run['input_sha256'])
        if not (run['artifact_sha256'] == case['artifact_sha256'] and
                run['actual_result'] == case['expected_rejection'] and
                run['effect_count'] == 0):
            return verdict(False, 'adversarial case accepted or allowed effects', case['id'])
    if any(r['severity'] in ('CRITICAL', 'HARD_FAIL') and r['resolved_at'] is None for r in defects):
        return verdict(False, 'adversarial review leaves critical defect unresolved')
    return verdict(True, 'explicit artifact-specific adversarial cases reject unsafe outcomes without effects')


def architecture(c):
    objects = c.rows('architecture_authorship')
    approvals = c.rows('authorizations')
    for obj in objects:
        if obj['asset_type'] != 'architecture':
            continue
        exception = any(r['authority'] == 'OWNER' and r['operation'] == 'ALLOW_PROCEDURAL_ARCHITECTURE'
                        and r['asset_id'] == obj['asset_id'] and instant(r['at']) < instant(obj['at'])
                        for r in approvals)
        if obj['authorship'] != 'ONE_TO_ONE' and not exception:
            return verdict(False, 'architectural geometry generated modularly without explicit exception')
        if obj['source_asset'] == 'APPROVED_PAVILION' and obj['operation'] in ('DEMOLISH', 'REBUILD'):
            trials = c.rows('necessity_trials')
            if not any(r['asset_id'] == obj['asset_id'] and r['outcome'] == 'REBUILD_REQUIRED'
                       and instant(r['at']) < instant(obj['at']) for r in trials):
                return verdict(False, 'approved Pavilion rebuilt without demonstrated necessity')
    return verdict(True, 'architecture authored one-to-one and protected baseline not arbitrarily rebuilt')


def quality_floor(c):
    reference = c.get('quality_floor')
    comparisons = c.rows('quality_floor_comparisons')
    required = {'ROOF_SURFACE', 'RIDGE', 'ROOF_CENTER', 'SUPPORT_CHAIN', 'CARPENTRY',
                'PODIUM_STAIRS', 'ROUND_FACETING', 'INTERSECTIONS', 'UNDERSIDE',
                'REPETITION', 'LOCKED_QUALITY_REGRESSION'}
    require({r['class'] for r in comparisons} == required, 'architectural hard-failure coverage incomplete')
    for row in comparisons:
        c.blob(row['candidate_sha256']); c.blob(row['reference_sha256'])
        if row['reference_sha256'] != reference['sha256'] or row['finding_count'] != 0:
            return verdict(False, 'architectural hard failure or wrong quality baseline', row['class'])
    for circle in c.rows('round_elements'):
        minimum = {'HERO': 48, 'MEDIUM': 32, 'SMALL': 24}[circle['visibility']]
        if number(circle['radial_segments']) < minimum or circle['visible_faceting']:
            return verdict(False, 'circular element below canonical tessellation or visibly faceted', circle['id'])
    return verdict(True, 'all canonical architectural failure classes assessed against floor and round geometry')


def autonomous(c):
    cycles = c.rows('verification_cycles')
    questions = c.rows('autonomous_questions')
    issues = c.rows('quality_issues')
    for cycle in cycles:
        hits = [r for r in questions if r['cycle_id'] == cycle['id'] and
                instant(r['at']) < instant(cycle['closed_at']) and r['scope'] == 'OUTSIDE_REQUESTED_CHECKLIST']
        require(bool(hits), 'no autonomous pre-close question outside checklist')
        for question in hits:
            for finding in question['material_finding_ids']:
                linked = [r for r in issues if r['id'] == finding and r['question_id'] == question['id']]
                if not linked or any(r['resolved_at'] is None or
                                     instant(r['resolved_at']) >= instant(cycle['closed_at']) for r in linked):
                    return verdict(False, 'material autonomous finding not resolved before cycle close')
    return verdict(True, 'pre-close autonomous questions open and resolve material findings beyond checklist')


def behavior_protocol(c):
    children = {'110_ERROR_REGISTRY': error_registry(c), 'A': evaluate(reading, c),
                'B': evaluate(analysis, c), 'PRE_ACTION_CONSTRAINTS': evaluate(b014, c),
                'EXACT_OPERATION': evaluate(b017, c)}
    def destination(context):
        publications = context.rows('artifact_publications')
        forbidden = {'MODEL', 'TEXTURE', 'RENDER', 'PRODUCTION_PACKAGE'}
        return verdict(not any(r['kind'] in forbidden and r['destination'] == 'GITHUB' for r in publications),
                       '3D assets remain in chat/Library and out of GitHub')
    children['DELIVERY_DESTINATION'] = evaluate(destination, c)
    return combine(children, 'behavior protocol combines all prevention, pre-action and publication obligations')


MACROS = {'110_ERROR_REGISTRY': error_registry, 'A': reading, 'B': analysis,
          'APPEND_ONLY_AUDIT': append_only, 'ADVERSARIAL_QA': adversarial,
          'ARCHITECTURE_1TO1': architecture, 'ARCHITECTURAL_QUALITY_FLOOR': quality_floor,
          'AUTONOMOUS_PRE_PASS_QUESTION': autonomous,
          'ASSISTANT_BEHAVIOR_PROTOCOL': behavior_protocol}
EVALUATORS = {**BEHAVIOR, **PRODUCTION, **MACROS}
assert set(EVALUATORS) == set(BATCH_IDS)


def inspect_candidate(inventory, observations, blobs=None):
    """Evaluate code candidates, not native proofs or a trusted plan's admission.

    Source-clause hashes are frozen against the actual v175-derived inventory.
    Master revisions may change while unchanged clauses retain their identity;
    callers must still supply the real current canonical inventory separately.
    """
    require(type(inventory) is dict and inventory.get('schema') == 'gg-effective-family-inventory-v1'
            and inventory.get('rule_count') == 763 and len(inventory.get('rules', {})) == 763,
            'canonical 763-rule inventory required')
    for rid, binding in CLAUSE_BINDINGS.items():
        row = inventory['rules'].get(rid, {})
        clause = row.get('requirement')
        require(type(clause) is str and hashlib.sha256(clause.encode('utf8')).hexdigest() ==
                row.get('requirement_sha256') == binding['requirement_sha256']
                and row.get('source') == binding['source'], 'source clause changed: '+rid)
    context = Context(observations, blobs)
    rows = {}
    for rid in BATCH_IDS:
        observation = evaluate(EVALUATORS[rid], context)
        rows[rid] = {**asdict(observation), 'rule_id': rid,
                     'requirement_sha256': CLAUSE_BINDINGS[rid]['requirement_sha256'],
                     'implementation': EVALUATORS[rid].__module__+'.'+EVALUATORS[rid].__name__,
                     'independent_semantic_review': 'PENDING', 'individual_mg0': 'NOT_RUN',
                     'full_rule_pass': False}
    return {'schema': 'gg-c07-macro100-domain-candidate-v1',
            'input_authority': 'UNTRUSTED_OBSERVATIONS',
            'rule_count': 100, 'rules': rows,
            'counts': {state: sum(r['result'] == state for r in rows.values())
                       for state in ('OBSERVED', 'FAIL', 'UNKNOWN')},
            'certified_full_count': 0, 'individual_mg0_passes': 0,
            'advancement_authorized': False}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory', type=Path, required=True)
    p.add_argument('--observations', type=Path, required=True)
    p.add_argument('--blobs', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(argv)
    inventory = strict_json(args.inventory.read_bytes())
    observations = strict_json(args.observations.read_bytes())
    blobs = {}
    for path in args.blobs.iterdir():
        if path.is_file() and not path.is_symlink() and len(path.name) == 64:
            blobs[path.name] = path.read_bytes()
    report = inspect_candidate(inventory, observations, blobs)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
