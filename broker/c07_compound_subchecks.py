"""C07: derive reviewable composite obligations from immutable canonical sources.

The 72 composite flags come from the already reviewed 758-question manifest.
No new question wording is invented; source bullet lists are *candidates* until
reviewed individually by a genuinely independent native semantic validator.
"""
import hashlib
import re

import c07_answer_semantics as answers


class IncompleteComposite(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise IncompleteComposite(reason)


def sha(raw):
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def ids(inventory):
    """Never take the composite list from the assistant or a work offer."""
    wording = answers._verified_wording(inventory)
    if inventory.get('rule_count') == 763:
        found = {rid for rid, row in wording.items() if row['compound_review']}
        need(len(found) == 72, 'C07_COMPOSITE_REVIEW_COUNT_DRIFT')
        need(found <= set(inventory['rules']), 'C07_COMPOSITE_NOT_CANONICAL')
        return found
    # Tiny, non-operational unit fixtures keep only their explicitly marked IDs.
    return set()


def clauses(rule_id, source):
    """Source clauses are evidence targets, never verified results.

    Only G0 has an exactly numbered 30-control section for which coverage can
    be verified mechanically. Lists elsewhere are NOT assumed exhaustive.
    """
    need(isinstance(source, str) and source.strip(), 'C07_COMPOSITE_MISSING_SOURCE:' + rule_id)
    if rule_id == 'G0':
        begin = '### Exact recovered 30-control source list'
        end = '### G0 canonical role'
        a = source.find(begin)
        b = source.find(end, a + len(begin))
        need(a >= 0 and b > a, 'C07_G0_SOURCE_LIST_MISSING')
        text = source[a + len(begin):b]
        found = [(int(n), value.strip()) for n, value in
                 re.findall(r'(?m)^([0-9]{1,2})[.]\s+(.+)$', text)]
        need([n for n, _ in found] == list(range(1, 31)),
             'C07_G0_NOT_ALL_30_SOURCE_CONTROLS')
        return [(n, value) for n, value in found], 'EXACT_30_SOURCE_CONTROLS_NOT_SEMANTICALLY_VERIFIED'
    # Extract complete source lines, without treating heading text or a short
    # summary as proof that the composite has been fully decomposed.
    matches = re.findall(r'(?m)^\s*(?:[-*]|[0-9]{1,3}[.])\s+(.+)$', source)
    lines = [line.strip() for line in matches if line.strip()]
    if len(lines) > 1:
        need(len(lines) <= 200, 'C07_COMPOSITE_SOURCE_LIST_TOO_LARGE:' + rule_id)
        return list(enumerate(lines, 1)), 'SOURCE_LIST_CANDIDATES_REVIEW_PENDING'
    return [(1, source.strip())], 'UNSPLIT_COMPOSITE_REVIEW_PENDING'


def inspect(inventory, due_ids):
    all_composite = ids(inventory)
    need(isinstance(due_ids, list) and len(due_ids) == len(set(due_ids))
         and set(due_ids) <= set(inventory['rules']), 'C07_COMPOSITE_TRUSTED_DUE')
    output = {}
    for rule_id in sorted(all_composite.intersection(due_ids)):
        rule = inventory['rules'][rule_id]
        source = rule['requirement']
        need(rule['requirement_sha256'] == sha(source),
             'C07_COMPOSITE_REQUIREMENT_DRIFT:' + rule_id)
        enumerated, coverage = clauses(rule_id, source)
        checks = []
        for number, text in enumerated:
            checks.append({'subcheck_id': rule_id + ':SC' + str(number).zfill(3),
                           'canonical_clause': text,
                           'clause_sha256': sha(text),
                           'provenance_requirement_sha256': rule['requirement_sha256'],
                           'native_semantic_verifier': 'NOT_REVIEWED',
                           'individual_mg0': 'UNKNOWN',
                           'independent_result': 'UNKNOWN'})
        output[rule_id] = {
            'family': rule['family'],
            'source_sha256': rule['source_sha256'],
            'requirement_sha256': rule['requirement_sha256'],
            'source_decomposition': coverage,
            'source_subcheck_count': len(checks),
            'subchecks': checks,
            'independent_verifier_ready': False,
            'advancement_authorized': False}
    return {'schema': 'gg-c07-canonical-composites-v1',
            'master_sha256': inventory['canonical_master_sha256'],
            'canonical_composite_count': len(all_composite),
            'due_composite_count': len(output),
            'due_composites': output,
            'independently_verified_count': 0,
            'advancement_authorized': False}


def assess(report, packets, *, attempt_id, operation_sha256):
    """Classify producer's per-subcheck statements without giving PASS.

    Every packet identifies a *source* subcheck. YES/NO on its own cannot
    establish a native rule or MG0 pass; false or missing assertions produce
    targeted FAIL/UNKNOWN findings that remain visible in Controller audit.
    """
    need(isinstance(report, dict) and report.get('schema') ==
         'gg-c07-canonical-composites-v1', 'C07_COMPOSITE_REPORT_SCHEMA')
    need(isinstance(packets, list), 'C07_COMPOSITE_PACKET_LIST')
    expected = {row['subcheck_id']: (rid, row)
                for rid, detail in report['due_composites'].items()
                for row in detail['subchecks']}
    received = {}
    failures = []
    keys = {'rule_id', 'subcheck_id', 'clause_sha256', 'master_sha256',
            'attempt_id', 'operation_sha256', 'answer', 'evidence_refs'}
    for item in packets:
        need(type(item) is dict and set(item) == keys,
             'C07_COMPOSITE_PACKET_SCHEMA')
        sid = item['subcheck_id']
        need(sid in expected and expected[sid][0] == item['rule_id'],
             'C07_COMPOSITE_NOT_DUE_OR_UNKNOWN_SUBCHECK')
        need(sid not in received, 'C07_COMPOSITE_DUPLICATE_SUBCHECK:' + sid)
        expected_clause = expected[sid][1]
        need(item['clause_sha256'] == expected_clause['clause_sha256']
             and item['master_sha256'] == report['master_sha256']
             and item['attempt_id'] == attempt_id
             and item['operation_sha256'] == operation_sha256,
             'C07_COMPOSITE_SOURCE_OR_ATTEMPT_REPLAY:' + sid)
        need(item['answer'] in ('YES', 'NO', 'UNKNOWN') and
             type(item['answer']) is str, 'C07_COMPOSITE_ANSWER_ENUM:' + sid)
        refs = item['evidence_refs']
        need(type(refs) is list and len(refs) <= 20 and
             all(type(r) is dict and set(r) == {'ref', 'sha256'} and
                 type(r['ref']) is str and 0 < len(r['ref']) <= 1024 and
                 isinstance(r['sha256'], str) and
                 re.fullmatch('[a-f0-9]{64}', r['sha256']) for r in refs),
             'C07_COMPOSITE_EVIDENCE_REFS:' + sid)
        received[sid] = {'answer': item['answer'],
                         'result': 'FAIL' if item['answer'] == 'NO' else 'UNKNOWN',
                         'reason': 'ADMITTED_SUBCONTROL_NOT_DONE' if item['answer'] == 'NO'
                                   else 'INDEPENDENT_SUBCONTROL_PROOF_REQUIRED'}
        if item['answer'] == 'NO':
            failures.append({'rule_id': item['rule_id'], 'subcheck_id': sid,
                             'required_correction': 'COMPLETE_THIS_CANONICAL_SUBCONTROL'})
    missing = [{'rule_id': expected[sid][0], 'subcheck_id': sid,
                'required_correction': 'SUPPLY_THIS_DUE_SUBCONTROL_ANSWER'}
               for sid in sorted(set(expected) - set(received))]
    return {'schema': 'gg-c07-composite-assessment-v1',
            'result': 'FAIL' if failures else 'UNKNOWN',
            'answered': received, 'failed': failures, 'missing': missing,
            'independent_subcontrol_proof_verified': False,
            'advancement_authorized': False}
