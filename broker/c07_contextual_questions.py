"""Source-bound B selection for the canonical 300 questions.

All 300 remain visible. Only an owner-approved Controller STATUS plan with
specific evidence may mark a question N/A in THIS operation. Exclusions are
not semantic/MG0 PASS and cannot waive the mandatory discovery/closing gates.
"""
import hashlib
import json
import re

SHA = re.compile(r'[a-f0-9]{64}\Z')
NON_EXCLUDABLE = frozenset('Q-%03d' % n for n in range(280, 301))
SCHEMA = 'gg-c07-300-owner-reviewed-context-v1'

class ContextBlocked(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise ContextBlocked(reason)

def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest()

def select(inventory, plan):
    """Recompute all 300 dispositions from canonical source and trusted plan.

    The caller must prove Controller STATUS approval of the plan; a producer
    packet must never supply this scope. All missing decisions remain DUE.
    """
    if inventory.get('rule_count') != 763:
        need(not plan.get('question_context'), 'C07_CONTEXT_NONCANONICAL_INVENTORY')
        return None
    questions = inventory['families']['QUESTIONS_300']
    need(questions == ['Q-%03d' % n for n in range(1, 301)],
         'C07_CONTEXT_300_SOURCE_MEMBERSHIP')
    for rid in questions:
        row = inventory['rules'][rid]
        need(row['family'] == 'QUESTIONS_300' and
             row['source_sha256'] == inventory['source_digests']['master'] and
             row['requirement_sha256'] == hashlib.sha256(
                 row['requirement'].encode('utf-8')).hexdigest(),
             'C07_CONTEXT_QUESTION_SOURCE_DRIFT:' + rid)
    ctx = plan.get('question_context')
    exclusions = {}
    if ctx is not None:
        need(type(ctx) is dict and set(ctx) == {'schema', 'master_sha256',
             'phase', 'asset_type', 'profiles', 'exclusions'},
             'C07_CONTEXT_SCHEMA')
        need(ctx['schema'] == SCHEMA and
             ctx['master_sha256'] == inventory['canonical_master_sha256'] == plan['master_sha256']
             and ctx['phase'] == plan['phase'] and ctx['asset_type'] == plan['asset_type']
             and ctx['profiles'] == plan['profiles'], 'C07_CONTEXT_TRUSTED_WORK_DRIFT')
        exclusions = ctx['exclusions']
        need(type(exclusions) is dict and set(exclusions) <= set(questions),
             'C07_CONTEXT_EXCLUSION_IDS')
    rows = {}
    for rid in questions:
        source = inventory['rules'][rid]
        spec = exclusions.get(rid)
        if spec is not None:
            need(rid not in NON_EXCLUDABLE,
                 'C07_CONTEXT_CRITICAL_QUESTION_CANNOT_BE_EXCLUDED:' + rid)
            need(type(spec) is dict and set(spec) == {
                'requirement_sha256','reason','evidence_ref','evidence_sha256',
                'review_authority'}, 'C07_CONTEXT_REASON_SCHEMA:' + rid)
            need(spec['requirement_sha256'] == source['requirement_sha256'],
                 'C07_CONTEXT_QUESTION_HASH_DRIFT:' + rid)
            need(spec['review_authority'] == 'OWNER_APPROVED_CONTROLLER_STATUS' and
                 type(spec['reason']) is str and 40 <= len(spec['reason'].strip()) <= 1500 and
                 len(set(spec['reason'].lower().split())) >= 7 and
                 type(spec['evidence_ref']) is str and
                 0 < len(spec['evidence_ref']) <= 1024 and
                 not spec['evidence_ref'].startswith(('http://', 'https://')) and
                 type(spec['evidence_sha256']) is str and SHA.fullmatch(spec['evidence_sha256']),
                 'C07_CONTEXT_SPECIFIC_OWNER_REASON_AND_EVIDENCE_REQUIRED:' + rid)
        rows[rid] = {
            'requirement_sha256': source['requirement_sha256'],
            'source_sha256': source['source_sha256'],
            'selection': 'CONTEXT_EXCLUDED_OWNER_REVIEWED_NOT_PASS' if spec else 'DUE',
            'reason': spec['reason'].strip() if spec else 'NO_APPROVED_CONTEXT_EXCLUSION',
            'evidence_ref': spec['evidence_ref'] if spec else None,
            'evidence_sha256': spec['evidence_sha256'] if spec else None,
            'semantic_result': 'NOT_EVALUATED' if spec else 'UNKNOWN',
            'individual_mg0': 'NOT_DUE_NO_PASS' if spec else 'UNKNOWN',
            'advancement_authorized': False,
        }
    due = [rid for rid in questions if rows[rid]['selection'] == 'DUE']
    excluded = [rid for rid in questions if rid not in due]
    need(len(rows) == len(due) + len(excluded) == 300 and
         NON_EXCLUDABLE <= set(due), 'C07_CONTEXT_LOST_MANDATORY_QUESTIONS')
    return {
        'schema': 'gg-c07-300-context-selection-v1',
        'master_sha256': inventory['canonical_master_sha256'],
        'context_sha256': digest(ctx) if ctx is not None else None,
        'total_questions': 300, 'due': due, 'excluded': excluded,
        'due_count': len(due), 'excluded_count': len(excluded),
        'rows': rows, 'excluded_never_pass': True,
        'dynamic_discovery_always_due': sorted(NON_EXCLUDABLE),
        'work_advancement_authorized': False,
    }
