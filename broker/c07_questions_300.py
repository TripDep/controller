"""C07 canonical 300+ question bank: source-bound, per-question, fail-closed.

The master defines 300 *base* questions, not 300 automatic PASS flags.
The '+' denotes dynamically generated material questions; in particular,
280-285 oblige seeking new unknowns and reasonable saturation.
No assistant/producer answer, empty audit, or CI success implies work PASS.
"""
import hashlib
import re

FAMILY = 'QUESTIONS_300'
SOURCE = 'master'
SOURCE_PATH = 'governance/sources/GOLDEN_GARDEN_MASTER_RULES_AND_STATE.md'
QUESTION_COUNT = 300
DYNAMIC_IDS = tuple('Q-%03d' % n for n in range(280, 286))

class Blocked(ValueError): pass

def need(ok, reason):
    if not ok: raise Blocked(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def extract_bank(raw):
    """Recover canonical 300 exactly, not an invented assistant question list."""
    need(isinstance(raw, bytes) and raw, 'C07_300_MASTER_BYTES_REQUIRED')
    text = raw.decode('utf-8', errors='strict')
    boundary = text.find('# 13. Current Pavilion / Golden Ting state')
    need(boundary > 0, 'C07_300_ACTIVE_MASTER_BOUNDARY')
    core = text[:boundary]
    anchor = '## Canonical 300 base questions'
    end = '## Bank usage integrity'
    need(core.count(anchor) == 1 and core.count(end) == 1,
         'C07_300_CANONICAL_BANK_ANCHOR')
    before, tail = core.split(anchor, 1)
    bank_text, usage = tail.split(end, 1)
    need('## How ' in before and '300' in before and
         'non-mechanical' in before and
         'Questions 280' in before and
         'context-sensitive' in before,
         'C07_300_CONTEXT_DYNAMIC_SOURCE_NOT_FOUND')
    need('Do not claim' in usage and
         'A new material question' in usage and
         'Any important answer that lacks evidence' in usage,
         'C07_300_BANK_USAGE_FAIL_CLOSED_SOURCE')
    matches = re.findall(r'(?m)^(\d{1,3})\. ([^\n]+)$', bank_text)
    need(len(matches) == 300 and
         [int(n) for n, _ in matches] == list(range(1, 301)),
         'C07_300_QUESTION_COUNT_ORDER_DUPLICATE')
    need(all(q.strip() and ('?' in q or n in ('299', '300'))
             for n, q in matches),
         'C07_300_EMPTY_OR_INVALID_QUESTION')
    return {'Q-%03d' % int(n): q for n, q in matches}

def inspect(inventory, plan, *, master_raw=None,
            audit_raw=None, asset=None, attempt_id=None, reviewed=None):
    """Make all 300 source/question and applicability uncertainties visible."""
    from family_coverage import expected_result
    if reviewed is None:
        from approved_validators import REVIEWED as reviewed
    need(isinstance(inventory, dict) and
         inventory.get('schema') == 'gg-effective-family-inventory-v1',
         'C07_300_TRUSTED_INVENTORY')
    groups, rules, digests = inventory.get('families'), inventory.get('rules'), inventory.get('source_digests')
    need(isinstance(groups,dict) and isinstance(rules,dict)
         and isinstance(digests,dict) and
         re.fullmatch('[a-f0-9]{64}', str(digests.get(SOURCE, ''))),
         'C07_300_MASTER_DIGEST_BINDING')
    flat = [rid for ids in groups.values() for rid in ids]
    need(len(groups)==20 and len(flat)==len(set(flat))==763
         and len(rules)==763 and set(flat)==set(rules)
         and inventory.get('rule_count')==763 and inventory.get('family_count')==20,
         'C07_300_CANONICAL_INVENTORY_MEMBERSHIP')
    ids=groups.get(FAMILY)
    expected=['Q-%03d' % n for n in range(1,301)]
    need(ids==expected, 'C07_300_QUESTION_ID_SEQUENCE')
    need(isinstance(plan,dict) and
         plan.get('master_sha256')==inventory.get('canonical_master_sha256')
         and plan.get('mode') in ('DIAGNOSTIC_ONLY','OPERATIONAL')
         and isinstance(plan.get('enrolled'), dict)
         and isinstance(plan.get('profiles'), list),
         'C07_300_CURRENT_PLAN_REQUIRED')
    parsed=None
    if master_raw is not None:
        need(sha(master_raw)==digests[SOURCE]==plan['master_sha256'],
             'C07_300_LIVE_MASTER_DRIFT')
        parsed=extract_bank(master_raw)

    has_some_attempt=any(v is not None for v in
                         (audit_raw,asset,attempt_id))
    if has_some_attempt:
        need(parsed is not None and isinstance(audit_raw,bytes)
             and isinstance(asset,str) and asset == asset.upper()
             and isinstance(attempt_id,str) and re.fullmatch('[a-f0-9]{64}',attempt_id),
             'C07_300_INCOMPLETE_TRUSTED_ATTEMPT')
        from real_work_intake import audit_check
        from c07_mg0_individual import inspect as inspect_mg0
        rows, tail = audit_check(audit_raw,asset)
    else:
        rows, tail = (), None

    from c07_contextual_questions import select as context_select
    context = context_select(inventory,plan)
    excluded = set(context['excluded'])
    found={}; missing=[]; audit_fails=[]; mg0_fails=[]
    for rid in expected:
        row=rules[rid]
        question=row.get('requirement')
        need(row.get('family')==FAMILY and row.get('source')==SOURCE
             and row.get('source_path')==SOURCE_PATH
             and row.get('source_sha256')==digests[SOURCE]
             and row.get('requirement_sha256')==sha(question.encode('utf-8'))
             and row.get('required_mg0') is True
             and isinstance(question,str) and question.strip(),
             'C07_300_SOURCE_QUESTION_DRIFT:'+rid)
        if parsed is not None:
            need(parsed[rid]==question, 'C07_300_MASTER_QUESTION_TEXT_MISMATCH:'+rid)
        applicability=expected_result(row,plan.get('phase'),plan.get('asset_type'),
                                     plan.get('profiles'))
        need(applicability in ('PASS','FUTURE_PHASE','N_A_PROFILE_NOT_SELECTED','N_A_ASSET_TYPE'),
             'C07_300_UNTRUSTED_APPLICABILITY:'+rid)
        # Global base bank has no source-declared N/A for a particular work item.
        # A work-specific selection requires independent proof; never create one.
        need(applicability=='PASS', 'C07_300_BASE_BANK_UNEXPECTED_WAIVER:'+rid)
        if rid not in excluded and (rid not in reviewed or rid not in plan['enrolled']):
            missing.append(rid)
        scoped=[r for r in rows if r.get('rule_id')==rid and
                r.get('attempt_id')==attempt_id]
        failure=[r['record_hash'] for r in scoped
                 if r.get('result') in ('FAIL','BLOCKED')
                 or r.get('event')=='VERIFIED_STATE_REVOKED']
        if failure: audit_fails.append(rid)
        mg0='UNKNOWN'
        if has_some_attempt:
            mg0=inspect_mg0(master_raw,audit_raw,asset,
                            plan['master_sha256'],rid,attempt_id)['individual_rule_mg0']
            need(mg0 in ('UNKNOWN','FAIL'), 'C07_300_MG0_FALSE_PASS:'+rid)
            if mg0=='FAIL': mg0_fails.append(rid)
        found[rid]={
            'canonical_question':question,
            'context_selection':context['rows'][rid],
            'requirement_sha256':row['requirement_sha256'],
            'source_sha256':row['source_sha256'],
            'canonical_integrity':'PASS',
            'question_selection':context['rows'][rid]['selection'],
            'answer_evidence_verified':False,
            'semantic_verdict':'UNKNOWN',
            'individual_mg0':mg0,
            'current_attempt_failure_hashes':failure,
            'dynamic_question_discovery_required':rid in DYNAMIC_IDS,
            'work_progress_authorized':False,
        }
    need(len(found)==300 and all(x in found for x in DYNAMIC_IDS),
         'C07_300_ALL_QUESTIONS_AND_DYNAMIC_TRIGGER_REQUIRED')
    return {
        'schema':'gg-c07-300-plus-question-bank-source-gate-v1',
        'canonical_master_sha256':plan['master_sha256'],
        'base_questions':len(found),
        'canonical_questions_source_integrity_pass':300,
        'required_dynamic_discovery_questions':list(DYNAMIC_IDS),
        'additional_material_questions': 'UNRESOLVED_CONTEXT_DERIVED_NOT_FIXED_300',
        'independent_context_applicability_confirmed':0,
        'owner_reviewed_context_exclusions':len(excluded),
        'context_due_count':context['due_count'],
        'context_exclusions_with_reasons':{rid:context['rows'][rid] for rid in context['excluded']},
        'context_scope_is_not_independent_asset_proof':True,
        'missing_due_semantic_validators':missing,
        'observed_question_failure_ids':audit_fails,
        'observed_uncorrected_mg0_ids':mg0_fails,
        'real_work_audit_bound':has_some_attempt,'audit_tail':tail,
        'answers_independently_verified':0,'individual_mg0_passes':0,
        'advancement_authorized':False,'questions':found,
    }

def require_operational_scope(inventory,plan,**context):
    report=inspect(inventory,plan,**context)
    if plan['mode']=='OPERATIONAL':
        need(not report['missing_due_semantic_validators'],
             'C07_300_MISSING_SEMANTIC_QUESTION_VALIDATORS:'+
             str(len(report['missing_due_semantic_validators'])))
        need(not report['observed_question_failure_ids'],
             'C07_300_UNRESOLVED_QUESTION_FAILURE')
        need(not report['observed_uncorrected_mg0_ids'],
             'C07_300_UNCORRECTED_MG0')
        # A complete reviewed validator registry remains insufficient to
        # authorize work absent native evidence for the current attempt.
    return report
