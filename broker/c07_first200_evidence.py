"""C07 first 200: compile and evaluate rule-bound *independent evidence* in bulk.

Not the R108 question-count/readback step. This executes existing native
documentary predicates and, when explicitly furnished verified current
Controller audit bytes, replays MG0 for the exact due rules. Every rule keeps
its own requirement digest, evidence contract, negative findings and blockers.
A source-integrity or documentary PASS is NEVER a production/MG0 PASS.
No externally furnished PASS dictionary is accepted.
"""
import hashlib
import json

import c07_answer_semantics as question_bank
import c07_compound_subchecks as composites
import c07_operation_scope as operation_scope
from c07_aaa200 import EVIDENCE_BY_SECTION
from approved_validators import REVIEWED

SCHEMA = 'gg-c07-first200-evidence-execution-v1'
HEX = set('0123456789abcdef')

class IncompleteNativeBatch(ValueError):
    pass

def need(ok, msg):
    if not ok:
        raise IncompleteNativeBatch(msg)

def digest(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),
                                     ensure_ascii=False).encode()).hexdigest()

def inspect(inventory, plan, *, qa_raw=None, catalog_raw=None,
            master_raw=None, audit_raw=None, asset=None, attempt_id=None):
    """Evaluate the first 200 in immutable source order; never trust a result map.

    A historical R173 report supplies *documentary* evidence only for its
    eleven exact requirements; it is not the current asset or attempt.
    A supplied audit must be tied to current Controller asset+attempt and
    is never interpreted as proof that undiscovered errors cannot exist.
    """
    need(inventory.get('schema')=='gg-effective-family-inventory-v1'
         and inventory.get('rule_count')==763,
         'FIRST200_CANONICAL_INVENTORY_REQUIRED')
    ids = [rid for family in inventory['families'].values() for rid in family]
    need(len(ids)==len(set(ids))==763 and set(ids)==set(inventory['rules']),
         'FIRST200_CANONICAL_MEMBERSHIP')
    # R108 batch identities are in stable lexical canonical-ID order, not
    # insertion order of family_coverage.build_inventory (family-based).
    selected = sorted(ids)[:200]
    need(selected[:2] == ['110_ERROR_REGISTRY','A'] and
         selected[2:] == [f'AAA-200-{chr(ord("A")+(n-1)//10)}-{n:03d}'
                          for n in range(1,199)],
         'FIRST200_EXACT_SOURCE_ORDER_CHANGED')
    ledger = question_bank.build(inventory)
    applicability = operation_scope.inspect(inventory, plan)
    all_compounds = composites.ids(inventory)
    compound = composites.inspect(inventory,
                 sorted(set(applicability['due']) & set(selected)))
    expected_compound = all_compounds & set(selected) & set(applicability['due'])
    need(set(compound['due_composites'])==expected_compound,
         'FIRST200_COMPOSITE_SOURCE_DRIFT')

    # Recompute actual source-backed predicates, never read producer verdicts.
    if qa_raw is None and catalog_raw is None:
        documented = {}
        documentary_sha = None
    else:
        need(type(qa_raw) is bytes and type(catalog_raw) is bytes,
             'FIRST200_DOCUMENTARY_SOURCE_BYTES_REQUIRED')
        from r173_rule_semantics import inspect as inspect_r173
        report = inspect_r173(qa_raw,catalog_raw)
        need(report['schema']=='gg-r173-p0-documentary-verdict-v1'
             and report['individual_rule_mg0_passes']==0
             and not report['advancement_authorized']
             and len(report['results'])==11,
             'FIRST200_R173_INDEPENDENT_READBACK_INVALID')
        documented = report['results']
        documentary_sha = hashlib.sha256(qa_raw).hexdigest()
        need(set(documented) <= set(selected),
             'FIRST200_DOCUMENTARY_OUT_OF_SCOPE')

    due = set(applicability['due'])
    selected_due = sorted(due & set(selected))
    mg0_rows = None
    if any(x is not None for x in (master_raw,audit_raw,asset,attempt_id)):
        need(type(master_raw) is bytes and type(audit_raw) is bytes
             and type(asset) is str and asset==asset.upper()
             and type(attempt_id) is str and len(attempt_id)==64
             and set(attempt_id) <= HEX,
             'FIRST200_CURRENT_ATTEMPT_SOURCES_REQUIRED')
        from c07_mg0_individual import inspect_batch as inspect_real_mg0
        mg0_batch = inspect_real_mg0(master_raw,audit_raw,asset,
                 inventory['canonical_master_sha256'],selected_due,attempt_id)
        need(mg0_batch['rule_count']==len(selected_due)
             and mg0_batch['individual_mg0_passes']==0
             and not mg0_batch['advancement_authorized'],
             'FIRST200_MG0_REVIEW_MISMATCH')
        mg0_rows = mg0_batch['rules']

    rows = {}
    counts = {'DOCUMENTARY_PASS_SCOPE_LIMITED':0,
              'DOCUMENTARY_FAIL':0,'DOCUMENTARY_NOT_EVALUATED':0,
              'CURRENT_ATTEMPT_MG0_FAIL':0,'CURRENT_ATTEMPT_MG0_UNKNOWN':0,
              'CURRENT_ATTEMPT_MG0_NOT_CHECKED':0,
              'DUE_NO_REVIEWED_NATIVE_IMPLEMENTATION':0}
    for rid in selected:
        source = inventory['rules'][rid]
        entry = ledger['entries'][rid]
        applicability_row = applicability['by_rule'][rid]
        want = applicability_row['disposition']
        need(source['requirement_sha256']==entry['requirement_sha256']
             and source['source_sha256']==entry['source_sha256'],
             'FIRST200_REQUIREMENT_SOURCE_DRIFT:'+rid)
        section=source.get('catalog_section')
        contract = (EVIDENCE_BY_SECTION[section] if section else
                    'HASH_CHAINED_CONTROLLER_PROCESS_AND_OWNER_SCOPE')
        native=rid in REVIEWED
        doc = documented.get(rid)
        doc_result = ('DOCUMENTARY_NOT_EVALUATED' if doc is None else
                      'DOCUMENTARY_PASS_SCOPE_LIMITED' if
                          doc['documentary_result']=='PASS'
                      else 'DOCUMENTARY_FAIL')
        need(doc_result in counts, 'FIRST200_UNEXPECTED_DOCUMENTARY_RESULT:'+rid)
        counts[doc_result]+=1
        mg = ('NOT_DUE' if want!='DUE' else
              mg0_rows[rid]['verdict'] if mg0_rows is not None else
              'UNKNOWN_NOT_CHECKED')
        if want=='DUE':
            if mg == 'FAIL':
                counts['CURRENT_ATTEMPT_MG0_FAIL']+=1
            elif mg=='UNKNOWN':
                counts['CURRENT_ATTEMPT_MG0_UNKNOWN']+=1
            else:
                need(mg=='UNKNOWN_NOT_CHECKED',
                     'FIRST200_CURRENT_MG0_FALSE_PASS:'+rid)
                counts['CURRENT_ATTEMPT_MG0_NOT_CHECKED']+=1
            if not native:
                counts['DUE_NO_REVIEWED_NATIVE_IMPLEMENTATION']+=1
        issues=[]
        if want=='DUE':
            if not native:
                issues.append('PER_RULE_NATIVE_SEMANTIC_PREDICATE_NOT_YET_IMPLEMENTED')
            if rid not in plan.get('enrolled',{}):
                issues.append('CONTROLLER_PLAN_VERIFIER_NOT_ENROLLED')
            if rid in expected_compound:
                issues.append('COMPOSITE_CLAUSES_NOT_INDEPENDENTLY_VERIFIED')
            if mg=='FAIL':
                issues.append('REAL_CURRENT_ATTEMPT_MG0_FAILURE')
            else:
                issues.append('NO_INDEPENDENT_CURRENT_ATTEMPT_MG0_PASS')
            if doc_result=='DOCUMENTARY_FAIL':
                issues.append('HISTORICAL_R173_DOCUMENTARY_CRITERIA_FAIL')
            issues.append('CURRENT_WORK_SEMANTIC_PROOF_NOT_CONFIRMED')
        rows[rid] = {
            'rule_id':rid,'requirement_sha256':entry['requirement_sha256'],
            'source_sha256':entry['source_sha256'],
            'evidence_family':contract,
            'required_rule_specific_proof':entry['questions'],
            'composite_subcontrol_count':compound['due_composites'][rid]['source_subcheck_count']
                  if rid in expected_compound else 0,
            'applicability':want,
            'native_predicate_registered':native,
            'historical_documentary_verdict':doc_result,
            'historical_documentary_checks':doc['documentary_checks'] if doc else None,
            'current_attempt_mg0':mg,
            'operational_semantic_verdict':'FAIL' if mg=='FAIL' else 'UNKNOWN'
                         if want=='DUE' else 'NOT_DUE',
            'evidence_gap':issues,'production_pass':False,
        }
    need(len(rows)==200 and set(rows)==set(selected)
         and sum(counts[k] for k in ('DOCUMENTARY_PASS_SCOPE_LIMITED',
                                    'DOCUMENTARY_FAIL','DOCUMENTARY_NOT_EVALUATED'))==200,
         'FIRST200_INCOMPLETE_RESULTS')
    segments=[]
    for n in range(0,200,100):
        keys=selected[n:n+100]
        segments.append({'part':n//100+1,'rule_count':100,
                         'rule_ids_sha256':digest(keys),
                         'rules_sha256':digest({k:rows[k] for k in keys})})
    return {'schema':SCHEMA,'catalog_rule_count':200,'rule_count':200,
            'first_rule_id':selected[0],'last_rule_id':selected[-1],
            'source_order_sha256':digest(selected),
            'canonical_master_sha256':inventory['canonical_master_sha256'],
            'documentary_source_sha256':documentary_sha,
            'actual_current_attempt_mg0_readback':mg0_rows is not None,
            'counts':counts,'segments':segments,'rules':rows,
            'newly_operational_native_semantic_verifiers':0,
            'independent_work_mg0_passes':0,'advancement_authorized':False,
            'status':'BATCH_PROOF_EXECUTED_INDIVIDUAL_NATIVE_GAPS_REMAIN'}
