"""C07 source-verified 200-rule batches over the full canonical 763 IDs.

Independent meaning: source/wording applicability *only*. The canonical source
reader and Controller plan are trusted inputs, never the assistant's PASS list.
The existing native Controller remains sole authority for work/MG0 progress.
Unverified semantics stay UNKNOWN; 12 installed predicates are not 12 passes.
"""
import hashlib
import json

import c07_answer_semantics as answers
import c07_compound_subchecks as compound
import c07_operation_scope as scope
from approved_validators import REVIEWED

BATCH_SIZE = 200

class BatchBlocked(ValueError):
    pass

def need(ok, why):
    if not ok:
        raise BatchBlocked(why)

def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False,
                                    separators=(',', ':')).encode('utf-8')).hexdigest()

def inspect(inventory, plan, *, batch_size=BATCH_SIZE, mg0=None):
    """Read all 763 immutable rules, in ordered, auditable 200-rule segments.

    `mg0` is an optional real verified report from c07_mg0_individual.inspect_batch
    for the same Controller asset/attempt and complete DUE set; user-supplied
    PASS maps are never accepted.
    """
    need(type(batch_size) is int and batch_size in (100, 200),
         'C07_BATCH_CHUNK_SIZE_MUST_BE_100_OR_200')
    need(inventory.get('schema') == 'gg-effective-family-inventory-v1' and
         inventory.get('rule_count') == 763, 'C07_BATCH_CANONICAL_763_REQUIRED')
    canonical = [rid for ids in inventory['families'].values() for rid in ids]
    need(len(canonical) == 763 and len(set(canonical)) == 763 and
         set(canonical) == set(inventory['rules']), 'C07_BATCH_CANONICAL_SET_DRIFT')

    # Both validators independently reconstruct requirements and the exact
    # 758 revised yes/no phrasings from pinned canonical Git/Library sources.
    ledger = answers.build(inventory)
    need(ledger['rule_count'] == 763 and ledger['wording_reviewed_count'] == 758
         and ledger['reviewed_count'] == 5 and ledger['generic_count'] == 0
         and ledger['compound_pending_count'] == 72,
         'C07_BATCH_758_5_72_REVIEW_DRIFT')
    application = scope.inspect(inventory, plan)
    due = set(application['due'])
    composite = compound.inspect(inventory, application['due'])
    all_composite = compound.ids(inventory)
    need(composite['canonical_composite_count'] == 72 and
         set(composite['due_composites']) == (all_composite & due),
         'C07_BATCH_COMPOSITES_MISSING')

    if mg0 is not None:
        # The only optional MG0 input is the output of trusted real-audit
        # readback. Fail closed on an invented PASS, cross-work or partial map.
        need(mg0.get('schema') == 'gg-c07-mg0-canonical-batch-readback-v1' and
             mg0.get('master_sha256') == inventory['canonical_master_sha256']
             and mg0.get('rule_count') == len(due)
             and set(mg0.get('rules', {})) == due
             and mg0.get('advancement_authorized') is False
             and mg0.get('individual_mg0_passes') == 0
             and mg0.get('counts', {}).get('PASS') == 0
             and set(mg0.get('failed_rule_ids', [])) <= due
             and mg0.get('rule_ids_sha256') == digest(application['due'])
             and mg0.get('attempt_id') == plan.get('attempt_id')
             and mg0.get('audit_sha256') == plan.get('audit_sha256'),
             'C07_BATCH_UNTRUSTED_MG0_BINDING')
        for rid, row in mg0['rules'].items():
            need(row.get('verdict') in ('FAIL', 'UNKNOWN') and
                 (rid in mg0['failed_rule_ids']) == (row['verdict'] == 'FAIL'),
                 'C07_BATCH_FORGED_MG0_VERDICT:'+rid)
    categories = {'DUE': 0, 'FUTURE_PHASE': 0, 'N_A': 0, 'N_A_CONTEXT': 0}
    output = []
    checked = []
    for offset in range(0, len(canonical), batch_size):
        ids = canonical[offset:offset+batch_size]
        rows = {}
        for rid in ids:
            entry = ledger['entries'][rid]
            base = application['by_rule'][rid]
            status = base['disposition']
            categories[status] += 1
            reviewer = REVIEWED.get(rid)
            clauses = composite['due_composites'].get(rid)
            # Missing source-specific validators and untested subchecks are
            # explicit separate obligations, never auto-generated PASS flags.
            mg0_status = (mg0['rules'][rid]['verdict'] if
                          mg0 is not None and rid in due else 'UNKNOWN'
                          if rid in due else 'NOT_DUE')
            blockers = []
            if status == 'DUE':
                if reviewer is None:
                    blockers.append('NO_REVIEWED_NATIVE_SEMANTIC_IMPLEMENTATION')
                if rid not in plan.get('enrolled', {}):
                    blockers.append('NOT_ENROLLED_IN_CONTROLLER_PLAN')
                if clauses:
                    blockers.append('COMPOSITE_CLAUSES_UNVERIFIED')
                if mg0_status == 'FAIL':
                    blockers.append('OBSERVED_MG0_PROCESS_FAILURE')
                elif mg0_status == 'UNKNOWN':
                    blockers.append('CURRENT_ATTEMPT_INDEPENDENT_MG0_MISSING')
                blockers.append('CURRENT_ASSET_INDEPENDENT_SEMANTIC_PROOF_NOT_SUPPLIED')
            row = {
                'rule_id': rid, 'family': entry['family'],
                'requirement_sha256': entry['requirement_sha256'],
                'source_sha256': entry['source_sha256'],
                'source_and_question_readback': 'PASS',
                'question': [v['text'] for v in entry['questions']],
                'question_classification': entry['classification'],
                'source_question_count': len(entry['questions']),
                'applicability': status,
                'reviewed_native_implementation': reviewer is not None,
                'reviewed_native_criteria': list(reviewer[1]) if reviewer else [],
                'composite_subcheck_count': clauses['source_subcheck_count'] if clauses else 0,
                'composite_decomposition': clauses['source_decomposition'] if clauses else None,
                'individual_mg0': mg0_status,
                'current_asset_semantic_verdict': 'UNKNOWN' if status == 'DUE'
                                                  else 'NOT_DUE',
                'blockers': blockers,
                'work_advancement_authorized': False,
            }
            rows[rid] = row
            checked.append(rid)
        output.append({
            'batch': len(output)+1, 'from_index': offset+1,
            'to_index': offset+len(ids), 'count': len(ids),
            'first_rule_id': ids[0], 'last_rule_id': ids[-1],
            'source_question_readback_pass': len(ids),
            'operational_semantic_mg0_pass': 0,
            'due_without_native': sum(r['applicability']=='DUE' and
                                      not r['reviewed_native_implementation']
                                      for r in rows.values()),
            'due_mg0_fail': sum(r['individual_mg0']=='FAIL'
                               for r in rows.values()),
            'rule_ids_sha256': digest(ids),
            'rows_sha256': digest(rows), 'rules': rows,
        })
    need(len(output) == (4 if batch_size == 200 else 8)
         and len(checked) == 763 and set(checked) == set(canonical)
         and sum(v['count'] for v in output) == 763,
         'C07_BATCH_763_NOT_ALL_CHECKED')
    need(categories['DUE'] == len(due) and
         categories['FUTURE_PHASE'] == len(application['future_phase']) and
         categories['N_A'] == len(application['not_applicable']) and
         categories['N_A_CONTEXT'] == len(application['context_excluded']),
         'C07_BATCH_APPLICABILITY_TOTAL_DRIFT')
    need(sum(categories.values()) == 763, 'C07_BATCH_MISSING_RULE')
    need(sum(r['due_without_native'] for r in output) ==
         len(application['due_without_reviewed_native_verifier']),
         'C07_BATCH_REVIEWED_IMPLEMENTATION_COVERAGE_DRIFT')
    return {
        'schema': 'gg-c07-trusted-batch-200-v1',
        'master_sha256': inventory['canonical_master_sha256'],
        'reviewed_canonical_source_rules': 763,
        'reviewed_yes_no_questions': 758,
        'previously_reviewed_questions': 5,
        'canonical_composites': 72,
        'due_composites': composite['due_composite_count'],
        'applicability': categories,
        'registered_native_implementations': len(REVIEWED),
        'due_without_native_implementation': len(
            application['due_without_reviewed_native_verifier']),
        'independent_semantic_and_mg0_passes': 0,
        'current_operation_approved': False,
        'batch_size': batch_size, 'batch_count': len(output),
        'full_ordered_rule_ids_sha256': digest(canonical),
        'rule_coverage_complete': True,
        'meaning': 'SOURCE_AND_QUESTION_STRUCTURE_PASS_ONLY_NOT_ASSET_MG0_PASS',
        'batches': output,
        'advancement_authorized': False,
    }
