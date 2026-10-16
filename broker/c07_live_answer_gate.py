"""C07 assistant-answer gate for a Controller-enrolled exact operation.

Not a validator and not an authorization: self-reported YES never means PASS.
All applicability comes from the Controller plan and pinned canonical inventory.
The caller writes the resulting record through the Controller append-only audit.
"""
import hashlib
import json

import c07_answer_semantics as answer_contract
import c07_operation_scope as scope
import c07_compound_subchecks as composites


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode('utf-8')).hexdigest()



def compact_composites(contract):
    """Small reproducible index; never copy hundreds of source clauses into audit."""
    if contract is None:
        return {}
    return {
        rid: {
            'family': row['family'],
            'source_sha256': row['source_sha256'],
            'requirement_sha256': row['requirement_sha256'],
            'source_decomposition': row['source_decomposition'],
            'source_subcheck_count': row['source_subcheck_count'],
            'subcheck_index_sha256': digest([
                (q['subcheck_id'], q['clause_sha256']) for q in row['subchecks']]),
            'independent_verifier_ready': False,
        }
        for rid, row in contract['due_composites'].items()
    }


def challenge(inventory, plan, work, checkpoint, *,
              detail_rule=None, subcheck_offset=0, subcheck_limit=20):
    """Read-only questions due now from Controller authority, not assistant scope.

    Emit a machine-readable answer request. This is not approval of an attempt
    or independent proof of a 3D operation. No Git/Library asset transfer.
    """
    if not isinstance(checkpoint, dict) or type(checkpoint.get('next_step')) is not int:
        raise ValueError('C07_TRUSTED_CHECKPOINT_REQUIRED')
    applicability = scope.inspect(inventory, plan)
    due = applicability['due']
    ledger = answer_contract.build(inventory)
    compound_contract = composites.inspect(inventory, due) if inventory.get('rule_count') == 763 else None
    if detail_rule is not None:
        if detail_rule not in due or not compound_contract or detail_rule not in compound_contract['due_composites']:
            raise ValueError('C07_SUBCHECK_VIEW_NOT_DUE')
        if (type(subcheck_offset) is not int or subcheck_offset < 0 or
            type(subcheck_limit) is not int or not 1 <= subcheck_limit <= 50):
            raise ValueError('C07_SUBCHECK_PAGE_INVALID')
        selected = compound_contract['due_composites'][detail_rule]['subchecks']
        view = selected[subcheck_offset:subcheck_offset + subcheck_limit]
        detailed = {'rule_id': detail_rule, 'offset': subcheck_offset,
                    'total': len(selected), 'next_offset':
                    subcheck_offset + len(view) if subcheck_offset + len(view) < len(selected) else None,
                    'subchecks': view}
    else:
        detailed = None
    questions = []
    for rid in due:
        entry = ledger['entries'][rid]
        for question in entry['questions']:
            questions.append({
                'rule_id': rid, 'family': entry['family'],
                'question_id': question['id'], 'type': question['type'],
                'question': question['text'],
                'source_sha256': entry['source_sha256'],
                'requirement_sha256': entry['requirement_sha256'],
                'compound_subchecks_pending': entry['compound_subchecks_pending'],
                'evidence_required_for_independent_pass': True,
            })
    return {
        'schema': 'gg-c07-controller-question-batch-v1',
        'asset': checkpoint['asset'], 'phase': work['phase'],
        'master_sha256': work['master_sha256'],
        'work_item_sha256': work['work_item_sha256'],
        'attempt_id': work['attempt_id'],
        'attempt_number': work['attempt_number'],
        'previous_attempt_id': work['previous_attempt_id'],
        'operation_sha256': work['operation_sha256'],
        'checkpoint': checkpoint,
        'plan_record_hash': checkpoint['plan_record_hash'],
        'due_rules_sha256': digest(due),
        'question_count': len(questions),
        'canonical_question_bank_size': applicability.get('base_questions_accounted_for', 0),
        'context_excluded_question_ids': applicability.get('context_excluded', []),
        'context_exclusion_reasons': applicability.get('context_exclusions_with_reasons', {}),
        'context_exclusion_never_pass': True,
        'compound_due': sorted({q['rule_id'] for q in questions
                                if q['compound_subchecks_pending']}),
        'compound_source_subchecks': compact_composites(compound_contract),
        'selected_source_subcheck_page': detailed,
        'compound_source_count': compound_contract['canonical_composite_count'] if compound_contract else 0,
        'compound_independent_semantic_proof': False,
        'questions': questions,
        'answer_packet_schema_fields': [
            'rule_id', 'question_id', 'requirement_sha256', 'master_sha256',
            'attempt_id', 'operation_sha256', 'answer', 'statement', 'evidence_refs'],
        'native_rule_mg0_verified': False,
        'advancement_authorized': False,
    }

def inspect(inventory, plan, work, packets, checkpoint, subcheck_packets=None):
    """Return a reviewable STOP/continuation report, never a work PASS.

    plan is the enrolled/approved Controller plan, not producer-supplied
    applicability; work comes from ControlledJudgment.prepare under its lock.
    A referenced SHA is NOT independent verification of its claimed contents.
    """
    if not isinstance(packets, list):
        raise ValueError('C07_ASSISTANT_ANSWERS_REQUIRED')
    if not isinstance(checkpoint, dict) or type(checkpoint.get('next_step')) is not int:
        raise ValueError('C07_TRUSTED_CHECKPOINT_REQUIRED')
    trusted = scope.inspect(inventory, plan)
    ledger = answer_contract.build(inventory)
    due = trusted['due']
    assessed = answer_contract.assess(
        ledger, due, packets, attempt_id=work['attempt_id'],
        operation_sha256=work['operation_sha256'])
    failures = []
    for qid in assessed['failed']:
        rid = qid.split(':', 1)[0]
        info = assessed['answered'][qid]
        failures.append({
            'rule_id': rid, 'question_id': qid, 'answer': info['answer'],
            'reason': info['reason'], 'required_correction':
            'REPAIR_OR_PERFORM_THE_ADMITTED_MISSING_REQUIREMENT_AND_RESUBMIT_PROOF',
            'requirement_sha256': ledger['entries'][rid]['requirement_sha256']})
    missing = [{'rule_id': qid.split(':', 1)[0], 'question_id': qid,
                'required_correction': 'ANSWER_THIS_DUE_QUESTION'}
               for qid in assessed['missing']]
    compound = [rid for rid in due if ledger['entries'][rid]['compound_subchecks_pending']]
    composite_contract = (composites.inspect(inventory, due)
                          if inventory.get('rule_count') == 763 else None)
    composite_answers = (composites.assess(
        composite_contract, subcheck_packets if subcheck_packets is not None else [],
        attempt_id=work['attempt_id'], operation_sha256=work['operation_sha256'])
        if composite_contract else None)
    # A producer's admitted NO on a canonical composite subcontrol is a
    # failure, even if every top-level question was answered positively.
    # Preserve both failure channels for Controller audit and correction lineage.
    compound_failures = composite_answers['failed'] if composite_answers else []
    reasons = []
    if failures:
        reasons.append('ADMITTED_DEFECT_OR_UNPERFORMED_CHECK')
    if missing:
        reasons.append('DUE_QUESTIONS_NOT_ANSWERED')
    if compound:
        reasons.append('COMPOUND_RULES_REQUIRE_INDEPENDENT_SUBCHECKS')
    if composite_answers and composite_answers['failed']:
        reasons.append('ADMITTED_COMPOUND_SUBCONTROL_FAILURE')
    if composite_answers and composite_answers['missing']:
        reasons.append('MISSING_COMPOUND_SUBCONTROL_ANSWERS')
    if composite_answers:
        # Exact missing IDs are reconstructible from the pinned canonical
        # source. Keep the first page and its digest, not hundreds of copies.
        all_missing = composite_answers['missing']
        composite_answers = {
            **composite_answers,
            'missing': all_missing[:20],
            'missing_total': len(all_missing),
            'missing_sha256': digest(all_missing),
            'missing_truncated': len(all_missing) > 20,
        }
    # Even full positive answers are still UNKNOWN. A separate native validator
    # and individually checked MG0 must determine actual eligibility.
    return {
        'schema': 'gg-c07-live-answer-gate-v1',
        'asset': checkpoint['asset'],
        'phase': work['phase'],
        'master_sha256': work['master_sha256'],
        'work_item_sha256': work['work_item_sha256'],
        'attempt_id': work['attempt_id'],
        'attempt_number': work['attempt_number'],
        'previous_attempt_id': work['previous_attempt_id'],
        'operation_sha256': work['operation_sha256'],
        'checkpoint': checkpoint,
        'plan_record_hash': checkpoint['plan_record_hash'],
        'answer_packets_sha256': digest(packets),
        'due_rule_ids_sha256': digest(due),
        'canonical_question_bank_size': trusted.get('base_questions_accounted_for', 0),
        'context_excluded_question_ids': trusted.get('context_excluded', []),
        'context_exclusion_reasons': trusted.get('context_exclusions_with_reasons', {}),
        'context_exclusion_never_pass': True,
        'answered': assessed['answered'],
        'failed': failures,
        'failed_subchecks': compound_failures,
        'admitted_failure_total': len(failures) + len(compound_failures),
        'missing': missing,
        'compound_subchecks_unverified': compound,
        'compound_source_subchecks': compact_composites(composite_contract),
        'compound_answer_assessment': composite_answers,
        'unverified_evidence_refs': [
            {'question_id': packet['question_id'], 'evidence_refs': packet['evidence_refs']}
            for packet in packets if packet['evidence_refs']],
        'source_bindings_validated': True,
        'individual_mg0_verified': False,
        'independent_semantics_verified': False,
        'answer_verdict': 'FAIL' if failures or compound_failures else 'UNKNOWN',
        'blocking_reasons': reasons,
        'may_request_native_proof': not reasons,
        'advancement_authorized': False,
        'next_required_action': ('CORRECT_FAILED_QUESTIONS' if failures else
                                 'CORRECT_FAILED_SUBCHECKS' if compound_failures else
                                 'SUBMIT_MISSING_DUE_ANSWERS' if missing else
                                 'IMPLEMENT_AND_VERIFY_COMPOUND_SUBCHECKS' if compound else
                                 'REQUEST_INDEPENDENT_NATIVE_RULE_AND_MG0_PROOF'),
    }
