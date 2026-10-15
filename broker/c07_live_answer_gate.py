"""C07 assistant-answer gate for a Controller-enrolled exact operation.

Not a validator and not an authorization: self-reported YES never means PASS.
All applicability comes from the Controller plan and pinned canonical inventory.
The caller writes the resulting record through the Controller append-only audit.
"""
import hashlib
import json

import c07_answer_semantics as answer_contract
import c07_operation_scope as scope


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode('utf-8')).hexdigest()



def challenge(inventory, plan, work, checkpoint):
    """Read-only questions due now from Controller authority, not assistant scope.

    Emit a machine-readable answer request. This is not approval of an attempt
    or independent proof of a 3D operation. No Git/Library asset transfer.
    """
    if not isinstance(checkpoint, dict) or type(checkpoint.get('next_step')) is not int:
        raise ValueError('C07_TRUSTED_CHECKPOINT_REQUIRED')
    due = scope.inspect(inventory, plan)['due']
    ledger = answer_contract.build(inventory)
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
        'compound_due': sorted({q['rule_id'] for q in questions
                                if q['compound_subchecks_pending']}),
        'questions': questions,
        'answer_packet_schema_fields': [
            'rule_id', 'question_id', 'requirement_sha256', 'master_sha256',
            'attempt_id', 'operation_sha256', 'answer', 'statement', 'evidence_refs'],
        'native_rule_mg0_verified': False,
        'advancement_authorized': False,
    }

def inspect(inventory, plan, work, packets, checkpoint):
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
    reasons = []
    if failures:
        reasons.append('ADMITTED_DEFECT_OR_UNPERFORMED_CHECK')
    if missing:
        reasons.append('DUE_QUESTIONS_NOT_ANSWERED')
    if compound:
        reasons.append('COMPOUND_RULES_REQUIRE_INDEPENDENT_SUBCHECKS')
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
        'answered': assessed['answered'],
        'failed': failures,
        'missing': missing,
        'compound_subchecks_unverified': compound,
        'unverified_evidence_refs': [
            {'question_id': packet['question_id'], 'evidence_refs': packet['evidence_refs']}
            for packet in packets if packet['evidence_refs']],
        'source_bindings_validated': True,
        'individual_mg0_verified': False,
        'independent_semantics_verified': False,
        'answer_verdict': 'FAIL' if failures else 'UNKNOWN',
        'blocking_reasons': reasons,
        'may_request_native_proof': not reasons,
        'advancement_authorized': False,
        'next_required_action': ('CORRECT_FAILED_QUESTIONS' if failures else
                                 'SUBMIT_MISSING_DUE_ANSWERS' if missing else
                                 'IMPLEMENT_AND_VERIFY_COMPOUND_SUBCHECKS' if compound else
                                 'REQUEST_INDEPENDENT_NATIVE_RULE_AND_MG0_PROOF'),
    }
