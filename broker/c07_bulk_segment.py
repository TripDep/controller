"""C07: independent source-/attempt-bound semantic execution for 200-ID windows.

Use one independent SHA-validated audit for the whole window, not 200 user
answers passed as positive proofs. Counterpart to c07_bulk200_semantics R115:
this consumer specializes the other 563 rules (behaviour, G0, governance,
questions, system clauses). Machine-observable process integrity is scoped;
it cannot prove a subjective, visual, policy, individual MG0 or owner claim.
"""
import hashlib
import json
from collections import Counter

from c07_negative_semantic_replay import audit_readback, inspect as replay_negatives
from approved_validators import REVIEWED
import c07_answer_semantics as answer_contract
import c07_compound_subchecks as composite
import c07_operation_scope as scope

SCHEMA = 'gg-c07-bulk-remaining-segment-evidence-v1'
STARTS={2:200,3:400,4:600}
LENGTHS={2:200,3:200,4:163}
BOUNDS={2:('AAA-200-T-199','G4'),
        3:('GOLDEN_CONTROLLER','Q-150'),
        4:('Q-151','WORK_STATE')}
# Evidence mechanisms are independent of question wording; a valid source
# or an attested audit event can be a PARTIAL observation, never entire PASS.
FAMILY_CHANNELS={
  'AAA-200':('CANONICAL_ASSET_SCOPE','SIGNED_SOURCE_DEPENDENCIES','INDIVIDUAL_MG0'),
  'BEHAVIOR_110':('EXACT_SOURCE_BEHAVIOR_RULE','TRUSTED_OPERATION_AUDIT','OWNER_OR_NATIVE_OBSERVATION'),
  'G0_CONTROLS':('CANONICAL_G0_CRITERION','CURRENT_CONTROLLER_AUDIT','INDEPENDENT_GATE_CHECK'),
  'QUESTIONS_300':('CANONICAL_QUESTION_POLARITY','SOURCE_BOUND_ANSWER','INDEPENDENT_NATIVE_CONFIRMATION'),
  'MASTER_CHAIN':('CANONICAL_MASTER','CURRENT_AUDIT','AUTHORIZED_PHASE_SEQUENCE'),
  'EXECUTION':('ORIGINAL_ARTIFACT_BYTES','ORIGINAL_CONTROLLER_AUDIT','NATIVE_PROCESS_REPLAY'),
  'GOVERNANCE':('CANONICAL_POLICY_SOURCE','CURRENT_CONTROLLER_AUDIT','OWNER_AUTHORIZATION'),
  'DELIVERY':('ACTUAL_DELIVERY_BYTES','REGISTERED_ASSET_AUDIT','INDEPENDENT_OWNER_ACCEPTANCE'),
  'DESIGN_STANDARDS':('ORIGINAL_VISUAL_ASSET','MULTIVIEW_VISUAL_QA','DESIGN_REFERENCE'),
  'GLOBAL_GATES':('CANONICAL_GATE_REQUIREMENTS','CONTROLLER_GATE_EVIDENCE','INDEPENDENT_REVIEW'),
}
FALLBACK_CHANNELS=('CANONICAL_RULE_SOURCE','EXACT_ATTEMPT_AUDIT','INDEPENDENT_SEMANTIC_QA')

class SourceBlocked(ValueError): pass

def need(ok, why):
    if not ok: raise SourceBlocked(why)

def checksum(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,ensure_ascii=False,
             allow_nan=False,separators=(',',':')).encode('utf-8')).hexdigest()

def _slice(inventory, segment):
    need(type(segment) is int and segment in STARTS,'C07_UNSUPPORTED_SEGMENT')
    need(type(inventory) is dict and inventory.get('schema')=='gg-effective-family-inventory-v1'
         and inventory.get('rule_count')==763 and type(inventory.get('families')) is dict
         and type(inventory.get('rules')) is dict,'C07_CANONICAL_763_REQUIRED')
    ids=[v for vs in inventory['families'].values() for v in vs]
    need(len(ids)==len(set(ids))==763 and set(ids)==set(inventory['rules']),
         'C07_CANONICAL_MEMBERSHIP_CHANGED')
    order=sorted(ids)
    selected=order[STARTS[segment]:STARTS[segment]+LENGTHS[segment]]
    need(len(selected)==LENGTHS[segment] and
         (selected[0],selected[-1])==BOUNDS[segment],
         'C07_SEGMENT_SOURCE_BOUNDARY_DRIFT')
    return selected

def inspect(inventory,plan,*,segment,audit_raw=None,asset=None,attempt_id=None,
            operation_sha256=None):
    """Evaluate 200 (last: 163) separately source-bound semantic obligations.

    An actually supplied Controller audit is independently rehashed once and
    replayed against the exact attempt by R112/R113. Failed source-linked
    obligations stay FAIL; a green chain is only scoped process integrity.
    Source-only test has UNKNOWN for current work, never historical PASS.
    """
    selected=_slice(inventory,segment)
    applicability=scope.inspect(inventory,plan)
    ledger=answer_contract.build(inventory)
    need(ledger['rule_count']==763 and set(applicability['by_rule'])==set(inventory['rules']),
         'C07_SCOPE_AND_QUESTIONS_CANONICAL_BINDING')
    due=set(applicability['due'])
    compound_report=composite.inspect(inventory,sorted(due.intersection(selected)))
    observed=None
    original_chain=None
    question_evidence={}
    if any(x is not None for x in (audit_raw,asset,attempt_id,operation_sha256)):
        need(type(audit_raw) is bytes and type(asset) is str and
             type(attempt_id) is str and type(operation_sha256) is str,
             'C07_AUDIT_SOURCE_ALL_OR_NOTHING')
        records, tail=audit_readback(audit_raw,asset)
        need(len(records)>0 and isinstance(tail,str) and len(tail)==64,
             'C07_AUDIT_VALID_CHAIN_REQUIRED')
        # Validate the Q-xxx recorded answer *identity*, independent of the
        # producer's alleged YES/PASS. There is no positive semantic pass.
        for event in records:
            if event.get('event')!='SUPERVISOR_ASSISTANT_ANSWER_GATE':
                continue
            report=event.get('report')
            if type(report) is not dict or report.get('attempt_id')!=attempt_id:
                continue
            need(report.get('master_sha256')==inventory['canonical_master_sha256'] and
                 report.get('operation_sha256')==operation_sha256 and
                 type(report.get('answered')) is dict and
                 report.get('advancement_authorized') is False,
                 'C07_QUESTION_AUDIT_EXACT_OPERATION_INVALID')
            # Every answer ID and rule association is checked against the
            # complete immutable reviewed-question ledger, not self-described.
            valid={q['id']:rid for rid in due
                   for q in ledger['entries'][rid]['questions']}
            for question_id,answer in report['answered'].items():
                need(question_id in valid and type(answer) is dict and
                     answer.get('status') in ('FAIL','UNKNOWN'),
                     'C07_QUESTION_AUDIT_UNREVIEWED_OR_FALSE_PASS')
                if question_id in question_evidence:
                    need(question_evidence[question_id]['answer']==answer,
                         'C07_QUESTION_AUDIT_CONTRADICTORY_REPLAY')
                else:
                    question_evidence[question_id]={
                        'answer':answer,'rule_id':valid[question_id],
                        'source_record_hash':event['record_hash']}
        observed=replay_negatives(inventory,plan,audit_raw,asset,attempt_id,
                                  operation_sha256=operation_sha256)
        need(observed['rule_count']==763 and
             observed['batch_counts']==[200,200,200,163] and
             observed['individual_mg0_passes']==0 and
             observed['advancement_authorized'] is False,
             'C07_NEGATIVE_READBACK_MISMATCH')
        original_chain={'original_audit_sha256':hashlib.sha256(audit_raw).hexdigest(),
                       'record_count':len(records),'last_record_hash':tail,
                       'observed_process_integrity':'ORIGINAL_AUDIT_CHAIN_VERIFIED'}
    negatives={rid:row for batch in observed['batches'] for rid,row in batch['rules'].items()} if observed else {}
    need(not observed or len(negatives)==763,'C07_ALL_NEGATIVE_RULES_REQUIRED')
    counters=Counter()
    rows={}
    for rid in selected:
        source=inventory['rules'][rid]
        contract=ledger['entries'][rid]
        need(rid in inventory['families'][source['family']] and
             contract['requirement_sha256']==source['requirement_sha256'] and
             contract['source_sha256']==source['source_sha256'],
             'C07_INDIVIDUAL_CANONICAL_REQUIREMENT_DRIFT:'+rid)
        family=source['family']
        actual_status=applicability['by_rule'][rid]['disposition']
        is_due=actual_status=='DUE'
        witness=negatives.get(rid, {}) if is_due else {}
        negative_status=witness.get('semantic_negative_verdict','UNKNOWN')
        if is_due and negative_status=='FAIL':
            verdict='FAIL'
        elif is_due and negative_status=='UNKNOWN_REVIEW_NOT_AUTHENTICATED':
            verdict='UNKNOWN_REVIEW_NOT_AUTHENTICATED'
        else:verdict='UNKNOWN' if is_due else 'NOT_DUE'
        # Explicit group-specific native observation: proving the original
        # hash-chained audit says nothing about whether each rule was obeyed.
        if rid=='APPEND_ONLY_AUDIT' and original_chain is not None:
            process='ORIGINAL_CHAIN_INTEGRITY_OBSERVED_SCOPE_ONLY'
            counters['PROCESS_INTEGRITY_PREDICATE_EXECUTED']+=1
        else:process='UNOBSERVED'
        is_compound=rid in compound_report['due_composites']
        relevant_native=rid in REVIEWED
        if is_due and not relevant_native:counters['MISSING_REVIEWED_POSITIVE_VERIFIER']+=1
        if is_due and is_compound:counters['DUE_COMPOSITES_WITHOUT_INDEPENDENT_SUBCHECK_PASS']+=1
        counters['DUE' if is_due else 'NOT_DUE']+=1
        counters['FAIL' if verdict=='FAIL' else 'UNKNOWN' if is_due else 'FUTURE_OR_NA']+=1
        if family=='QUESTIONS_300':
            counters['QUESTION_SOURCE_CONTRACTS_EXECUTED']+=1
            if is_due and original_chain is not None:
                ids=[q['id'] for q in contract['questions']]
                counters['QUESTION_SOURCE_RESPONSES_AUDITED']+=sum(
                    q in question_evidence for q in ids)
                counters['QUESTION_SOURCE_RESPONSES_STILL_MISSING']+=sum(
                    q not in question_evidence for q in ids)
        if family=='BEHAVIOR_110':counters['BEHAVIOR_SOURCE_CONTRACTS_EXECUTED']+=1
        if family=='G0_CONTROLS':counters['G0_GATE_SOURCE_CONTRACTS_EXECUTED']+=1
        rows[rid]={
            'family':family,'requirement_sha256':source['requirement_sha256'],
            'source_sha256':source['source_sha256'],
            'question_source_contracts':contract['questions'],
            'source_bound_answer_audit':[{
                'question_id':q['id'],
                'source_record_hash':question_evidence[q['id']]['source_record_hash'],
                'independent_native_confirmation':False}
                for q in contract['questions'] if q['id'] in question_evidence]
                if family=='QUESTIONS_300' and is_due else [],
            'native_positive_verifier_implemented':relevant_native,
            'native_positive_current_attempt_proof':'NOT_VERIFIED',
            'evidence_channels':list(FAMILY_CHANNELS.get(family,FALLBACK_CHANNELS)),
            'composite_subcontrols_from_source':compound_report['due_composites'].get(rid,{}).get('source_subcheck_count',0),
            'source_scope_applicability':actual_status,
            'historical_current_audit_verified':original_chain is not None,
            'machine_process_observation':process,
            'negative_observation':negative_status if is_due else 'NOT_DUE',
            'source_bound_failures':witness.get('native_negative_evidence',[]) if is_due else [],
            'real_current_attempt_semantic_result':verdict,
            'individual_mg0':'UNKNOWN' if is_due else 'NOT_DUE',
            'current_asset_pass':False,'advancement_authorized':False,
        }
    need(len(rows)==LENGTHS[segment] and
         counters['DUE']+counters['NOT_DUE']==len(rows),
         'C07_SEGMENT_INCOMPLETE')
    chunks=[]
    for i in range(0,len(selected),100):
        ids=selected[i:i+100]
        chunks.append({'part':1+i//100,'count':len(ids),
                       'source_ids_sha256':checksum(ids),
                       'result_sha256':checksum({k:rows[k] for k in ids})})
    failures=sorted(r for r in selected if rows[r]['real_current_attempt_semantic_result']=='FAIL')
    return {'schema':SCHEMA,'segment':segment,
       'source_rule_count':len(selected), 'source_rule_ids_sha256':checksum(selected),
       'first_rule_id':selected[0],'last_rule_id':selected[-1],
       'actual_controller_audit_scanned':original_chain is not None,
       'source_chain':original_chain,'counts':dict(counters),
       'chunks':chunks,'rules':rows,'failed_due_rule_ids':failures,
       'independent_current_asset_pass_count':0,
       'individual_mg0_pass_count':0,
       'advancement_authorized':False,
       'positive_200_rule_certification':False,
       'phase':'PROVEN_NEGATIVE_AND_SOURCE_CONTRACTS_NOT_FULL_SEMANTIC_COMPLETION'}
