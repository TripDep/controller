"""MG0 source-derived, individual-rule evidence review.

Reads ALL five canonical process-falsification triggers from the pinned Master
and verifies actual Golden Controller hash-chained events. Correlations are
evidence of a trigger, not independent verification of the owner's identity.
Missing independent observation NEVER means that a trigger is false or that MG0
passed. This module cannot issue an operational PASS by itself.
"""
from collections import Counter, defaultdict
import hashlib
import json

from real_work_intake import audit_check, require, sha

TRIGGERS = (
    'a significant error reaches the user despite previous PASS states;',
    'something was VERIFIED but later proves it should not have been;',
    'the user rapidly finds something the assistant should have found autonomously;',
    'two or more errors reveal the same pattern;',
    'a formally compliant process still produces a mediocre or non-deliverable result.',
)
EVENTS = ('STEP_CLOSE','USER_REVIEW','VERIFIED_STATE_REVOKED',
          'QUALITY_FINDING','DELIVERY_GATE_CHECK','MG0_BASELINE_PASS',
          'MG0_PROCESS_ROOT_CAUSE','MG0_PROCESS_CORRECTION',
          'MG0_AFFECTED_STATES_INVALIDATED','MG0_RULE_REAPPLIED')



def _verify_master(master_raw, master_sha256):
    """Validate all five immutable MG0 triggers exactly once per batch."""
    require(sha(master_raw) == master_sha256, 'C07_MG0_MASTER_DRIFT')
    text = master_raw.decode('utf-8')
    section = text.split('## MG0 — PROCESS FALSIFICATION', 1)
    require(len(section) == 2, 'C07_MG0_CANONICAL_SECTION')
    body = section[1].split('\n## ', 1)[0]
    require(all(('- ' + phrase) in body for phrase in TRIGGERS),
            'C07_MG0_FIVE_CANONICAL_TRIGGERS_CHANGED')
    require('The response is not limited to fixing the asset.' in body and
            'invalidate affected states and reapply the corrected process' in body,
            'C07_MG0_CORRECTION_SOURCE_MISSING')

def _inspect_checked(rows, tail, audit_sha256, asset, master_sha256,
                     rule_id, attempt_id, scoped=None):
    """One rule over a validated shared audit; NEVER independently callable as proof."""
    require(isinstance(rule_id,str) and rule_id.strip() and
            isinstance(attempt_id,str) and len(attempt_id)==64 and
            all(c in '0123456789abcdef' for c in attempt_id),
            'C07_MG0_CURRENT_RULE_ATTEMPT')
    # Scope strictly to the exact rule and attempt; no historical ticket replay.
    scope = (scoped if scoped is not None else
             [r for r in rows if r.get('rule_id') == rule_id and
              r.get('attempt_id') == attempt_id])
    require(all(r.get('event') in EVENTS for r in scope),
            'C07_MG0_UNKNOWN_SCOPED_EVENT')
    completed = [r for r in scope if r.get('event') == 'STEP_CLOSE'
                 and r.get('result') == 'PASS']
    # A proper Controller already has one STEP_CLOSE per step. A later owner
    # review therefore references that real step through a scoped annotation,
    # rather than inventing a second close for the same step.
    prior_passes = {r['record_hash']:r for r in rows if
                    r.get('event')=='STEP_CLOSE' and r.get('result')=='PASS'}
    for evidence in scope:
        if evidence.get('event') != 'MG0_BASELINE_PASS':
            continue
        referenced = prior_passes.get(evidence.get('previous_pass_record_hash'))
        if referenced and rows.index(referenced) < rows.index(evidence):
            completed.append(evidence)
    owner_failures = [r for r in scope if r.get('event')=='USER_REVIEW'
                      and r.get('result')=='FAIL' and
                      r.get('detected_by')=='OWNER' and
                      isinstance(r.get('owner_evidence_sha256'),str) and
                      len(r['owner_evidence_sha256'])==64]
    trigger1 = [r for r in owner_failures
                if any(scope.index(p) < scope.index(r) for p in completed)]
    revoked = [r for r in scope if r.get('event')=='VERIFIED_STATE_REVOKED'
               and r.get('previous_verified_record_hash') in
                    {x['record_hash'] for x in completed}]
    trigger3 = [r for r in owner_failures if r.get('assistant_preflight_passed') is True]
    classes = Counter(r.get('failure_class') for r in scope if
                      r.get('event')=='QUALITY_FINDING' and
                      isinstance(r.get('failure_class'),str) and
                      r['failure_class'].strip())
    trigger4 = [r for r in scope if r.get('event')=='QUALITY_FINDING' and
                classes[r.get('failure_class')]>1]
    trigger5 = [r for r in scope if r.get('event')=='DELIVERY_GATE_CHECK' and
                r.get('result') in ('BLOCKED','FAIL') and
                any(scope.index(p)<scope.index(r) for p in completed)]
    signals=(trigger1,revoked,trigger3,trigger4,trigger5)
    found = sorted({r['record_hash'] for hits in signals for r in hits})
    # All corrections must have the SAME rule and attempt, explicitly link
    # to each observed failure record, and occur AFTER the corresponding event.
    corrections={}
    for found_hash in found:
        origin=next(r for r in scope if r['record_hash']==found_hash)
        chain=[]
        prior_index=scope.index(origin)
        for category in ('MG0_PROCESS_ROOT_CAUSE','MG0_PROCESS_CORRECTION',
                         'MG0_AFFECTED_STATES_INVALIDATED','MG0_RULE_REAPPLIED'):
            next_event=next((r for r in scope[prior_index+1:]
                             if r.get('event')==category and
                             r.get('trigger_record_hash')==found_hash and
                             r.get('result')=='PASS' and
                             bool(r.get('evidence_operation'))),None)
            if next_event is None:break
            chain.append(next_event['record_hash'])
            prior_index=scope.index(next_event)
        corrections[found_hash]={'ordered_correction_records':chain,
                                 'complete':len(chain)==4}
    observed=[{'id':i+1,'canonical_text':TRIGGERS[i],
               'status':'OBSERVED_IN_AUDIT' if hits else 'UNKNOWN_NOT_EXHAUSTIVELY_OBSERVED',
               'event_hashes':[r['record_hash'] for r in hits]}
              for i,hits in enumerate(signals)]
    return {
        'schema':'gg-c07-individual-mg0-audit-evidence-v1',
        'asset':asset,'rule_id':rule_id,'attempt_id':attempt_id,
        'master_sha256':master_sha256,'audit_sha256':audit_sha256,
        'audit_tail_sha256':tail,'audit_events_checked':len(rows),
        'canonical_trigger_count':len(TRIGGERS),'triggers':observed,
        'observed_failure_record_hashes':found,'corrections':corrections,
        'individual_rule_mg0':('FAIL' if found and
                not all(x['complete'] for x in corrections.values()) else 'UNKNOWN'),
        'not_observed_never_interpreted_as_pass':True,
        'owner_provenance_verified_by_git':False,
        'current_attempt_reapplication_verified':False,
        'advancement_authorized':False,
        'scope':'AUDIT_CORRELATION_NOT_OWNER_AUTHENTICATION_OR_OPERATIVE_MG0_PASS'
    }


def inspect(master_raw, audit_raw, asset, master_sha256, rule_id, attempt_id):
    """Legacy single-rule API retains its exact observable result."""
    _verify_master(master_raw, master_sha256)
    rows, tail = audit_check(audit_raw, asset)
    return _inspect_checked(rows, tail, sha(audit_raw), asset, master_sha256,
                            rule_id, attempt_id)


def inspect_batch(master_raw, audit_raw, asset, master_sha256, rule_ids, attempt_id):
    """One real audit readback for ALL DUE IDs, retaining independent judgments.

    A full batch is the MG0 *falsification* layer, not a proof of absence of
    defects, authenticity of owner, semantic compliance or production readiness.
    A result of UNKNOWN is a STOP for an eventual operational PASS.
    """
    require(type(rule_ids) in (list, tuple) and 0 < len(rule_ids) <= 763 and
            all(type(r) is str and r.strip() for r in rule_ids) and
            list(rule_ids) == sorted(set(rule_ids)),
            'C07_MG0_BATCH_EXACT_SORTED_UNIQUE_RULE_SET')
    require(type(attempt_id) is str and len(attempt_id) == 64 and
            all(c in '0123456789abcdef' for c in attempt_id),
            'C07_MG0_BATCH_EXACT_ATTEMPT')
    _verify_master(master_raw, master_sha256)
    rows, tail = audit_check(audit_raw, asset)
    audit_hash = sha(audit_raw)
    due = set(rule_ids)
    # Group scoped events in ONE traversal, instead of scanning a potentially
    # large audit once per rule. Non-scoped events remain available for baseline
    # validation in the same pre-verified set of rows.
    grouped = defaultdict(list)
    for row in rows:
        if row.get('attempt_id') == attempt_id and row.get('rule_id') in due:
            event=row.get('event')
            # R127: the real Controller may append a source-bound R178 rule
            # observation with the same rule_id/attempt_id. That is not an
            # MG0 claim. Ignore unrelated audit events, but never ignore an
            # unknown MG0_* event, which could otherwise smuggle fake PASS.
            if event in EVENTS or (type(event) is str and
                                    event.startswith('MG0_')):
                grouped[row['rule_id']].append(row)
    results = {}
    failed = []
    counts = {'FAIL': 0, 'UNKNOWN': 0, 'PASS': 0}
    for rule_id in rule_ids:
        observed = _inspect_checked(rows, tail, audit_hash, asset, master_sha256,
                                    rule_id, attempt_id, grouped.get(rule_id, []))
        verdict = observed['individual_rule_mg0']
        require(verdict in ('FAIL', 'UNKNOWN') and
                observed['advancement_authorized'] is False and
                observed['owner_provenance_verified_by_git'] is False,
                'C07_MG0_BATCH_UNTRUSTED_RULE_PASS')
        counts[verdict] += 1
        if verdict == 'FAIL':
            failed.append(rule_id)
        results[rule_id] = {
            'verdict': verdict,
            'observed_failure_count': len(observed['observed_failure_record_hashes']),
            'uncorrected_failure_count': sum(
                not x['complete'] for x in observed['corrections'].values()),
            'observation_sha256': sha(json.dumps(observed, sort_keys=True,
                ensure_ascii=False, separators=(',', ':')).encode('utf-8')),
        }
    require(sum(counts.values()) == len(rule_ids) and counts['PASS'] == 0,
            'C07_MG0_BATCH_NOT_ALL_RULES_REVIEWED')
    return {
        'schema': 'gg-c07-mg0-canonical-batch-readback-v1',
        'asset': asset, 'master_sha256': master_sha256,
        'audit_sha256': audit_hash, 'audit_tail_sha256': tail,
        'audit_events_verified_once': len(rows),
        'attempt_id': attempt_id, 'rule_count': len(rule_ids),
        'rule_ids_sha256': sha(json.dumps(list(rule_ids),
            separators=(',', ':')).encode('utf-8')),
        'counts': counts, 'failed_rule_ids': failed,
        'rules': results,
        'individual_mg0_passes': 0,
        'readback_scope': 'REAL_HASH_CHAINED_AUDIT_ONE_PASS',
        'missing_independent_evidence_never_passes': True,
        'advancement_authorized': False,
    }
