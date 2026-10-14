"""MG0 source-derived, individual-rule evidence review.

Reads ALL five canonical process-falsification triggers from the pinned Master
and verifies actual Golden Controller hash-chained events. Correlations are
evidence of a trigger, not independent verification of the owner's identity.
Missing independent observation NEVER means that a trigger is false or that MG0
passed. This module cannot issue an operational PASS by itself.
"""
from collections import Counter

from real_work_intake import audit_check, require, sha

TRIGGERS = (
    'a significant error reaches the user despite previous PASS states;',
    'something was VERIFIED but later proves it should not have been;',
    'the user rapidly finds something the assistant should have found autonomously;',
    'two or more errors reveal the same pattern;',
    'a formally compliant process still produces a mediocre or non-deliverable result.',
)
EVENTS = ('STEP_CLOSE','USER_REVIEW','VERIFIED_STATE_REVOKED',
          'QUALITY_FINDING','DELIVERY_GATE_CHECK',
          'MG0_PROCESS_ROOT_CAUSE','MG0_PROCESS_CORRECTION',
          'MG0_AFFECTED_STATES_INVALIDATED','MG0_RULE_REAPPLIED')


def inspect(master_raw, audit_raw, asset, master_sha256, rule_id, attempt_id):
    """Rule/attempt scoped observation; source or audit drift blocks."""
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
    require(isinstance(rule_id,str) and rule_id.strip() and
            isinstance(attempt_id,str) and len(attempt_id)==64 and
            all(c in '0123456789abcdef' for c in attempt_id),
            'C07_MG0_CURRENT_RULE_ATTEMPT')
    rows, tail = audit_check(audit_raw, asset)
    # Scope strictly to the exact rule and attempt; no historical ticket replay.
    scope = [r for r in rows if r.get('rule_id') == rule_id and
             r.get('attempt_id') == attempt_id]
    require(all(r.get('event') in EVENTS for r in scope),
            'C07_MG0_UNKNOWN_SCOPED_EVENT')
    completed = [r for r in scope if r.get('event') == 'STEP_CLOSE'
                 and r.get('result') == 'PASS']
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
        'master_sha256':master_sha256,'audit_sha256':sha(audit_raw),
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
