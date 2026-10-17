"""C07 R130: 110 individual original-Controller anti-recurrence and remediation checks.

Reads ORIGINAL canonical error/prevention clauses, pinned MASTER and the actual
hash-chained Controller log. A signed event or self-reported correction cannot
verify an owner's identity, prevention effectiveness or individual MG0 PASS.
Detected uncorrected errors cause FAIL; unproven correction stays UNKNOWN.
"""
import hashlib
import re
from collections import defaultdict

from c07_behavior_110 import (parse_registry, CANONICAL_PATH, SOURCE, FAMILY,
                              FAIL_EVENTS)
from c07_mg0_individual import inspect_batch as mg0_batch
from real_work_intake import audit_check

PIN='e8dd5bee1e423c4bba6aec6f5a96c04436a840dc180cd3f2656a84b1d239027f'
IDS=tuple('BEHAVIOR-'+str(n).zfill(3) for n in range(1,111))
STEPS=('MG0_PROCESS_ROOT_CAUSE','MG0_PROCESS_CORRECTION',
       'MG0_AFFECTED_STATES_INVALIDATED','MG0_RULE_REAPPLIED')

class UnprovenBehavior(ValueError):pass

def need(ok,msg):
    if not ok:raise UnprovenBehavior(msg)

def sha(raw):return hashlib.sha256(raw).hexdigest()


def relevant_failure(row):
    """A reported or observed noncompliance is a finding, never an owner PASS."""
    event=row.get('event')
    if event not in FAIL_EVENTS:return False
    if event=='VERIFIED_STATE_REVOKED':return True
    if event=='QUALITY_FINDING':return row.get('result')!='PASS'
    return row.get('result') in ('FAIL','BLOCKED')


def inspect(inventory,plan,asset,step,work,master_raw,audit_raw,state_tail,
            registry_raw=None):
    need(type(asset) is str and asset and asset==asset.upper()
         and type(step) is str and step and type(work) is dict
         and type(inventory) is dict and type(plan) is dict,
         'R130_EXACT_WORK_SOURCE_SCHEMA')
    need(inventory.get('schema')=='gg-effective-family-inventory-v1'
         and inventory.get('rule_count')==763
         and inventory.get('canonical_master_sha256')==work.get('master_sha256')
         and plan.get('master_sha256')==work.get('master_sha256'),
         'R130_CANONICAL_INVENTORY_MASTER_OR_PLAN_DRIFT')
    need(type(master_raw) is bytes and sha(master_raw)==work['master_sha256']
         and inventory.get('source_digests',{}).get(SOURCE)==PIN,
         'R130_PINNED_MASTER_OR_ORIGINAL_REGISTRY_BYTES_CHANGED')
    need(inventory.get('families',{}).get(FAMILY)==list(IDS),
         'R130_ORIGINAL_110_SOURCE_FAMILY_INCOMPLETE')
    if registry_raw is None:
        # family_coverage.build_inventory originally read the full private
        # source bytes and pinned their SHA. Do not claim a second byte read.
        clauses={rid:inventory.get('rules',{}).get(rid,{}).get('requirement')
                 for rid in IDS}
    else:
        need(type(registry_raw) is bytes and sha(registry_raw)==PIN,
             'R130_PINNED_REGISTRY_BYTES_CHANGED')
        clauses=parse_registry(registry_raw)
    for rid in IDS:
        row=inventory.get('rules',{}).get(rid,{})
        canonical=clauses[rid]
        need(row.get('family')==FAMILY and row.get('source')==SOURCE
             and row.get('source_path')==CANONICAL_PATH
             and row.get('source_sha256')==PIN
             and row.get('requirement')==canonical
             and row.get('requirement_sha256')==sha(canonical.encode('utf-8')),
             'R130_UNREVIEWED_RULE_TEXT_OR_SOURCE_CHANGED:'+rid)
    need(type(audit_raw) is bytes and type(state_tail) is str,
         'R130_ORIGINAL_AUDIT_BYTES_REQUIRED')
    rows,tail=audit_check(audit_raw,asset)
    need(tail==state_tail,'R130_ORIGINAL_AUDIT_AND_STATE_NOT_ALIGNED')
    opened=[(i,r) for i,r in enumerate(rows) if
            r.get('event')=='SUPERVISOR_OPERATION_OPENED' and r.get('step')==step]
    need(len(opened)==1,'R130_CURRENT_OPERATION_OPEN_MISSING_OR_DUPLICATED')
    index,op=opened[0]
    reservations=[(i,r) for i,r in enumerate(rows[:index]) if
                  r.get('event')=='SUPERVISOR_OPERATION_RESERVED' and
                  r.get('record_hash')==op.get('reservation_hash')]
    need(len(reservations)==1 and reservations[0][1].get('work')==work
         and op.get('operation_sha256')==work.get('operation_sha256')
         and type(work.get('attempt_id')) is str
         and re.fullmatch('[a-f0-9]{64}',work['attempt_id']),
         'R130_RESERVED_WORK_ATTEMPT_CROSS_REPLAY')
    need(not any(r.get('event') in ('STEP_CLOSE','SUPERVISOR_OPERATION_CLOSED')
                 and r.get('step')==step for r in rows[index+1:]),
         'R130_CLOSED_STEP_MUST_NOT_BE_REOPENED')
    scoped=defaultdict(list)
    for pos,row in enumerate(rows[index+1:],index+1):
        if row.get('rule_id') in IDS and row.get('attempt_id')==work['attempt_id']:
            need(row.get('step') in (None,step),
                 'R130_RULE_EVENT_CROSS_STEP_REPLAY')
            scoped[row['rule_id']].append((pos,row))
    # One independent source check per ID over the SAME 110-source canonical
    # evidence. The MG0 scanner itself reads the ORIGINAL master and audit.
    mg=mg0_batch(master_raw,audit_raw,asset,work['master_sha256'],
                 list(IDS),work['attempt_id'])
    need(mg.get('rule_count')==110 and set(mg.get('rules',{}))==set(IDS)
         and mg.get('counts',{}).get('PASS')==0
         and mg.get('individual_mg0_passes')==0
         and mg.get('advancement_authorized') is False
         and mg.get('audit_sha256')==sha(audit_raw) and
         mg.get('audit_tail_sha256')==tail,
         'R130_MG0_INDEPENDENT_BATCH_FALSE_PASS')
    details={};uncorrected=[];observed=[];all_missing=[];correction_chains=0
    for rid in IDS:
        literal=clauses[rid]
        group=scoped.get(rid,[])
        findings=[(p,r) for p,r in group if relevant_failure(r)]
        observations=[]
        for origin_pos,origin in findings:
            sequence=[];prior=origin_pos;missing=[]
            for phase in STEPS:
                matches=[(p,r) for p,r in group if p>prior and
                         r.get('event')==phase and
                         r.get('trigger_record_hash')==origin['record_hash']
                         and r.get('result')=='PASS' and
                         bool(r.get('evidence_operation'))]
                if len(matches)!=1:
                    missing.extend(STEPS[len(sequence):]);break
                prior,record=matches[0]
                sequence.append(record['record_hash'])
            complete=len(sequence)==4
            correction_chains+=int(complete)
            if not complete:uncorrected.append(rid)
            observations.append({
                'finding_record_hash':origin['record_hash'],
                'event':origin['event'],
                'reported_owner_origin_unverified':origin.get('detected_by')=='OWNER',
                'ordered_correction_record_hashes':sequence,
                'missing_correction_phases':missing,
                'claimed_chain_complete':complete,
                'corrective_quality_independently_verified':False})
        verdict=mg['rules'][rid]['verdict']
        need(verdict in ('FAIL','UNKNOWN'),'R130_NO_SELF_ATTESTED_MG0_PASS:'+rid)
        if findings:observed.append(rid)
        # Even after four claimed steps, the owner and independent full-rule
        # verification are missing. NEVER turn absence of reports into PASS.
        status=('FAIL' if verdict=='FAIL' or
                any(not o['claimed_chain_complete'] for o in observations)
                else 'UNKNOWN')
        if status=='FAIL':all_missing.append(rid)
        error,prevention=literal[len('Errore: '):].split(' → ',1)
        details[rid]={
            'rule_id':rid,
            'requirement_sha256':inventory['rules'][rid]['requirement_sha256'],
            'source_sha256':PIN,
            'specific_error':error,'specific_prevention':prevention,
            'observed_failure_count':len(findings),
            'observations':observations,
            'individual_mg0':verdict,
            'semantic_result':status,
            'independent_prevention_effectiveness':'UNKNOWN',
            'real_owner_identity':'UNKNOWN',
            'new_full_rule_pass':False,'advancement_authorized':False,
        }
    need(len(details)==110 and set(details)==set(IDS) and
         all(x['new_full_rule_pass'] is False for x in details.values()),
         'R130_110_INCOMPLETE_OR_FALSE_PASS')
    return {
        'schema':'gg-c07-r130-original-110-remediation-evidence-v1',
        'asset':asset,'step':step,'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'master_sha256':work['master_sha256'],
        'registry_sha256':PIN,
        'original_registry_bytes_rechecked':registry_raw is not None,
        'original_audit_sha256':sha(audit_raw),'original_audit_tail':tail,
        'source_rules_examined':110,'observed_failure_rule_ids':sorted(observed),
        'uncorrected_finding_rule_ids':sorted(set(uncorrected)),
        'failed_rule_ids':sorted(set(all_missing)),
        'ordered_claimed_correction_chains':correction_chains,
        'rule_count_with_semantic_PASS':0,'individual_mg0_PASS':0,
        'rules':details,'advancement_authorized':False,
        'result':'FAIL' if all_missing else 'UNKNOWN',
    }