"""C07 R133: independently read ORIGINAL file bytes for 110 remediation chains.

Four text/logged PASS entries cannot repair an observed behavioral failure.
For each original finding, require four distinct source-bound JSON witnesses,
verified from the original Controller root with exact file SHA, rule, attempt,
phase, previous audit hash and trigger hash. File presence does NOT demonstrate
effective prevention, author identity, owner approval, semantic or MG0 PASS.
"""
import hashlib
import json
import re
from pathlib import Path
from real_work_intake import audit_check

IDS=tuple('BEHAVIOR-'+str(i).zfill(3) for i in range(1,111))
PHASES=('MG0_PROCESS_ROOT_CAUSE','MG0_PROCESS_CORRECTION',
        'MG0_AFFECTED_STATES_INVALIDATED','MG0_RULE_REAPPLIED')
POINTER='gg-c07-original-remediation-pointer-v1'
WITNESS='gg-c07-original-remediation-byte-witness-v1'
SCHEMA='gg-c07-r133-110-original-byte-witnesses-v1'

class OriginalEvidenceBlocked(ValueError):pass
def require(ok,why):
    if not ok:raise OriginalEvidenceBlocked(why)
def sha(b):return hashlib.sha256(b).hexdigest()
def exact_pairs(items):
    obj={}
    for key,val in items:
        if key in obj:raise ValueError('R133_DUPLICATE_WITNESS_JSON_KEY')
        obj[key]=val
    return obj

def read_witness(root,evidence,row,rid,trigger_hash,phase,work,step):
    if type(evidence) is not dict or set(evidence)!={'schema','relative_path','sha256'} or evidence['schema']!=POINTER:return None
    name,digest=evidence['relative_path'],evidence['sha256']
    if type(name) is not str or not name or '\x00' in name or '\\' in name or type(digest) is not str or not re.fullmatch('[a-f0-9]{64}',digest):return None
    rel=Path(name)
    if rel.is_absolute() or '..' in rel.parts:return None
    source=root/rel
    try:
        if not source.resolve().is_relative_to(root) or not source.is_file():return None
        if any(p.is_symlink() for p in (source,*source.parents) if p!=root):return None
        raw=source.read_bytes()
    except OSError:return None
    if not raw or len(raw)>200_000 or sha(raw)!=digest:return None
    try:doc=json.loads(raw,object_pairs_hook=exact_pairs)
    except (ValueError,TypeError,UnicodeDecodeError):return None
    expected={
        'schema':WITNESS,'rule_id':rid,'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],'step':step,
        'trigger_record_hash':trigger_hash,'phase':phase,
        'predecessor_record_sha256':row['prev_hash']}
    if type(doc) is not dict or doc!=expected:return None
    return {'original_path':name,'original_sha256':digest,
            'audit_record_hash':row['record_hash']}

def inspect(original110,audit_raw,state_tail,asset,step,work,root):
    require(type(original110) is dict and type(work) is dict
            and type(audit_raw) is bytes and type(asset) is str
            and type(step) is str and type(state_tail) is str,
            'R133_ORIGINAL_INPUT_TYPES')
    require(original110.get('schema')=='gg-c07-r130-original-110-remediation-evidence-v1'
            and original110.get('source_rules_examined')==110
            and set(original110.get('rules',{}))==set(IDS)
            and original110.get('rule_count_with_semantic_PASS')==0
            and original110.get('individual_mg0_PASS')==0
            and original110.get('advancement_authorized') is False,
            'R133_ALL_110_SOURCE_PROVENANCE_AND_NO_FALSE_PASS')
    require(original110.get('asset')==asset and original110.get('step')==step
            and all(original110.get(k)==work[k] for k in
                    ('master_sha256','attempt_id','operation_sha256')),
            'R133_EXACT_ORIGINAL_WORK_AND_ATTEMPT')
    rows,tail=audit_check(audit_raw,asset)
    require(tail==state_tail==original110.get('original_audit_tail')
            and sha(audit_raw)==original110.get('original_audit_sha256'),
            'R133_ORIGINAL_AUDIT_BYTES_OR_STATE_CHANGED')
    opened=[(i,r) for i,r in enumerate(rows)
            if r.get('event')=='SUPERVISOR_OPERATION_OPENED'
            and r.get('step')==step]
    require(len(opened)==1 and
            opened[0][1].get('operation_sha256')==work['operation_sha256'],
            'R133_ORIGINAL_OPEN_NOT_UNIQUE')
    openpos=opened[0][0]
    require(not any(r.get('event') in ('STEP_CLOSE','SUPERVISOR_OPERATION_CLOSED')
                    and r.get('step')==step for r in rows[openpos+1:]),
            'R133_CURRENT_STEP_ALREADY_CLOSED')
    root=Path(root).resolve()
    require(root.is_dir(),'R133_ORIGINAL_CONTROLLER_ROOT_UNAVAILABLE')
    # Consumer independently enumerates each actual recorded failure instead
    # of trusting the producer's 110-row summary of observed findings.
    from c07_behavior110_remediation import relevant_failure
    by_hash={r['record_hash']:(n,r) for n,r in enumerate(rows)}
    detail={};failed=[];fully_byte_bound=0;read_files=set();observed_count=0
    for rid in IDS:
        item=original110['rules'][rid]
        require(item.get('rule_id')==rid and
                item.get('semantic_result') in ('UNKNOWN','FAIL')
                and item.get('individual_mg0') in ('UNKNOWN','FAIL')
                and item.get('new_full_rule_pass') is False
                and item.get('advancement_authorized') is False,
                'R133_INDIVIDUAL_SOURCE_OR_FALSE_PASS:'+rid)
        findings=item.get('observations')
        actual_findings={r['record_hash'] for r in rows[openpos+1:]
            if r.get('rule_id')==rid and
               r.get('attempt_id')==work['attempt_id'] and
               r.get('step') in (None,step) and relevant_failure(r)}
        claimed_findings=([v.get('finding_record_hash') for v in findings]
                          if type(findings) is list else [])
        require(type(findings) is list and
                len(findings)==item.get('observed_failure_count') and
                len(claimed_findings)==len(set(claimed_findings)) and
                set(claimed_findings)==actual_findings,
                'R133_110_SOURCE_FAILURE_OMITTED:'+rid)
        records=[]
        for finding in findings:
            trigger=finding.get('finding_record_hash')
            orig=by_hash.get(trigger)
            require(orig is not None and orig[0]>openpos
                    and orig[1].get('rule_id')==rid
                    and orig[1].get('attempt_id')==work['attempt_id']
                    and orig[1].get('step')==step,
                    'R133_TRIGGER_CROSS_ATTEMPT_OR_RULE:'+rid)
            recorded=finding.get('ordered_correction_record_hashes')
            require(type(recorded) is list and len(recorded)<=4,
                    'R133_ORDERED_CLAIM_SET_INVALID:'+rid)
            seen=[];prior=orig[0]
            for phase,rec_hash in zip(PHASES,recorded):
                row=by_hash.get(rec_hash)
                if row is None or row[0]<=prior or row[1].get('event')!=phase or (
                    row[1].get('rule_id')!=rid or
                    row[1].get('attempt_id')!=work['attempt_id'] or
                    row[1].get('step')!=step or
                    row[1].get('trigger_record_hash')!=trigger or
                    row[1].get('result')!='PASS'):
                    break
                prior=row[0]
                witness=read_witness(root,row[1].get('evidence_operation'),
                                     row[1],rid,trigger,phase,work,step)
                if witness is None:break
                seen.append(witness)
            complete=(len(recorded)==len(seen)==4 and
                      len({x['original_path'] for x in seen})==4 and
                      len({x['original_sha256'] for x in seen})==4)
            fully_byte_bound+=int(complete)
            observed_count+=1
            read_files.update(x['original_path'] for x in seen)
            records.append({'original_failure_record_hash':trigger,
                            'original_file_bytes_verified':len(seen),
                            'four_distinct_original_phase_witnesses':bool(complete),
                            'verified_original_sources':seen,
                            'independently_verified_correction_effect':'UNKNOWN'})
            if not complete:failed.append(rid)
        detail[rid]={'rule_id':rid,'source_sha256':item['source_sha256'],
                     'requirement_sha256':item['requirement_sha256'],
                     'failures':records,'all_original_finding_bytes_witnessed':
                     bool(records) and all(x['four_distinct_original_phase_witnesses']
                                           for x in records),
                     'semantic_result':'FAIL' if rid in failed or item['semantic_result']=='FAIL' else 'UNKNOWN',
                     'full_rule_pass':False,'individual_mg0':'UNKNOWN',
                     'owner_authenticity':'UNKNOWN','advancement_authorized':False}
    # A previous canonical MG0/behavior FAIL cannot be suppressed by four
    # apparently valid artifact files; original bytes are NOT proof of repair.
    failed=sorted(set(failed)|{rid for rid in IDS if
        original110['rules'][rid]['semantic_result']=='FAIL'})
    require(len(detail)==110 and
            all(x['full_rule_pass'] is False for x in detail.values()),
            'R133_UNTRUSTED_FULL_RULE_PASS')
    return {'schema':SCHEMA,'asset':asset,'step':step,
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'original_audit_sha256':sha(audit_raw),
            'original_audit_tail':tail,
            'source_rules_examined':110,
            'actual_failure_observations_checked':observed_count,
            'four_distinct_original_byte_witness_chains':fully_byte_bound,
            'verified_original_file_paths':len(read_files),
            'failed_rule_ids':sorted(set(failed)),
            'rules':detail,'full_semantic_PASS':0,'individual_mg0_PASS':0,
            'advancement_authorized':False,
            'result':'FAIL' if failed else 'UNKNOWN'}
