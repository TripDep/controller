"""C07 R112: enforce negative semantic evidence on real hash-chained Controller audit.

One independently parsed, full audit; 200-rule chunks; exact asset, attempt,
master and approved operation. A self-admitted failure or machine-confirmed
canonical negative is FAIL, never diluted by 0 earlier successes. Missing
independent evidence is UNKNOWN, not PASS. Owner assertions without provenance
are review BLOCKERS, not authenticated verdicts. This is deliberately NOT a
substitute for full positive semantic predicates, composite checks or MG0.
"""
import hashlib
import json
import re

SCHEMA = 'gg-c07-r112-negative-semantic-replay-v1'
HEX = re.compile(r'[a-f0-9]{64}\Z')

class ReplayBlocked(ValueError):
    pass

def need(ok, why):
    if not ok:
        raise ReplayBlocked(why)

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')

def sha(value):
    return hashlib.sha256(value).hexdigest()

def supervisor_digest(value):
    # Exactly supervisor_judgment.digest(): default ensure_ascii=True.
    return sha(json.dumps(value,sort_keys=True,separators=(',',':')).encode())

def audit_readback(raw, asset):
    """Read and hash-check EVERY record; duplicate JSON keys and NaNs STOP."""
    need(type(raw) is bytes and 0 < len(raw) <= 40_000_000, 'R112_AUDIT_BYTES')
    rows, previous = [], 'GENESIS'
    def strict_pairs(items):
        out = {}
        for k,v in items:
            need(k not in out,'R112_AUDIT_DUPLICATE_JSON_KEY')
            out[k] = v
        return out
    for i,line in enumerate(raw.splitlines(), 1):
        need(bool(line.strip()), 'R112_AUDIT_BLANK:'+str(i))
        try:
            row=json.loads(line,object_pairs_hook=strict_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ReplayBlocked('R112_AUDIT_NONFINITE')))
        except ReplayBlocked:
            raise
        except (ValueError, UnicodeDecodeError) as e:
            raise ReplayBlocked('R112_AUDIT_JSON:'+str(i)) from e
        need(type(row) is dict and row.get('asset')==asset and
             row.get('prev_hash')==previous, 'R112_AUDIT_CHAIN:'+str(i))
        record_hash=row.get('record_hash')
        need(type(record_hash) is str and HEX.fullmatch(record_hash) and
             sha(canonical({k:v for k,v in row.items() if k!='record_hash'}))==record_hash,
             'R112_AUDIT_HASH:'+str(i))
        rows.append(row)
        previous=record_hash
    need(bool(rows),'R112_AUDIT_EMPTY')
    return rows,previous

def inspect(inventory, plan, audit_raw, asset, attempt_id, *, batch_size=200):
    """Compute DUE internally from pinned rule inventory; ignore producer waivers.

    Produces 763 slots in four deterministic chunks; detects rule-specific
    admitted errors and machine findings from authentic Controller audit records.
    Does not infer successful model QA, owner's identity, or absence of errors.
    """
    import c07_operation_scope as source_scope
    need(type(batch_size) is int and batch_size in (100,200),'R112_BATCH_SIZE')
    need(type(asset) is str and asset and asset==asset.upper() and
         type(attempt_id) is str and HEX.fullmatch(attempt_id),
         'R112_EXACT_ASSET_ATTEMPT')
    need(type(inventory) is dict and inventory.get('rule_count')==763 and
         inventory.get('schema')=='gg-effective-family-inventory-v1' and
         type(inventory.get('families')) is dict and
         type(inventory.get('rules')) is dict, 'R112_CANONICAL_763_REQUIRED')
    ordered=[rid for group in inventory['families'].values() for rid in group]
    need(len(ordered)==len(set(ordered))==763 and
         set(ordered)==set(inventory['rules']), 'R112_CANONICAL_MEMBERSHIP')
    need(type(plan) is dict and
         plan.get('master_sha256')==inventory.get('canonical_master_sha256'),
         'R112_TRUSTED_PLAN_BINDING')
    scoped=source_scope.inspect(inventory,plan)
    need(scoped['rule_count']==763 and
         set(scoped['by_rule'])==set(ordered), 'R112_APPLICABILITY_BINDING')
    rows, tail=audit_readback(audit_raw, asset)
    rules=inventory['rules']
    due=set()
    applicability={}
    for rid in ordered:
        row=rules[rid]
        need(row.get('family') in inventory['families'] and
             rid in inventory['families'][row['family']] and
             type(row.get('source_sha256')) is str and
             HEX.fullmatch(row['source_sha256']) and
             type(row.get('requirement_sha256')) is str and
             HEX.fullmatch(row['requirement_sha256']),
             'R112_RULE_BINDING:'+rid)
        clause=row.get('requirement')
        need(type(clause) is str and sha(clause.encode('utf-8'))==
             row['requirement_sha256'], 'R112_REQUIREMENT_DRIFT:'+rid)
        verdict=scoped['by_rule'][rid]['disposition']
        need(verdict in ('DUE','FUTURE_PHASE','N_A','N_A_CONTEXT'),
             'R112_APPLICABILITY:'+rid)
        applicability[rid]=verdict
        if verdict=='DUE':due.add(rid)
    reasons={rid:[] for rid in due}
    untrusted_owner_claims={rid:[] for rid in due}
    relevant_records=[]
    # Read each record ONCE. Only actual same-attempt events count.
    for ev in rows:
        if ev.get('attempt_id') != attempt_id:
            # Assistant answer event holds the binding within `report`.
            if (ev.get('event')!='SUPERVISOR_ASSISTANT_ANSWER_GATE' or not
                    (type(ev.get('report')) is dict and ev['report'].get('attempt_id')==attempt_id)):
                continue
        kind=ev.get('event')
        if kind=='SUPERVISOR_ASSISTANT_ANSWER_GATE':
            report=ev.get('report')
            need(type(report) is dict and report.get('attempt_id')==attempt_id
                 and report.get('master_sha256')==plan['master_sha256']
                 and type(report.get('failed')) is list and
                 type(report.get('failed_subchecks')) is list and
                 report.get('advancement_authorized') is False,
                 'R112_ANSWER_GATE_BINDING')
            for answer in report['failed']:
                rid=answer.get('rule_id') if type(answer) is dict else None
                need(rid in rules, 'R112_ANSWER_FAIL_UNKNOWN_RULE')
                if rid in due:
                    reasons[rid].append({'source':'ANSWER_ADMITTED_DEFECT',
                                         'record_hash':ev['record_hash'],
                                         'question_id':answer.get('question_id')})
            for sub in report['failed_subchecks']:
                rid=sub.get('rule_id') if type(sub) is dict else None
                need(rid in rules, 'R112_ADMITTED_SUBCHECK_UNKNOWN_RULE')
                if rid in due:
                    reasons[rid].append({'source':'COMPOSITE_SUBCHECK_ADMITTED_DEFECT',
                                         'record_hash':ev['record_hash'],
                                         'subcheck_id':sub.get('subcheck_id')})
            relevant_records.append(ev['record_hash'])
        elif kind=='SUPERVISOR_CANONICAL_NATIVE_NEGATIVE_GATE':
            reports=ev.get('native_reports')
            need(type(reports) is list and reports and
                 ev.get('master_sha256')==plan['master_sha256']
                 and ev.get('attempt_id')==attempt_id and
                 ev.get('native_reports_sha256')==supervisor_digest(reports) and
                 type(ev.get('native_rule_ids')) is list and
                 ev['native_rule_ids']==sorted(set(ev['native_rule_ids'])) and
                 set(ev['native_rule_ids'])<=set(rules),
                 'R112_NATIVE_GATE_INTEGRITY')
            native_failure=set()
            for report in reports:
                need(type(report) is dict and report.get('binding',{}).get('asset_id')==asset
                     and report['binding'].get('attempt_id')==attempt_id
                     and report['binding'].get('master_sha256')==plan['master_sha256']
                     and report.get('rule_count')==len(ev['native_rule_ids'])
                     and set(report.get('rules',{}))==set(ev['native_rule_ids'])
                     and report.get('advancement_authorized') is False
                     and report.get('individual_mg0_passes')==0
                     and report.get('work_rule_passes')==0,
                     'R112_NATIVE_REPORT_BINDING')
                for rid,predicate in report['rules'].items():
                    need(predicate.get('individual_mg0')=='UNKNOWN' and
                         predicate.get('independent_native_rule_observation') in ('FAIL','UNKNOWN'),
                         'R112_NATIVE_PREDICATE_VERDICT')
                    if predicate['independent_native_rule_observation']=='FAIL':
                        need(type(predicate.get('native_negative_findings')) is list and
                             bool(predicate['native_negative_findings']),
                             'R112_NATIVE_FAILURE_WITHOUT_FINDING')
                        native_failure.add(rid)
            need((ev.get('result')=='FAIL_NATIVE_FINDINGS')==bool(native_failure),
                 'R112_NATIVE_EVENT_VERDICT_MISMATCH')
            for rid in native_failure & due:
                reasons[rid].append({'source':'REAL_NATIVE_GLB_FAILURE',
                                     'record_hash':ev['record_hash']})
            relevant_records.append(ev['record_hash'])
        elif kind=='USER_REVIEW' and ev.get('result')=='FAIL':
            rid=ev.get('rule_id')
            if rid in due:
                # This audit alone does NOT authenticate an owner's identity.
                untrusted_owner_claims[rid].append(ev['record_hash'])
                relevant_records.append(ev['record_hash'])
        elif kind=='QUALITY_FINDING' and ev.get('result')=='FAIL':
            rid=ev.get('rule_id')
            if (rid in due and ev.get('detected_by')=='INDEPENDENT_NATIVE_SCANNER' and
                    type(ev.get('machine_evidence_sha256')) is str and
                    HEX.fullmatch(ev['machine_evidence_sha256'])):
                reasons[rid].append({'source':'INDEPENDENT_MACHINE_QUALITY_FINDING',
                                     'record_hash':ev['record_hash']})
                relevant_records.append(ev['record_hash'])
    ordered=sorted(ordered)
    chunks=[]
    failures=[]
    owner_reviews=[]
    for i in range(0,len(ordered),batch_size):
        selected=ordered[i:i+batch_size]
        details={}
        for rid in selected:
            risk=reasons.get(rid,[])
            claims=untrusted_owner_claims.get(rid,[])
            status=('FAIL' if risk else 'UNKNOWN_REVIEW_NOT_AUTHENTICATED'
                    if claims else 'UNKNOWN' if rid in due else 'NOT_DUE')
            if risk:failures.append(rid)
            if claims:owner_reviews.append(rid)
            details[rid]={
                'applicability':applicability[rid],
                'source_sha256':rules[rid]['source_sha256'],
                'requirement_sha256':rules[rid]['requirement_sha256'],
                'semantic_negative_verdict':status,
                'native_negative_evidence':risk,
                'unauthenticated_owner_claim_hashes':claims,
                'positive_semantic_proof':'UNKNOWN' if rid in due else 'NOT_DUE',
                'individual_mg0':'UNKNOWN' if rid in due else 'NOT_DUE',
                'work_pass':False}
        chunks.append({'batch':len(chunks)+1,'count':len(selected),
                       'ids_sha256':sha(canonical(selected)),
                       'detail_sha256':sha(canonical(details)),
                       'failed':sorted(r for r in selected if r in failures),
                       'rules':details})
    need(len(chunks)==(4 if batch_size==200 else 8) and
         sum(c['count'] for c in chunks)==763, 'R112_BATCH_INCOMPLETE')
    output={'schema':SCHEMA, 'asset':asset,
        'attempt_id':attempt_id, 'master_sha256':plan['master_sha256'],
        'audit_sha256':sha(audit_raw), 'audit_tail_sha256':tail,
        'hash_chained_records_verified':len(rows),
        'attempt_records_used_sha256':sha(canonical(sorted(set(relevant_records)))),
        'rule_count':763,'due_count':len(due), 'batch_size':batch_size,
        'batch_counts':[c['count'] for c in chunks],
        'semantic_negative_fail_rule_ids':sorted(set(failures)),
        'unverified_owner_review_rule_ids':sorted(set(owner_reviews)),
        'positive_semantic_passes':0, 'individual_mg0_passes':0,
        'advancement_authorized':False,
        'batches':chunks,
        'next_action':'STOP_CORRECT_REVIEW' if failures or owner_reviews else
                      'CONTINUE_TO_INDEPENDENT_POSITIVE_SEMANTICS_AND_MG0'}
    output['report_sha256']=sha(canonical(output))
    return output
