"""C07 R152: exhaustive source-line provenance across the 563 IDs outside R122.

Three canonical disjoint batches (200/200/163) are checked on the *same*
original Controller attempt. Every nonempty source line is a proof target.
Actual registered evidence is independently reopened, and explicit NO is FAIL.
A source-line receipt is never full rule semantics, MG0, human approval or
permission to deliver. The previous R151 engine covers the frozen other 200
and all 72 composite requirements, including composite-only IDs.
"""
import json
from pathlib import Path

from c07_positive200_evidence import R122_FROZEN_IDS, _lanes
from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_r151_original_clause_proofs import (
    SCHEMA as SOURCE_SCHEMA, source_lines, assess as assess_original,
    sha, digest, HEX64,
)

SCHEMA = 'gg-c07-r152-remaining563-source-line-evidence-v1'
MANIFEST = 'gg-c07-r152-source-line-current-attempt-evidence-v1'
BATCH_SIZES = (200,200,163)
BATCH_ROLES = tuple('C07_R152_BATCH_'+str(n)+'_SOURCE_LINE_EVIDENCE'
                    for n in (1,2,3))

class InvalidRemainingCohort(ValueError):
    pass

def need(test, reason):
    if not test:
        raise InvalidRemainingCohort(reason)

def cohorts(inventory):
    need(type(inventory) is dict and
         inventory.get('schema')=='gg-effective-family-inventory-v1' and
         inventory.get('rule_count')==763 and
         type(inventory.get('rules')) is dict and
         len(inventory['rules'])==763,
         'R152_CANONICAL_SOURCE_763_REQUIRED')
    full=set(inventory['rules'])
    frozen=set(R122_FROZEN_IDS)
    need(len(frozen)==200 and frozen <= full,
         'R152_FIRST_200_SOURCE_COHORT_CHANGED')
    remaining=sorted(full-frozen)
    need(len(remaining)==563 and len(set(remaining))==563,
         'R152_EXACT_REMAINING_563_REQUIRED')
    batches=(remaining[:200],remaining[200:400],remaining[400:])
    need(tuple(len(b) for b in batches)==BATCH_SIZES and
         set().union(*[set(b) for b in batches])==set(remaining) and
         not any(set(batches[i]) & set(batches[j])
                 for i in range(3) for j in range(i+1,3)),
         'R152_EXHAUSTIVE_NONOVERLAPPING_200_200_163')
    return batches

def compile_contract(inventory, plan, index):
    need(type(index) is int and 0<=index<3 and
         type(plan) is dict and
         plan.get('master_sha256')==inventory.get('canonical_master_sha256') and
         HEX64.fullmatch(str(plan['master_sha256'])) is not None,
         'R152_MASTER_AND_BATCH_CONTEXT')
    batches=cohorts(inventory)
    selected=batches[index]
    rows={}
    for rid in selected:
        row=inventory['rules'][rid]
        need(type(row) is dict and
             type(row.get('family')) is str and
             type(row.get('source_sha256')) is str and
             HEX64.fullmatch(row['source_sha256']) is not None,
             'R152_ORIGINAL_FAMILY_SOURCE_MISSING:'+rid)
        original=source_lines(rid,row)
        original['family']=row['family']
        original['required_independent_lanes']=list(_lanes({**row,'rule_id':rid}))
        original['composite_flag']=False
        need(original['required_independent_lanes'],
             'R152_NO_SOURCE_SPECIFIC_EVIDENCE_LANES:'+rid)
        rows[rid]=original
    need(len(rows)==BATCH_SIZES[index] and
         all(x['all_source_bytes_accounted_for'] for x in rows.values()),
         'R152_NONEXHAUSTIVE_ORIGINAL_SOURCE_LINES')
    return {
        'schema':SOURCE_SCHEMA,
        'master_sha256':inventory['canonical_master_sha256'],
        'source_rule_count':len(selected),
        'source_rule_ids_sha256':digest(selected),
        'selected':selected,
        'rows':rows,
        'all_source_bytes_accounted_for':True,
        'all_semantic_obligations_reviewed':False,
        'batch':index+1,
        'source_lines_covered':sum(x['source_line_count'] for x in rows.values()),
    }

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(work) is dict and callable(source_loader) and
         type(asset) is str and asset and asset==asset.upper() and
         type(step) is str and bool(step) and
         work.get('master_sha256')==inventory.get('canonical_master_sha256') and
         plan.get('master_sha256')==work.get('master_sha256'),
         'R152_CURRENT_ATTEMPT_NOT_AUTHENTICATED')
    contracts=[compile_contract(inventory,plan,i) for i in range(3)]
    records,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step and
         sha(controller.master.read_bytes())==work['master_sha256'],
         'R152_MASTER_OR_ORIGINAL_CONTROLLER_DRIFT')
    registered=_registered_artifacts(records,state,step,source_loader,work)
    manifests={}
    for item in registered:
        if item[0] in BATCH_ROLES:
            need(item[0] not in manifests,
                 'R152_DUPLICATE_ORIGINAL_BATCH_MANIFEST:'+item[0])
            manifests[item[0]]=item
    reports=[]
    for i,contract in enumerate(contracts):
        role=BATCH_ROLES[i]
        packets=[]
        if role in manifests:
            raw=manifests[role][3]
            need(type(raw) is bytes and len(raw)<=8_000_000,
                 'R152_ORIGINAL_MANIFEST_TOO_LARGE')
            try:
                parsed=json.loads(raw)
            except (UnicodeError,ValueError,TypeError) as exc:
                raise InvalidRemainingCohort('R152_MANIFEST_NOT_JSON') from exc
            need(type(parsed) is dict and set(parsed)=={
                 'schema','batch','master_sha256','attempt_id',
                 'operation_sha256','source_rule_ids_sha256','packets'} and
                 parsed['schema']==MANIFEST and parsed['batch']==i+1 and
                 all(parsed.get(key)==work[key] for key in
                     ('master_sha256','attempt_id','operation_sha256')) and
                 parsed['source_rule_ids_sha256']==contract['source_rule_ids_sha256'] and
                 type(parsed['packets']) is list,
                 'R152_MANIFEST_BATCH_ORIGINAL_ATTEMPT_REPLAY')
            packets=parsed['packets']
        # Shares the reviewed, tamper/replay-resistant source-line reader R151.
        result=assess_original(contract,work,packets,registered,source_loader)
        need(result['source_rule_count']==BATCH_SIZES[i] and
             len(result['rule_status'])==BATCH_SIZES[i] and
             set(result['rule_status'])==set(contract['selected']) and
             all(v in ('UNKNOWN','FAIL') for v in result['rule_status'].values()) and
             result['full_rule_semantic_passes']==0 and
             result['individual_mg0_passes']==0 and
             result['advancement_authorized'] is False,
             'R152_FALSE_SOURCE_LINE_OR_MG0_APPROVAL')
        reports.append({
            'batch':i+1,'source_rule_count':BATCH_SIZES[i],
            'source_rule_ids_sha256':contract['source_rule_ids_sha256'],
            'source_lines_covered':contract['source_lines_covered'],
            'manifest_present':role in manifests,
            'original_proof_packets_reopened':result['original_proof_packets_reopened'],
            'missing_source_line_witnesses':result['missing_source_line_witnesses'],
            'admitted_negative_line_ids':result['admitted_negative_line_ids'],
            'result':result['result'],
            'rule_status':result['rule_status'],
            'full_rule_semantic_passes':0,
            'individual_mg0_passes':0,
            'advancement_authorized':False,
        })
    need(sum(x['source_rule_count'] for x in reports)==563 and
         len(set().union(*(set(r['rule_status']) for r in reports)))==563,
         'R152_SOURCE_LINE_COHORT_LOSS_OR_OVERLAP')
    output={
      'schema':SCHEMA,'asset':asset,'step':step,
      'attempt_id':work['attempt_id'],
      'operation_sha256':work['operation_sha256'],
      'master_sha256':work['master_sha256'],
      'original_audit_tail':tail,'original_audit_sha256':audit_sha,
      'source_rule_count':563,
      'remaining_source_batches':[200,200,163],
      'batch_reports':reports,
      'all_563_original_source_lines_indexed':True,
      'original_proof_packets_reopened':sum(r['original_proof_packets_reopened']
                                            for r in reports),
      'missing_source_line_witnesses':sum(r['missing_source_line_witnesses']
                                          for r in reports),
      'manifest_batches_present':sum(r['manifest_present'] for r in reports),
      'result':'FAIL' if any(r['result']=='FAIL' for r in reports) else 'UNKNOWN',
      'full_rule_semantic_passes':0,
      'individual_mg0_passes':0,
      'owner_approval_verified':False,
      'advancement_authorized':False,
    }
    output['report_sha256']=digest(output)
    return output
