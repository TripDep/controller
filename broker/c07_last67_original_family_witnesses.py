"""C07 R150 — remaining 67 canonical rule IDs, exact source-family witnesses.

Completes nominal ORIGINAL SOURCE machine-evidence channels for the 763-rule
inventory alongside R122, R143, R144..R147, R148..R149. Each of the 67
has a distinct original source-requirement, registered source file, and
original current-attempt family receipt bound by SHA. No self-authored
receipt can establish full source semantics, real artistic result, owner
approval, independent MG0 or work release.

Cross-cutting Master/auxiliary rules remain mandatory: N/A for individual
asset profiles or historical contexts cannot erase the registered rule.
"""
import json
from collections import Counter
from c07_positive_native_process import _original_attempt,_registered_artifacts,sha
from c07_positive200_evidence import R122_FROZEN_IDS
from c07_q200_original_witnesses import digest, structured

SCHEMA='gg-c07-r150-last67-source-family-original-evidence-v1'
CONTRACT='gg-c07-r150-67-pre-d-source-family-witness-v1'
EXPECTED_FAMILIES={
    'MASTER_CHAIN':1,'META':1,'GLOBAL_GATES':4,
    'GLOBAL_COMPLETION':1,'DELIVERY':5,'GOVERNANCE':6,
    'DESIGN_STANDARDS':3,'BEHAVIOR':2,'PROVOCATION':12,
    'HISTORICAL_ASSET_GATES':11,'PROFESSIONAL_PHASES':9,
    'ASSET_PROFILE_READINESS':6,'PROFESSIONAL_SYSTEM':6,
}
SOURCES=('master','developer_rules','behavior_rules','error_registry',
         'professional_phases','operating_contract')
class Last67Blocked(ValueError):pass
def need(ok,why):
    if not ok:raise Last67Blocked(why)
def remaining(inventory):
    need(type(inventory) is dict and inventory.get('schema')==
         'gg-effective-family-inventory-v1'
         and inventory.get('rule_count')==763
         and len(inventory.get('rules',{}))==763,
         'R150_CANONICAL_INVENTORY_763_REQUIRED')
    source=inventory['rules'];ids=set(source)
    done=set(R122_FROZEN_IDS)
    done.update(x for x in ids if x.startswith('AAA-200-') or
                x.startswith('Q-') or x.startswith('G0-'))
    need(done<=ids,'R150_EXISTING_SOURCE_COHORT_ID_DRIFT')
    rest=tuple(sorted(ids-done))
    need(len(rest)==67 and dict(Counter(source[r]['family'] for r in rest))==
         dict(Counter({k:v for k,v in EXPECTED_FAMILIES.items()})),
         'R150_EXACT_67_ORIGINAL_FAMILY_MEMBERSHIP')
    return rest

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    ids=remaining(inventory)
    need(callable(source_loader),'R150_REAL_ORIGINAL_SOURCE_LOADER_REQUIRED')
    master=controller.master.read_bytes()
    need(sha(master)==work.get('master_sha256')==
         plan.get('master_sha256')==inventory.get('canonical_master_sha256'),
         'R150_CURRENT_LIBRARY_MASTER_CHANGED')
    for rid in ids:
        row=inventory['rules'][rid]
        need(type(row.get('requirement')) is str and row['requirement'].strip()
             and row.get('requirement_sha256')==sha(row['requirement'].encode('utf-8'))
             and row.get('source') in SOURCES
             and row.get('source_sha256')==inventory['source_digests'][row['source']]
             and rid in inventory['families'][row['family']],
             'R150_UNVERIFIED_ORIGINAL_SOURCE_CLAUSE:'+rid)
    records,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'R150_ORIGINAL_AUDIT_CORRUPT')
    artifacts=_registered_artifacts(records,state,step,source_loader,work)
    files={}
    for role,path,hash_,raw in artifacts:
        need(role not in files,'R150_ORIGINAL_EVIDENCE_DUPLICATE_ROLE:'+role)
        files[role]=(path,hash_,raw)
    def present(role):
        row=files.get(role)
        return (row is not None and type(row[2]) is bytes and
            len(row[2])>0 and sha(row[2])==row[1])
    manifest=plan.get('last_67_source_evidence_contract')
    enrolled=(manifest.get('rules') if type(manifest) is dict and
        manifest.get('schema')==CONTRACT else {})
    if type(enrolled) is not dict:enrolled={}
    need(not set(enrolled)-set(ids),'R150_UNRECOGNIZED_FAMILY_RULE_ID')
    all_source=inventory['source_digests']
    source_files={
        key:('ORIGINAL_CANONICAL_'+key.upper())
        for key in SOURCES if key!='master'}
    file_source_ok={}
    for source,role in source_files.items():
        file_source_ok[source]=bool(present(role) and
            files[role][1]==all_source[source])
    results={};source_ok=0;receipt_ok=0;current_blocked=state.get('delivery_status')!='DELIVERABLE'
    for rid in ids:
        original=inventory['rules'][rid]
        family=original['family']
        slot=enrolled.get(rid)
        role='C07_FAMILY_'+family
        rec=files.get(role)
        source_token=original['source']
        authentically_read=(source_token=='master' or
                             file_source_ok.get(source_token,False))
        expected=(type(slot) is dict and
            set(slot)=={'requirement_sha256','source_sha256','witness_role',
                        'witness_sha256','observed_origin','claim_status'}
            and slot.get('requirement_sha256')==original['requirement_sha256']
            and slot.get('source_sha256')==original['source_sha256']
            and slot.get('witness_role')==role
            and rec is not None and
            slot.get('witness_sha256')==rec[1]
            and slot.get('observed_origin')=='ORIGINAL_REGISTERED_BYTES'
            and slot.get('claim_status')=='OBSERVATION_ONLY')
        # Presence and SHA of the original family evidence file does not
        # authenticate its asserted artistic or game-world meaning.
        payload=structured(rec[2]) if rec is not None and present(role) else {}
        sub=payload.get('source_rule_witnesses')
        row=sub.get(rid) if type(sub) is dict else None
        original_witness=(type(row) is dict and
            row.get('original_requirement_sha256')==original['requirement_sha256']
            and row.get('original_source_sha256')==original['source_sha256']
            and row.get('source_rule_id')==rid
            and row.get('evidence_class')==family
            and row.get('claimed_result')=='OBSERVATION_ONLY')
        native=bool(authentically_read and expected and
                    present(role) and original_witness)
        source_ok+=int(authentically_read)
        receipt_ok+=int(native)
        global_gate=(family in ('META','GLOBAL_GATES','GLOBAL_COMPLETION',
                                'GOVERNANCE','MASTER_CHAIN'))
        conditional=(family in ('ASSET_PROFILE_READINESS',
                                 'HISTORICAL_ASSET_GATES'))
        due=(not conditional or
             (family=='ASSET_PROFILE_READINESS' and
              original.get('profile') in plan.get('profiles',[])) or
             (family=='HISTORICAL_ASSET_GATES' and
              plan.get('asset_build_context_verified') is True))
        # Any quality gate may report an original negative finding. A lack
        # of such a finding is NOT evidence that the rule passed.
        negatives=[r['record_hash'] for r in records if
            r.get('step')==step and r.get('rule_id')==rid and
            (r.get('result') in ('FAIL','BLOCKED') or
             r.get('event')=='VERIFIED_STATE_REVOKED')]
        results[rid]={
          'rule_id':rid,'family':family,
          'source_sha256':original['source_sha256'],
          'requirement_sha256':original['requirement_sha256'],
          'original_auxiliary_source_reopened':authentically_read,
          'original_current_attempt_receipt_verified':native,
          'original_global_governance_rule':global_gate,
          'current_asset_applicability':'DUE' if due else 'CONTEXT_UNKNOWN',
          'original_current_attempt_negative_hashes':negatives,
          'semantic_verdict':'FAIL' if negatives else
                      'UNKNOWN' if due else 'NOT_DUE',
          'individual_mg0':'UNKNOWN' if due else 'NOT_DUE',
          'owner_approval':'UNKNOWN',
          'delivery_remains_protected':current_blocked,
          'advancement_authorized':False
        }
    need(len(results)==67 and set(results)==set(ids),
         'R150_ORIGINAL_67_SOURCE_RULES_MISSING')
    return {
       'schema':SCHEMA,'source_rule_count':67,
       'source_families':len(EXPECTED_FAMILIES),
       'canonical_source_files_reopened':source_ok,
       'original_per_rule_witnesses_verified':receipt_ok,
       'asset':asset,'step':step,
       'master_sha256':work['master_sha256'],
       'attempt_id':work['attempt_id'],
       'operation_sha256':work['operation_sha256'],
       'original_audit_sha256':audit_sha,
       'original_audit_tail':tail,
       'full_semantic_passes':0,'individual_mg0_passes':0,
       'advancement_authorized':False,
       'rules':results,
    }
