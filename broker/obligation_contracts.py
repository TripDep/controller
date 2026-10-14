"""C07 full canonical obligation ledger. Never an operational PASS.

The trusted inventory has all canonical IDs and their source bindings.
This makes missing per-rule semantic validation explicit and impossible to
silently omit or conflate with CI successes. It does not pretend that a
generic evidence recipe is a semantic verifier for an individual rule.
"""
import argparse
import hashlib
import json
import os
import re
from collections import Counter

import family_coverage as coverage
import approved_validators as approved

CURRENT_MASTER='5ba978ec0543d898b1f376b2d3528aa08a36a6b46be6e429abbbc1bef87fc116'

class Blocked(ValueError): pass
def need(ok, code):
    if not ok:raise Blocked(code)
def digest(raw):return hashlib.sha256(raw).hexdigest()

def evidence_modalities(rule):
    text=rule['requirement'].casefold()
    family=rule['family']
    kinds=['CANONICAL_REQUIREMENT_SOURCE_READBACK','INDIVIDUAL_NATIVE_GIT_SEMANTIC_RESULT',
           'INDIVIDUAL_MG0_CANONICAL_TRIGGER_TRIAGE']
    if family in ('AAA-200','ASSET_PROFILE_READINESS','PROFESSIONAL_SYSTEM'):
        kinds.append('PHASE_SPECIFIC_PRODUCTION_OR_DOCUMENTARY_QA')
    if any(w in text for w in ('render','visual','proporzion','silhouett','illuminaz','material','composizion')):
        kinds.append('MULTIANGLE_VISUAL_EVIDENCE_WITH_OWNER_ARTISTIC_GATE')
    if any(w in text for w in ('terrain','terreno','pendenz','quote','profond','collision','attravers','percorr','altezz','acqua','esport','coordinate','scala')):
        kinds.append('GEOMETRY_OR_WORLD_COORDINATE_MEASUREMENT')
    if any(w in text for w in ('server','fivem','motore','gioco','runtime','streaming','performance')):
        kinds.append('TARGET_RUNTIME_OR_ENGINE_EVIDENCE')
    if any(w in text for w in ('licenz','copyright','fonte','riferiment','registr','master','workflow','autorizz','approvaz')):
        kinds.append('CANONICAL_DOCUMENT_AND_CONTROLLER_AUDIT')
    if family in ('META','GLOBAL_GATES','MASTER_CHAIN'):
        kinds.append('PROCESS_CORRECTION_RECHECK_AND_AUDIT')
    return kinds

def build(inv):
    need(isinstance(inv,dict) and inv.get('schema')=='gg-effective-family-inventory-v1',
         'LEDGER_INVENTORY_SCHEMA')
    need(inv.get('canonical_master_sha256')==CURRENT_MASTER,'LEDGER_MASTER_DRIFT')
    families=inv['families'];rules=inv['rules']
    need(isinstance(families,dict) and isinstance(rules,dict),'LEDGER_FAMILY_SCHEMA')
    flattened=[rid for family,ids in families.items() for rid in ids]
    need(len(flattened)==len(set(flattened)) and set(flattened)==set(rules),
         'LEDGER_OMITTED_OR_DUPLICATE_ID')
    entries={}
    for rid in sorted(rules):
        row=rules[rid]
        need(row.get('family') in families and rid in families[row['family']] and
             isinstance(row.get('requirement'),str) and row['requirement'].strip() and
             re.fullmatch(r'[a-f0-9]{64}',row.get('source_sha256','')) and
             re.fullmatch(r'[a-f0-9]{64}',row.get('requirement_sha256','')),
             'LEDGER_SOURCE_ID_INVALID:'+rid)
        validator=approved.REVIEWED.get(rid)
        kinds=evidence_modalities(row)
        entries[rid]={
          'family':row['family'],'canonical_requirement':row['requirement'],
          'source_sha256':row['source_sha256'],
          'requirement_sha256':row['requirement_sha256'],
          'earliest_catalog_phase':row.get('catalog_phase'),
          'canonical_asset_type':row.get('asset_type'),
          'canonical_profile':row.get('profile'),
          'current_work_applicability':'UNRESOLVED_NO_TRUSTED_CONTROLLER_WORK_RECORD',
          'required_individual_evidence_modalities':kinds,
          'rule_specific_verifier':('REVIEWED_SOURCE_PREDICATE_NOT_WORK_PASS' if validator
                                    else 'MISSING_INDEPENDENT_SEMANTIC_VERIFIER'),
          'reviewed_validator_id':validator[0] if validator else None,
          'reviewed_criteria':list(validator[1]) if validator else [],
          'work_semantic_result':'UNKNOWN',
          'individual_mg0_result':'UNKNOWN',
          'current_phase_authorized':False,
          'closure_authorized':False,
          'unresolved':['TRUSTED_PHASE_AND_ASSET_CONTEXT',
                        'WORK_ATTEMPT_BOUND_NATIVE_SEMANTIC_PROOF',
                        'INDIVIDUAL_MG0_CANONICAL_EVALUATION']+
                       ([] if validator else ['SOURCE_SPECIFIC_VERIFIER_IMPLEMENTATION'])}
    need(len(entries)==len(rules)==inv['rule_count'] and
         len(families)==inv['family_count'],'LEDGER_COUNTS')
    reviewed=sum(x['reviewed_validator_id'] is not None for x in entries.values())
    missing=len(entries)-reviewed
    by_family={family:{'registered':len(ids),
                       'reviewed_implementations':sum(entries[r]['reviewed_validator_id'] is not None for r in ids),
                       'pending_semantic_implementations':sum(entries[r]['reviewed_validator_id'] is None for r in ids)}
               for family,ids in families.items()}
    need(sum(v['registered'] for v in by_family.values())==len(entries),
         'LEDGER_FAMILY_SUM')
    return {'schema':'gg-c07-current-canonical-obligation-ledger-v1',
            'canonical_master_sha256':CURRENT_MASTER,
            'inventory_source_digests':inv['source_digests'],
            'scope':'SOURCE_AND_MISSING_EVIDENCE_CONTRACTS_NOT_WORK_AUTHORIZATION',
            'trusted_controller_work_record_supplied':False,
            'registered_families':len(families),'registered_rule_ids':len(entries),
            'reviewed_documentary_predicate_implementations':reviewed,
            'missing_semantic_verifier_implementations':missing,
            'current_operational_rule_passes':0,'individual_mg0_passes':0,
            'advancement_authorized':False,'closure_authorized':False,
            'by_family':by_family,'rules':entries}

def main(argv=None):
    from broker_live_review import decode_file
    from git_judgment_origin import OriginAPI,PRIVATE_REPO_SHA
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ref',required=True)
    a=p.parse_args(argv)
    try:
        need(re.fullmatch('[0-9a-f]{40}',a.ref) is not None,'LEDGER_IMMUTABLE_REF')
        api=OriginAPI(os.environ['GH_REVIEW_TOKEN'],os.environ['GITHUB_REPOSITORY'])
        need(digest(api.repository.encode())==PRIVATE_REPO_SHA,'LEDGER_PRIVATE_REPO_ORIGIN')
        raw={key:decode_file(api.call('GET','/contents/'+path+'?ref='+a.ref),path)
             for key,path in coverage.SOURCES.items()}
        inv=coverage.build_inventory(raw,CURRENT_MASTER)
        report=build(inv)
        summary={k:v for k,v in report.items() if k not in ('rules','by_family')}
        print('C07_FULL_INVENTORY_SOURCE_CONTRACT_SUMMARY:'+json.dumps(summary,sort_keys=True))
        for rid,record in report['rules'].items():
            print('C07_CANONICAL_RULE_CONTRACT:'+json.dumps({'id':rid,**record},sort_keys=True))
        return 0
    except (ValueError,KeyError,TypeError,OSError) as ex:
        print('C07_CONTRACT_LEDGER_BLOCKED:'+str(ex))
        return 1

if __name__=='__main__':raise SystemExit(main())
