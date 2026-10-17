"""C07 native evidence reviewers for TWO exact literal P0 process obligations.

AAA-200-R-172: Distinguere sorgenti modificabili, esportazioni e consegne.
AAA-200-R-178: Registrare dipendenze e stato reale delle attività.

A passing machine-specific semantic verdict is NOT MG0 PASS, owner acceptance,
artistic quality, authorization or release readiness. The source bytes are
independently reread from the Controller's ORIGINAL local work repository.
"""
import hashlib
import json
from pathlib import Path

from c07_positive_native_process import (RULES, inspect as base_inspect,
                                          _original_attempt, sha)
from real_work_intake import strict_json

IDS=('AAA-200-R-172','AAA-200-R-178')
SCHEMA='gg-c07-native-2-exact-process-semantics-v1'

class IncompleteSemanticRule(ValueError):pass
def need(ok,why):
    if not ok:raise IncompleteSemanticRule(why)

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    """Every observation must be independently verified against original bytes."""
    original=base_inspect(inventory,plan,controller,asset,step,work,
                          source_loader=source_loader)
    need(original['schema']=='gg-c07-r123-positive-native-process-v1'
         and set(original['rules'])==set(IDS)
         and original['rule_count']==2
         and original['full_work_rule_passes']==0
         and original['individual_mg0_passes']==0
         and original['advancement_authorized'] is False,
         'R136_ORIGINAL_SOURCE_CLAUSE_OR_FALSE_FULL_WORK_PASS')
    records,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(audit_sha==original['audit_sha256']
         and tail==original['audit_tail_sha256']
         and sha(controller.master.read_bytes())==work['master_sha256']
         and state.get('last_audit_hash')==tail,
         'R136_CURRENT_MASTER_AUDIT_STATE_CHANGED')
    # Read the ACTUAL persisted WORK_STATE file; in-memory state is insufficient
    # to demonstrate that the work and dependencies have been recorded.
    saved=getattr(controller,'state_path',None)
    persisted=False
    if type(saved) is Path and saved.is_file():
        doc=strict_json(saved.read_bytes())
        if type(doc) is dict and type(doc.get('assets')) is dict:
            persisted=(doc['assets'].get(asset)==state)
    # Exact scope must be recorded in ORIGINAL plan and reservation; missing
    # or mismatched declared dependencies are not a positive source check.
    deps=plan.get('dependency_files',{})
    bound=(type(deps) is dict and bool(deps)
           and type(work.get('work_dependencies')) is dict
           and set(deps)==set(work['work_dependencies']))
    declared_bytes=False
    if bound:
        declared_bytes=True
        for key,name in deps.items():
            path=controller.root/name if type(name) is str else None
            if (type(key) is not str or len(key)!=64
                or path is None or path.is_symlink()
                or not path.resolve().is_relative_to(controller.root.resolve())
                or not path.is_file()):
                declared_bytes=False
                break
            try:raw=source_loader(str(path))
            except (OSError,ValueError):declared_bytes=False;break
            if type(raw) is not bytes or sha(raw)!=work['work_dependencies'][key]:
                declared_bytes=False;break
    result={}
    for rid in IDS:
        n,clause,required=RULES[rid]
        canonical=inventory['rules'][rid]
        item=original['rules'][rid]
        checks=item['criteria']
        need(canonical['requirement']==clause,
             'R136_ORIGINAL_CLAUSE_DRIFT:'+rid)
        need(canonical['requirement_sha256']==sha(clause.encode('utf-8')),
             'R136_ORIGINAL_REQUIREMENT_SHA_DRIFT:'+rid)
        need(item['source_sha256']==canonical['source_sha256'],
             'R136_SOURCE_IDENTITY_DRIFT:'+rid)
        need(item['requirement_sha256']==canonical['requirement_sha256'],
             'R136_REQUIREMENT_IDENTITY_DRIFT:'+rid)
        need(set(checks)==set(required),
             'R136_CRITERIA_NOT_COMPLETE:'+rid)
        need(all(type(v) is bool for v in checks.values()),
             'R136_CRITERIA_NOT_BOOLEAN:'+rid)
        extra=({
           'persisted_live_controller_state':persisted,
           'all_declared_dependency_bytes_rechecked':declared_bytes,
           'enrolled_operation_scope_authenticated':True,
        } if rid=='AAA-200-R-178' else {
           'source_export_delivery_exact_source_bound':True,
           'correct_current_attempt_bound':True,
        })
        full=all(checks.values()) and all(extra.values())
        result[rid]={
          'rule_id':rid,
          'source_sha256':canonical['source_sha256'],
          'requirement_sha256':canonical['requirement_sha256'],
          'original_machine_criteria':checks,
          'additional_full_literal_criteria':extra,
          'exact_literal_requirement':clause,
          'literal_process_semantics':'PASS' if full else 'UNKNOWN',
          'missing_criteria':sorted([k for k,v in {**checks,**extra}.items() if not v]),
          'individual_mg0':'UNKNOWN',
          'full_work_rule_pass':False,
          'owner_acceptance':'UNKNOWN',
          'advancement_authorized':False,
        }
    return {
       'schema':SCHEMA,'asset':asset,'step':step,
       'master_sha256':work['master_sha256'],
       'attempt_id':work['attempt_id'],
       'operation_sha256':work['operation_sha256'],
       'original_audit_sha256':audit_sha,
       'original_audit_tail':tail,
       'original_persisted_state_rechecked':persisted,
       'source_rule_count':2,
       'literal_process_semantics_passes':sum(
         x['literal_process_semantics']=='PASS' for x in result.values()),
       'rules':result,
       'individual_mg0_passes':0,
       'full_work_rule_passes':0,
       'advancement_authorized':False,
    }
