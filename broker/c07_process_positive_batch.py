"""C07 R120 — independently observed process evidence for a whole 200-rule group.

Each positive observation is limited to an exact machine-checkable source
predicate. NO observation alone satisfies a broad canonical AAA-200 rule,
no art/owner/license/MG0 PASS is ever inferred. Read actual Controller audit
and file bytes; never a producer-generated PASS dictionary.
"""
import hashlib
import json
from pathlib import Path

from real_work_intake import audit_check

SCHEMA='gg-c07-r120-positive-process-subpredicates-v1'
# Reviewed, source-specific positive *subpredicates* only. A broad requirement
# (e.g. "follow every instruction") is NOT satisfied by a master hash match.
PREDICATES = {
    'AAA-200-A-004': 'CANONICAL_MASTER_READBACK',
    'AAA-200-A-005': 'ENROLLED_OPERATION_UNCHANGED',
    'AAA-200-B-011': 'WORK_ITEM_AND_ASSET_SCOPE_RECORDED',
    'AAA-200-B-016': 'REGISTERED_DEPENDENCIES_MATCH_BYTES',
    'AAA-200-B-017': 'DELIVERABLE_KIND_DECLARED',
    'AAA-200-R-171': 'RECORDED_ARTIFACT_NAMES_AND_ROLES',
    'AAA-200-R-172': 'SOURCE_AND_EXPORT_ARTIFACT_SEPARATION',
    'AAA-200-R-175': 'ACTUAL_REPEATED_CHECK_EVENT',
    'AAA-200-R-176': 'ACTUAL_FILE_BYTES_VERIFIED_NOT_JUST_SUCCESS_EXIT',
    'AAA-200-R-177': 'PREVIOUSLY_RECORDED_BYTES_NOT_OVERWRITTEN',
    'AAA-200-R-178': 'REAL_STATE_AND_DEPENDENCY_CHAIN',
    'AAA-200-R-179': 'NON_DUPLICATE_STEP_LINEAGE',
    'AAA-200-R-180': 'NEW_NON_DOCUMENT_MODEL_OUTPUT_RECORDED',
}
# Distinct, machine-readable supporting criteria; strictly smaller than
# each full source obligation. Never insert into approved_validators.REVIEWED.
NEEDS = {
    'AAA-200-A-004': ('master_content_matches_enrolled_source',),
    'AAA-200-A-005': ('operation_matches_enrolled_plan','reserved_operation_unchanged'),
    'AAA-200-B-011': ('exact_asset_has_registered_scope','work_item_exactly_bound'),
    'AAA-200-B-016': ('actual_dependency_bytes_match_enrollment',),
    'AAA-200-B-017': ('deliverable_artifact_kind_declared_in_plan',),
    'AAA-200-R-171': ('artifact_name_and_role_resolve_to_one_file',),
    'AAA-200-R-172': ('editable_source_and_export_exist_at_distinct_paths',),
    'AAA-200-R-175': ('independent_machine_check_event_recorded',),
    'AAA-200-R-176': ('registered_file_bytes_rehashed_and_verified',),
    'AAA-200-R-177': ('recorded_file_bytes_unchanged_since_registration',),
    'AAA-200-R-178': ('current_audit_state_and_dependencies_integral',),
    'AAA-200-R-179': ('unique_open_step_and_no_duplicate_close',),
    'AAA-200-R-180': ('new_content_distinct_model_artifact_recorded',),
}

class EvidenceBlocked(ValueError):pass

def need(x, reason):
    if not x:raise EvidenceBlocked(reason)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def digest(o):return sha(json.dumps(o,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode())

def inspect(inventory, plan, controller, asset, step, work, *, source_loader=None):
    """One trust-bound readback for 13 useful predicates within same 200 IDs.

    These observations can be POSITIVE (observed), NEGATIVE (contradicted),
    or UNKNOWN (missing evidence). Never positive per-rule work/AAA approval.
    """
    from c07_operation_scope import inspect as inspect_scope
    from c07_bulk200_semantics import _first200
    selected=_first200(inventory)
    applicability=inspect_scope(inventory,plan)
    due=set(applicability['due'])
    need(set(PREDICATES)<=set(selected) and set(PREDICATES)==set(NEEDS),
         'R120_SOURCE_FIRST200_REGISTRY_DRIFT')
    need(type(work) is dict and work.get('master_sha256')==inventory['canonical_master_sha256']
         and work.get('attempt_id') and work.get('operation_sha256') and
         type(asset) is str and asset==asset.upper() and type(step) is str and
         type(plan) is dict and callable(source_loader),
         'R120_CURRENT_WORK_BINDING_REQUIRED')
    # Original controller, NOT a JSON report provided by the assistant.
    master=controller.master.read_bytes()
    records,tail=audit_check(controller.audit_path(asset).read_bytes(),asset)
    state=controller.asset_state(asset)
    need(sha(master)==work['master_sha256'], 'R120_MASTER_ACTUAL_CONTENT_CHANGED')
    need(state.get('last_audit_hash')==tail, 'R120_WORK_STATE_AUDIT_DIVERGED')
    opens=[r for r in records if r.get('event')=='SUPERVISOR_OPERATION_OPENED'
           and r.get('step')==step]
    need(len(opens)==1, 'R120_EXACT_OPEN_STEP_REQUIRED')
    reserved=[r for r in records if r.get('event')=='SUPERVISOR_OPERATION_RESERVED'
              and r.get('record_hash')==opens[0].get('reservation_hash')]
    need(len(reserved)==1 and reserved[0].get('work')==work,
         'R120_RESERVATION_EXACT_ATTEMPT_REQUIRED')
    plans=[r for r in records if r.get('event')=='SUPERVISOR_PLAN_ENROLLED'
           and r.get('record_hash')==reserved[0].get('plan_record_hash')]
    need(len(plans)==1 and plans[0].get('plan')==plan,
         'R120_PLAN_INDEPENDENT_SOURCE_REQUIRED')
    registered=[r for r in records if r.get('event')=='ARTIFACT_RECORDED' and
                r.get('result')=='PASS' and r.get('step')==step]
    item_state=state.get('artifacts',[])
    audited_items=[]
    for ev in registered:
        row=ev.get('evidence_operation')
        need(type(row) is dict and row in item_state,
             'R120_REGISTERED_FILE_MISSING_FROM_ORIGINAL_STATE')
        path=row.get('path')
        need(type(path) is str and Path(path).is_absolute() and
             not Path(path).is_symlink() and
             type(row.get('sha256')) is str and len(row['sha256'])==64 and
             type(row.get('size_bytes')) is int and row['size_bytes']>0,
             'R120_REGISTERED_ARTIFACT_SCHEMA')
        raw=source_loader(path)
        need(type(raw) is bytes, 'R120_REGISTERED_FILE_BYTES_UNREADABLE')
        # A mutated file is a negative finding, not a silent omission.
        actual=sha(raw)
        audited_items.append({'path':path,'role':row.get('role'),
             'record_hash':ev['record_hash'],'recorded_sha256':row['sha256'],
             'actual_sha256':actual,'byte_verified':actual==row['sha256'] and
                              len(raw)==row['size_bytes'],
             'suffix':Path(path).suffix.lower()})
    dependencies={}
    for key,path in plan.get('dependency_files',{}).items():
        raw=source_loader(str(controller.root / path)) if not Path(path).is_absolute() else source_loader(path)
        need(type(raw) is bytes, 'R120_DEPENDENCY_BYTES_NOT_FOUND:'+str(key))
        dependencies[key]=sha(raw)
    registered_dependencies=work.get('work_dependencies',{})
    # Do not call missing evidence a negative fact. Separate UNKNOWN/FAIL.
    checks={}
    checks['master_content_matches_enrolled_source'] = True
    checks['operation_matches_enrolled_plan'] = (
        reserved[0]['work'].get('operation_sha256')==work['operation_sha256'])
    checks['reserved_operation_unchanged'] = opens[0]['reservation_hash']==reserved[0]['record_hash']
    checks['exact_asset_has_registered_scope'] = bool(state.get('scope'))
    checks['work_item_exactly_bound'] = (
        work.get('work_item_sha256')==hashlib.sha256(
            json.dumps(asset,sort_keys=True,separators=(',',':')).encode()).hexdigest())
    checks['actual_dependency_bytes_match_enrollment'] = bool(dependencies) and dependencies==registered_dependencies
    op=plan.get('operation',{})
    # This is only "planned deliverable category", NOT real usable delivery.
    checks['deliverable_artifact_kind_declared_in_plan'] = op.get('category') in ('GENERATION','MUTATION','EXPORT')
    checks['artifact_name_and_role_resolve_to_one_file'] = (bool(audited_items) and all(
        type(x['role']) is str and bool(x['role'].strip()) and Path(x['path']).name
        for x in audited_items) and len({x['path'] for x in audited_items})==len(audited_items))
    editable={'.blend','.blend1','.fbx','.obj'}
    exports={'.glb','.gltf','.ydr','.ytd','.yft','.ymap','.ytyp'}
    checks['editable_source_and_export_exist_at_distinct_paths'] = (
        any(x['suffix'] in editable and x['byte_verified'] for x in audited_items)
        and any(x['suffix'] in exports and x['byte_verified'] for x in audited_items))
    native=[r for r in records if r.get('event')=='SUPERVISOR_CANONICAL_NATIVE_NEGATIVE_GATE'
            and r.get('attempt_id')==work['attempt_id'] and
            r.get('operation_sha256')==work['operation_sha256'] and
            type(r.get('native_reports')) is list and bool(r['native_reports']) and
            r.get('native_reports_sha256')==sha(json.dumps(
                r['native_reports'],sort_keys=True,separators=(',',':')).encode()) and
            r.get('advancement_authorized') is False]
    checks['independent_machine_check_event_recorded'] = bool(native)
    checks['registered_file_bytes_rehashed_and_verified'] = bool(audited_items) and all(x['byte_verified'] for x in audited_items)
    checks['recorded_file_bytes_unchanged_since_registration'] = checks['registered_file_bytes_rehashed_and_verified']
    checks['current_audit_state_and_dependencies_integral'] = (
        (state.get('active_step') or {}).get('step')==step and bool(dependencies)
        and dependencies==registered_dependencies)
    # We cannot assert that checkpoint continuation itself was valid merely
    # from absence of duplicate steps; this is only one supporting predicate.
    step_open=[r for r in records if r.get('event')=='STEP_OPEN' and r.get('step')==step]
    step_close=[r for r in records if r.get('event')=='STEP_CLOSE' and r.get('step')==step]
    checks['unique_open_step_and_no_duplicate_close'] = len(step_open)==1 and len(step_close)==0
    prior_hashes={v.get('sha256') for v in item_state if v.get('step')!=step and isinstance(v,dict)}
    model_ext={'.glb','.gltf','.blend','.fbx','.obj','.ydr','.yft'}
    checks['new_content_distinct_model_artifact_recorded'] = any(
        a['byte_verified'] and a['suffix'] in model_ext and
        a['recorded_sha256'] not in prior_hashes for a in audited_items)
    need(set(checks)=={n for names in NEEDS.values() for n in names},
         'R120_PREDICATE_IMPLEMENTATION_INCOMPLETE')
    results={}
    for rid,predicate in PREDICATES.items():
        row=inventory['rules'][rid]
        need(row.get('family')=='AAA-200' and row.get('source_sha256') and
             sha(row['requirement'].encode())==row.get('requirement_sha256'),
             'R120_CANONICAL_RULE_SOURCE_DRIFT:'+rid)
        relevant=rid in due
        values={name:checks[name] for name in NEEDS[rid]}
        status=('NOT_DUE' if not relevant else 'OBSERVED_SCOPE_PASS' if all(values.values())
                else 'UNKNOWN_OR_SCOPE_FAIL')
        results[rid]={'rule_id':rid,'requirement_sha256':row['requirement_sha256'],
          'source_sha256':row['source_sha256'],'machine_predicate':predicate,
          'scope_criteria':values,'scoped_positive_observation':status,
          'complete_rule_semantics':'UNKNOWN' if relevant else 'NOT_DUE',
          'individual_mg0':'UNKNOWN' if relevant else 'NOT_DUE',
          'owner_approved':False,'work_pass':False}
    return {'schema':SCHEMA,'selected_200_source_sha256':digest(selected),
       'master_sha256':work['master_sha256'],'attempt_id':work['attempt_id'],
       'operation_sha256':work['operation_sha256'],'audit_tail':tail,
       'actual_artifacts_read':len(audited_items),
       'actual_artifact_bytes_verified':sum(bool(x['byte_verified']) for x in audited_items),
       'actual_dependency_bytes_verified':sum(dependencies.get(k)==v for k,v in registered_dependencies.items()),
       'rule_specific_machine_predicates':len(results),
       'rule_specific_scoped_observed':sum(x['scoped_positive_observation']=='OBSERVED_SCOPE_PASS' for x in results.values()),
       'rule_specific_scoped_unknown':sum(x['scoped_positive_observation']=='UNKNOWN_OR_SCOPE_FAIL' for x in results.values()),
       'complete_work_rule_passes':0, 'individual_mg0_passes':0,
       'advancement_authorized':False,'results':results,
       'scope':'POSITIVE_PROCESS_SUBPREDICATES_NOT_COMPLETE_SEMANTIC_OR_MG0_PROOF',
       'result_sha256':digest(results)}
