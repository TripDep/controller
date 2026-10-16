"""C07 current-work process semantics for AAA-200-R-178 only.

Rule: record real activity state and source dependencies. Independently read
Golden Controller master, its entire hash-chained audit, the current state and
actual dependency bytes. A scoped process observation is NOT a full 3D, MG0,
visual, asset acceptance or Git native per-rule approval.
"""
import hashlib
import re
from real_work_intake import audit_check

RULE_ID='AAA-200-R-178'
RULE_TEXT='Registrare dipendenze e stato reale delle attività.'
SCHEMA='gg-c07-r178-current-process-readback-v1'

class ProcessBindingError(ValueError):
    pass

def need(x,reason):
    if not x:raise ProcessBindingError(reason)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def inspect(controller, asset, step, work, plan, inventory, source_loader):
    need(inventory.get('schema')=='gg-effective-family-inventory-v1' and
         inventory.get('rule_count')==763 and
         RULE_ID in inventory.get('rules',{}),
         'R178_CANONICAL_763_REQUIRED')
    row=inventory['rules'][RULE_ID]
    need(row.get('family')=='AAA-200' and row.get('catalog_number')==178
         and row.get('catalog_section')=='R' and row.get('catalog_phase')=='P0'
         and row.get('requirement')==RULE_TEXT and
         row.get('requirement_sha256')==sha(RULE_TEXT.encode('utf-8')),
         'R178_CANONICAL_REQUIREMENT_CHANGED')
    need(type(asset) is str and asset==asset.upper() and
         type(step) is str and step and
         type(work) is dict and type(plan) is dict and callable(source_loader),
         'R178_WORK_SCHEMA')
    sha_check=re.compile(r'[a-f0-9]{64}\Z')
    need(all(type(work.get(k)) is str and sha_check.fullmatch(work[k])
             for k in ('master_sha256','attempt_id','operation_sha256')) and
         work['master_sha256']==inventory['canonical_master_sha256'],
         'R178_EXACT_WORK_BINDING')
    master_bytes=controller.master.read_bytes()
    records,tail=audit_check(controller.audit_path(asset).read_bytes(),asset)
    state=controller.asset_state(asset)
    reserve=[x for x in records if x.get('event')=='SUPERVISOR_OPERATION_RESERVED'
             and x.get('operation_sha256')==work['operation_sha256']
             and x.get('work',{}).get('attempt_id')==work['attempt_id']]
    need(len(reserve)==1,'R178_RESERVATION_MISSING_OR_DUPLICATED')
    reserved=reserve[0]
    opened=[x for x in records if x.get('event')=='SUPERVISOR_OPERATION_OPENED'
            and x.get('reservation_hash')==reserved['record_hash']
            and x.get('step')==step]
    need(len(opened)==1,'R178_OPERATION_OPEN_MISSING_OR_DUPLICATED')
    plans=[x for x in records if x.get('event')=='SUPERVISOR_PLAN_ENROLLED'
           and x['record_hash']==reserved.get('plan_record_hash')]
    need(len(plans)==1 and plans[0].get('plan')==plan,
         'R178_ENROLLED_PLAN_NOT_AUTHENTICATED')
    need(type(work.get('work_dependencies')) is dict and
         type(plan.get('dependency_files')) is dict and
         set(work['work_dependencies'])==set(plan['dependency_files']) and
         len(work['work_dependencies'])>0,
         'R178_DEPENDENCY_SET_INVALID')
    observed={}
    for key,path in plan['dependency_files'].items():
        need(type(key) is str and sha_check.fullmatch(key) and
             type(path) is str and bool(path),
             'R178_DEPENDENCY_SOURCE_SCHEMA')
        loaded=source_loader(path)
        need(type(loaded) is bytes,'R178_DEPENDENCY_CONTENT_MISSING')
        observed[key]=sha(loaded)
    checks={
       'canonical_master_actual_bytes':sha(master_bytes)==work['master_sha256'],
       'chain_state_at_current_tail':state.get('last_audit_hash')==tail,
       'operation_opened_after_reservation':records.index(reserved)<records.index(opened),
       'current_active_step_matches_operation':(state.get('active_step') or {}).get('step')==step,
       'reserved_work_is_current_work':reserved['work']==work,
       'immutable_dependency_bytes_match_registration':observed==work['work_dependencies'],
       'plan_and_operation_recorded_with_sha':True,
    }
    errors=[k for k,v in checks.items() if v is not True]
    return {'schema':SCHEMA,'rule_id':RULE_ID,
            'master_sha256':work['master_sha256'],
            'operation_sha256':work['operation_sha256'],
            'attempt_id':work['attempt_id'],
            'requirement_sha256':row['requirement_sha256'],
            'audit_tail':tail,'audit_events_checked':len(records),
            'dependency_ids_sha256':sha(('\n'.join(sorted(observed))).encode()),
            'dependency_bytes_checked':len(observed),
            'criteria':checks,'failed_criteria':errors,
            'current_operation_process_observation':'PASS' if not errors else 'FAIL',
            'scope':'REGISTERED_DEPENDENCIES_AND_CURRENT_CONTROLLER_STATE_ONLY',
            'positive_3d_rule_semantic_passes':0,'individual_mg0_passes':0,
            'advancement_authorized':False}
