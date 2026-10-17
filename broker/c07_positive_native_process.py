"""C07 R123: real source-specific positive semantics for two P0 process rules.

These validators independently inspect the original Golden Controller chain,
registered file bytes and exact work attempt. They verify only the literal
source-defined PROCESS requirements, NOT artistic quality, owner approval,
FiveM runtime or MG0. A result SEMANTIC_OBSERVED is not work authorization.
Unknown/missing independent bytes never become positive just because CI is green.
"""
import hashlib
import io
import json
import re
from pathlib import Path
from zipfile import ZipFile, BadZipFile

from real_work_intake import audit_check

RULES = {
 'AAA-200-R-172': (
  172, 'Distinguere sorgenti modificabili, esportazioni e consegne.',
  ('authenticated_exact_attempt', 'editable_source_bytes_verified',
   'export_bytes_verified', 'delivery_bytes_verified',
   'distinct_explicit_artifact_roles', 'archive_safely_contains_identical_export',
   'delivery_manifest_binds_source_export_and_attempt')),
 'AAA-200-R-178': (
  178, 'Registrare dipendenze e stato reale delle attività.',
  ('authenticated_exact_attempt', 'canonical_master_bytes_verified',
   'current_audit_tail_matches_state', 'recorded_current_step',
   'all_declared_dependency_bytes_match',
   'real_activity_state_recorded_and_not_self_reported')),
}
VALIDATOR='GG_C07_R123_NATIVE_SOURCE_SPECIFIC_PROCESS_V1'
SCHEMA='gg-c07-r123-positive-native-process-v1'
SOURCE_SUFFIXES={'.blend', '.fbx', '.obj'}
EXPORT_SUFFIXES={'.glb', '.gltf', '.ydr', '.yft', '.ymap'}
ROLE_TYPES={'SOURCE_EDITABLE':SOURCE_SUFFIXES,
            'NATIVE_EXPORT':EXPORT_SUFFIXES,
            'DELIVERY_PACKAGE':{'.zip'}}
MAX_ARCHIVE=256*1024*1024

class NativeEvidenceBlocked(ValueError): pass

def need(test, reason):
    if not test: raise NativeEvidenceBlocked(reason)

def sha(b): return hashlib.sha256(b).hexdigest()

def _literal_rule(inventory, rid):
    need(inventory.get('schema')=='gg-effective-family-inventory-v1' and
         inventory.get('rule_count')==763, 'R123_CANONICAL_INVENTORY_REQUIRED')
    n,txt,criteria=RULES[rid]
    row=inventory['rules'][rid]
    need(row['family']=='AAA-200' and row.get('catalog_number')==n and
         row.get('catalog_phase')=='P0' and row.get('catalog_section')=='R' and
         row['requirement']==txt and row['requirement_sha256']==sha(txt.encode()) and
         row['source_sha256']==inventory['source_digests']['aaa_catalog'],
         'R123_LITERAL_RULE_OR_SOURCE_CHANGED:'+rid)
    return row, criteria

def _original_attempt(inventory, plan, controller, asset, step, work):
    need(type(asset) is str and asset and asset==asset.upper() and
         type(step) is str and bool(step) and type(work) is dict and type(plan) is dict,
         'R123_INVALID_OPERATION_IDENTITY')
    need(work.get('master_sha256')==inventory['canonical_master_sha256'] and
         plan.get('master_sha256')==work['master_sha256'] and
         type(work.get('attempt_id')) is str and re.fullmatch('[0-9a-f]{64}',work['attempt_id']) and
         type(work.get('operation_sha256')) is str and re.fullmatch('[0-9a-f]{64}',work['operation_sha256']),
         'R123_ATTEMPT_MASTER_BINDING_MISSING')
    raw=controller.audit_path(asset).read_bytes()
    records,tail=audit_check(raw,asset)
    state=controller.asset_state(asset)
    opens=[x for x in records if x.get('event')=='SUPERVISOR_OPERATION_OPENED'
           and x.get('step')==step]
    need(len(opens)==1, 'R123_EXACT_OPEN_STEP_REQUIRED')
    reserved=[x for x in records if x.get('event')=='SUPERVISOR_OPERATION_RESERVED'
              and x.get('record_hash')==opens[0].get('reservation_hash')]
    need(len(reserved)==1 and reserved[0].get('work')==work and
         reserved[0].get('operation_sha256')==work['operation_sha256'],
         'R123_EXACT_RESERVED_WORK_REQUIRED')
    plans=[x for x in records if x.get('event')=='SUPERVISOR_PLAN_ENROLLED'
           and x.get('record_hash')==reserved[0].get('plan_record_hash')]
    need(len(plans)==1 and plans[0].get('plan')==plan,
         'R123_ENROLLED_PLAN_NOT_AUTHENTICATED')
    need(records.index(plans[0])<records.index(reserved[0])<records.index(opens[0]),
         'R123_PLAN_RESERVE_OPEN_ORDER')
    return records,tail,state,sha(raw)

def _registered_artifacts(records, state, step, source_loader, work):
    # R125: an identical step label alone is NOT evidence of the current attempt.
    opened=[(i,e) for i,e in enumerate(records)
            if e.get('event')=='SUPERVISOR_OPERATION_OPENED'
            and e.get('step')==step]
    need(len(opened)==1,'R125_ARTIFACT_OPERATION_OPEN_UNIQUE')
    open_index,opening=opened[0]
    reservation=[r for r in records
                 if r.get('event')=='SUPERVISOR_OPERATION_RESERVED'
                 and r.get('record_hash')==opening.get('reservation_hash')]
    need(len(reservation)==1
         and reservation[0].get('work')==work
         and reservation[0].get('operation_sha256')==work.get('operation_sha256')
         and records.index(reservation[0])<open_index,
         'R125_ARTIFACT_ATTEMPT_RESERVATION_MISMATCH')
    closing=[i for i,e in enumerate(records)
             if e.get('step')==step and
             e.get('event') in ('STEP_CLOSE','SUPERVISOR_OPERATION_CLOSED')]
    need(not any(i<open_index for i in closing),
         'R125_ARTIFACT_HISTORIC_CLOSED_STEP_REUSED')
    scoped=[(i,e) for i,e in enumerate(records)
            if e.get('event')=='ARTIFACT_RECORDED' and e.get('step')==step]
    need(all(i>open_index and
             (not closing or i<min(closing)) and
             e.get('result')=='PASS' for i,e in scoped),
         'R125_ARTIFACT_OUTSIDE_CURRENT_OPERATION_WINDOW')
    current=[x for x in state.get('artifacts',[])
             if type(x) is dict and x.get('step')==step]
    need(len(scoped)==len(current)
         and all(current.count(e.get('evidence_operation'))==1
                 for _,e in scoped),
         'R125_STATE_ARTIFACT_AUDIT_SET_DIVERGED')
    entries=[ev for ev in records if ev.get('event')=='ARTIFACT_RECORDED'
             and ev.get('step')==step and ev.get('result')=='PASS']
    result=[]
    seen=set()
    for ev in entries:
        info=ev.get('evidence_operation')
        need(type(info) is dict and info in state.get('artifacts',[]),
             'R123_ARTIFACT_NOT_IN_ORIGINAL_CONTROLLER_STATE')
        path=info.get('path')
        need(type(path) is str and Path(path).is_absolute() and
             str(Path(path))==path and path not in seen and
             Path(path).resolve()==Path(path) and
             not Path(path).is_symlink(), 'R123_ARTIFACT_PATH_AMBIGUOUS')
        seen.add(path)
        role=info.get('role')
        # Unknown roles are not silently interpreted as one of the three.
        suffix=Path(path).suffix.lower()
        if role in ROLE_TYPES:
            need(suffix in ROLE_TYPES[role], 'R123_ROLE_EXTENSION_CONTRADICTION')
        binary=source_loader(path)
        need(type(binary) is bytes and len(binary)>0 and
             sha(binary)==info.get('sha256') and
             len(binary)==info.get('size_bytes'),
             'R123_REGISTERED_ARTIFACT_BYTES_CHANGED')
        result.append((role,path,info['sha256'],binary))
    return result

def _archive_semantics(delivery,export,source,asset,work):
    data=delivery[3]
    if len(data)>MAX_ARCHIVE: return False,False
    try:
        with ZipFile(io.BytesIO(data),'r') as z:
            contents=z.infolist()
            names=[x.filename for x in contents]
            if (len(names)!=len(set(names)) or len(names)>256 or
                any(x.is_dir() or x.filename.startswith('/') or '\\' in x.filename or
                    '..' in Path(x.filename).parts or x.file_size>MAX_ARCHIVE
                    for x in contents) or
                'C07_DELIVERY_MANIFEST.json' not in names):
                return False,False
            manifest=json.loads(z.read('C07_DELIVERY_MANIFEST.json'))
            expected={'schema','asset','attempt_id','source_sha256',
                      'export_sha256','export_member'}
            if (type(manifest) is not dict or set(manifest)!=expected or
                manifest['schema']!='gg-c07-delivery-source-export-binding-v1' or
                manifest['asset']!=asset or manifest['attempt_id']!=work['attempt_id'] or
                manifest['source_sha256']!=source[2] or
                manifest['export_sha256']!=export[2] or
                type(manifest['export_member']) is not str):
                return False,False
            member=manifest['export_member']
            if member not in names or Path(member).suffix.lower() not in EXPORT_SUFFIXES:
                return False,False
            return z.read(member)==export[3], True
    except (BadZipFile, KeyError, TypeError, ValueError, UnicodeError, OSError, RuntimeError):
        return False,False

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    """Perform TWO real native semantic validators in one Controller readback.

    PASS is deliberately called SEMANTIC_OBSERVED, not WORK_PASS/MG0_PASS.
    No producer YES, fixtures, unverified owner identity or status packet is used.
    """
    need(callable(source_loader), 'R123_ORIGINAL_FILE_READER_REQUIRED')
    for rid in RULES: _literal_rule(inventory,rid)
    records,tail,state,audit_sha=_original_attempt(inventory,plan,controller,asset,step,work)
    master=controller.master.read_bytes()
    master_ok=sha(master)==work['master_sha256']
    state_ok=state.get('last_audit_hash')==tail
    step_ok=(state.get('active_step') or {}).get('step')==step
    deps=plan.get('dependency_files',{})
    deps_ok=(type(deps) is dict and bool(deps) and
             type(work.get('work_dependencies')) is dict and
             set(deps)==set(work['work_dependencies']))
    if deps_ok:
        for key,path in deps.items():
            need(type(key) is str and re.fullmatch('[0-9a-f]{64}',key) and
                 type(path) is str and path and '\\' not in path and
                 not Path(path).is_absolute() and '..' not in Path(path).parts and
                 (controller.root / path).resolve().is_relative_to(controller.root.resolve()),
                 'R123_DEPENDENCY_PATH_OUTSIDE_CONTROLLER')
            raw=source_loader(str(controller.root / path))
            if type(raw) is not bytes or sha(raw)!=work['work_dependencies'][key]:
                deps_ok=False
                break
    # The operation is authentic even when a predicate fails. Contradicted
    # master/audit/deps are hard stops and never convert to missing-evidence YES.
    need(master_ok and state_ok and step_ok, 'R123_ORIGINAL_MASTER_OR_AUDIT_STATE_DIVERGED')
    artifact_rows=_registered_artifacts(records,state,step,source_loader,work)
    unique_by_role={role:[x for x in artifact_rows if x[0]==role]
                    for role in ROLE_TYPES}
    distinct=(all(len(rows)==1 for rows in unique_by_role.values()) and
              len({x[1] for rows in unique_by_role.values() for x in rows})==3)
    archive_ok=manifest_ok=False
    if distinct:
        source=unique_by_role['SOURCE_EDITABLE'][0]
        export=unique_by_role['NATIVE_EXPORT'][0]
        delivery=unique_by_role['DELIVERY_PACKAGE'][0]
        archive_ok,manifest_ok=_archive_semantics(delivery,export,source,asset,work)
    observations={
      'AAA-200-R-172':{
        'authenticated_exact_attempt':True,
        'editable_source_bytes_verified':len(unique_by_role['SOURCE_EDITABLE'])==1,
        'export_bytes_verified':len(unique_by_role['NATIVE_EXPORT'])==1,
        'delivery_bytes_verified':len(unique_by_role['DELIVERY_PACKAGE'])==1,
        'distinct_explicit_artifact_roles':distinct,
        'archive_safely_contains_identical_export':archive_ok,
        'delivery_manifest_binds_source_export_and_attempt':manifest_ok,
      },
      'AAA-200-R-178':{
        'authenticated_exact_attempt':True,
        'canonical_master_bytes_verified':master_ok,
        'current_audit_tail_matches_state':state_ok,
        'recorded_current_step':step_ok,
        'all_declared_dependency_bytes_match':deps_ok,
        'real_activity_state_recorded_and_not_self_reported':bool(
          state.get('active_step')) and bool(state.get('scope')) and
          (state.get('active_step') or {}).get('step')==step and
          len([x for x in records if x.get('event')=='STEP_OPEN' and
               x.get('step')==step])==1 and
          records.index(next(x for x in records if x.get('event')=='STEP_OPEN'
                             and x.get('step')==step)) <
          records.index(next(x for x in records if x.get('event')=='SUPERVISOR_OPERATION_OPENED'
                             and x.get('step')==step)),
      },
    }
    result={}
    for rid,criteria in observations.items():
        row,required=_literal_rule(inventory,rid)
        need(set(criteria)==set(required), 'R123_CRITERIA_COVERAGE_MISMATCH:'+rid)
        missing=sorted(k for k,v in criteria.items() if v is not True)
        result[rid]={
          'rule_id':rid,'validator_id':VALIDATOR,
          'source_sha256':row['source_sha256'],
          'requirement_sha256':row['requirement_sha256'],
          'criteria':criteria,'missing_criteria':missing,
          'semantic_result':'SEMANTIC_OBSERVED' if not missing else 'UNKNOWN',
          'individual_mg0':'UNKNOWN', 'owner_approved':False,
          'advancement_authorized':False,
        }
    return {'schema':SCHEMA,'master_sha256':work['master_sha256'],
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'audit_sha256':audit_sha,'audit_tail_sha256':tail,
            'rule_count':len(result),'machine_semantic_observed_count':sum(
                 x['semantic_result']=='SEMANTIC_OBSERVED' for x in result.values()),
            'source_specific_positive_engines_evaluated':2,
            'full_work_rule_passes':0,'individual_mg0_passes':0,
            'advancement_authorized':False,'rules':result}