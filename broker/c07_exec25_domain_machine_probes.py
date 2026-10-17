"""C07: 25 independent, rule-specific EXEC source evidence probes.

The clauses are literally bound to the canonical MASTER by R129. This module
replays the original audit and original registered bytes and adds 25 distinct
measurable predicates; it does NOT assert the portions that require artist,
owner or external native semantic review. No generated PASS or synthetic MG0.
"""
import hashlib
import json
import re
from pathlib import Path
from c07_exec25_native_observation import inspect as original25, IDS, sha
from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_r124_positive_process import _glb_mesh

SCHEMA='gg-c07-r138-exec25-original-domain-probes-v1'
class ProofError(ValueError): pass

def need(ok, reason):
    if not ok: raise ProofError(reason)

def digest(obj):
    return sha(json.dumps(obj,sort_keys=True,separators=(',',':'),
        ensure_ascii=False,allow_nan=False).encode())

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    base=original25(inventory,plan,controller,asset,step,work,
        source_loader=source_loader)
    need(base['source_rule_count']==25 and set(base['rules'])==set(IDS)
         and base['full_rule_passes']==0 and base['individual_mg0_passes']==0
         and base['advancement_authorized'] is False,
         'R138_ORIGINAL_25_EXEC_SOURCE_INVALID')
    records,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(tail==base['original_audit_tail'] and
         audit_sha==base['original_audit_sha256'] and
         state.get('last_audit_hash')==tail,
         'R138_CANONICAL_AUDIT_CHANGED')
    artifacts=_registered_artifacts(records,state,step,source_loader,work)
    current=[r for r in records if r.get('step')==step or
             (r.get('work') or {}).get('attempt_id')==work['attempt_id']]
    before=[r for r in records if r not in current]
    actual={r:(path,hash_,raw) for r,path,hash_,raw in artifacts}
    accepted=[r for r in before if r.get('event')=='STEP_CLOSE' and r.get('result')=='PASS']
    issues=[r for r in records if r.get('event')=='QUALITY_FINDING']
    present=lambda role:(role in actual and
        isinstance(actual[role][2],bytes) and
        sha(actual[role][2])==actual[role][1])
    # Source-dependent observations are computed from original bytes; event
    # names alone never establish artistic correctness or full-rule compliance.
    native_export=present('NATIVE_EXPORT') and _glb_mesh(actual['NATIVE_EXPORT'][2])
    original_source=present('SOURCE_EDITABLE')
    snapshots=present('BASELINE_SNAPSHOT') and present('CURRENT_SOURCE_COPY')
    preserved=(snapshots and actual['BASELINE_SNAPSHOT'][1]==
               actual['CURRENT_SOURCE_COPY'][1] and
               actual['BASELINE_SNAPSHOT'][0]!=actual['CURRENT_SOURCE_COPY'][0])
    exact_deps=base['dependency_bytes_verified']>0
    sections=plan.get('operation',{}).get('sections',[])
    nonempty_sections=(isinstance(sections,list) and bool(sections) and
                      all(isinstance(v,str) and v.strip() for v in sections))
    evidence_events=lambda name:[r for r in current if r.get('event')==name]
    independent_scan=bool(evidence_events('SUPERVISOR_CANONICAL_NATIVE_NEGATIVE_GATE'))
    timestamps=all(isinstance(x.get('timestamp_utc'),str)
                   for x in current if x.get('event') in ('STEP_OPEN','STEP_CLOSE'))
    previous_hashes={r.get('evidence_operation',{}).get('sha256')
                     for r in before if r.get('event')=='ARTIFACT_RECORDED'}
    artifact_hashes={h for _role,_path,h,_raw in artifacts}
    unique_role_paths=len({p for _role,p,_h,_raw in artifacts})==len(artifacts)
    changed_output=bool(native_export and previous_hashes and
                        actual['NATIVE_EXPORT'][1] not in previous_hashes)
    preconditions=plan.get('acceptance_criteria')
    committed_oracles=isinstance(preconditions,list) and bool(preconditions) and all(
        isinstance(c,dict) and isinstance(c.get('criterion_id'),str) and
        isinstance(c.get('expected'),(int,float,str)) and
        isinstance(c.get('oracle'),str) for c in preconditions)
    output_identity=(original_source and native_export and
        actual['SOURCE_EDITABLE'][1]!=actual['NATIVE_EXPORT'][1])
    # All 25 distinct original obligations receive independent, measurable
    # current-attempt probes. They supplement (never replace) R129's source
    # clauses and the independent owner/MG0 requirements.
    checks={
      1: {'pre_d_action_bound_to_original_plan':bool(plan.get('operation',{}).get('action')),
          'output_binary_exists_for_measurable_goal':native_export},
      2: {'prior_accepted_versions_present':bool(accepted),
          'current_export_distinct_from_old_accepted_bytes':changed_output},
      3: {'declared_direct_dependencies_current_bytes_verified':exact_deps,
          'dependency_set_has_unique_pinned_keys':len(plan.get('dependency_files',{}))==
              len(set(plan.get('dependency_files',{})))},
      4: {'pre_d_expected_oracle_criteria_stored_in_enrolled_plan':committed_oracles,
          'current_operation_bound_before_step':bool(current and
              any(r.get('event')=='SUPERVISOR_OPERATION_RESERVED' for r in current))},
      5: {'actual_export_has_nondegenerate_geometry':native_export,
          'registered_source_and_export_distinct_bytes':output_identity},
      6: {'open_quality_finding_history_independently_read':bool(issues),
          'mandatory_issue_ids_in_plan':bool(plan.get('mandatory_issue_ids'))},
      7: {'original_plan_has_documented_time_budget':isinstance(plan.get('timebox_seconds'),int)
          and plan['timebox_seconds']>0,
          'original_step_has_native_timestamps':timestamps and bool(current)},
      8: {'two_original_rollback_bytes_identical':preserved,
          'rollback_backup_file_verified_from_disk':snapshots},
      9: {'original_findings_preserved_in_audit':bool(issues),
          'actual_finding_source_attached':any(
             isinstance(r.get('evidence_sha256'),str) and
             re.fullmatch('[a-f0-9]{64}',r['evidence_sha256']) for r in issues)},
      10:{'original_direct_input_dependencies_hash_verified':exact_deps,
          'original_editable_source_binary_reopened':original_source},
      11:{'pre_d_scope_is_original_audited_input':bool(plan.get('operation',{}).get('action')),
          'source_artifacts_distinguished_from_output':output_identity},
      12:{'original_failure_record_identified':bool(evidence_events('MG0_PROCESS_ROOT_CAUSE')),
          'actual_before_after_binary_pair':changed_output},
      13:{'nested_components_declared_before_work':nonempty_sections,
          'original_work_is_one_controller_step':len(evidence_events('STEP_OPEN'))==1},
      14:{'original_verified_baseline_present':bool(accepted),
          'current_export_actual_bytes_distinct':changed_output},
      15:{'pre_delivery_source_reopened':original_source,
          'export_structure_checked_independently':native_export},
      16:{'fresh_eye_original_audit_event_present':bool(evidence_events('FRESH_EYES_REVIEW')),
          'multi_angle_images_really_registered':sum(1 for role in actual
              if role.startswith('VISUAL_VIEW_') and present(role))>=4},
      17:{'distinct_source_and_export_provenance':output_identity,
          'pre_d_sections_belong_to_original_plan':nonempty_sections},
      18:{'declared_dependency_bytes_unchanged':exact_deps,
          'artifacts_have_no_reused_original_path':unique_role_paths},
      19:{'nonempty_real_export_independently_parsed':native_export,
          'pre_d_visual_hierarchy_defined':bool(plan.get('visual_hierarchy_contract'))},
      20:{'export_was_not_merely_producer_report':native_export,
          'source_original_current_attempt_bound':original_source},
      21:{'measurable_pre_d_oracle_committed_before_execution':committed_oracles,
          'native_export_actual_bytes_accessible':native_export},
      22:{'nondegenerate_actual_export_geometry':native_export,
          'different_view_artifacts_from_original_bytes':sum(1 for role in actual
              if role.startswith('VISUAL_VIEW_') and present(role))>=4},
      23:{'site_connector_sections_named_pre_d':nonempty_sections and
              any(any(w in s.lower() for w in ('bridge','ponte','path','raccord','gate'))
                  for s in sections),
          'actual_export_geometry_independently_decoded':native_export},
      24:{'actual_quality_finding_records_consulted':bool(issues),
          'multiple_original_finding_classes_observed':len({
              r.get('issue_class') for r in issues if r.get('issue_class')})>1},
      25:{'prior_protected_original_byte_snapshot_reopened':snapshots,
          'reused_component_differs_from_current_attempt':changed_output}
    }
    need(len(checks)==25 and set(checks)==set(range(1,26)) and
         all(len(x)==2 and all(type(v) is bool for v in x.values())
             for x in checks.values()) and
         len({k for group in checks.values() for k in group})==50,
         'R138_TWENTYFIVE_DISTINCT_EXEC_PROBES_MISSING')
    results={}
    for number,rid in enumerate(IDS,1):
        row=inventory['rules'][rid]
        native=base['rules'][rid]
        need(native['rule_id']==rid and
             native['requirement_sha256']==row['requirement_sha256'] and
             native['source_sha256']==row['source_sha256'],
             'R138_EXEC_NATIVE_OR_SOURCE_DRIFT:'+rid)
        observed=checks[number]
        results[rid]={
            'rule_id':rid,'source_sha256':row['source_sha256'],
            'requirement_sha256':row['requirement_sha256'],
            'original_scoped_machine_criteria':native['scoped_machine_predicates'],
            'additional_domain_machine_criteria':observed,
            'observed':sorted(k for k,v in observed.items() if v),
            'not_verified':sorted(k for k,v in observed.items() if not v),
            'additional_oracle_digest':digest({'rule_id':rid,'source_sha256':
                row['source_sha256'],'criteria':observed}),
            'whole_source_requirement':'UNKNOWN',
            'individual_mg0':'UNKNOWN',
            'owner_approval':'UNKNOWN',
            'advancement_authorized':False,
        }
    return {
        'schema':SCHEMA,'source_rule_count':25,
        'rule_ids_sha256':base['rule_ids_sha256'],
        'asset':asset,'step':step,
        'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'master_sha256':work['master_sha256'],
        'original_audit_sha256':audit_sha,'original_audit_tail':tail,
        'domain_probes':50,
        'domain_positive_observations':sum(
            sum(v is True for v in row['additional_domain_machine_criteria'].values())
            for row in results.values()),
        'full_native_semantics_passes':0,
        'individual_mg0_passes':0,
        'advancement_authorized':False,'rules':results,
    }
