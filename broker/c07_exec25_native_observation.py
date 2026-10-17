"""C07 R129: original-source individual machine observations for EXEC-001..025.

Read the original hash-chained Controller audit, original MASTER rule clauses
and real registered file bytes. These are 25 different scoped predicates, NOT
full semantically approved verifiers, owner QA, native Git review or MG0.
"""
import hashlib
import re
from pathlib import Path

from family_coverage import block
from c07_operation_scope import inspect as operation_scope
from c07_positive_native_process import _original_attempt, _registered_artifacts

SCHEMA='gg-c07-r129-exec25-native-original-process-v1'
IDS=tuple('EXEC-'+str(i).zfill(3) for i in range(1,26))

class UnverifiedSource(ValueError):pass

def need(test,reason):
    if not test:raise UnverifiedSource(reason)

def sha(data):return hashlib.sha256(data).hexdigest()

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(callable(source_loader) and type(plan) is dict and type(work) is dict,
         'R129_REQUIRED_ORIGINAL_SOURCE_READER')
    need(inventory.get('schema')=='gg-effective-family-inventory-v1' and
         inventory.get('rule_count')==763 and
         inventory.get('canonical_master_sha256')==work.get('master_sha256'),
         'R129_CANONICAL_INVENTORY_OR_MASTER_DRIFT')
    scope=operation_scope(inventory,plan)
    need(set(IDS)<=set(scope['due']),'R129_ALL_EXEC25_MUST_BE_DUE')
    raw=controller.master.read_bytes()
    need(type(raw) is bytes and sha(raw)==work['master_sha256'],
         'R129_ORIGINAL_MASTER_BYTES_CHANGED')
    source=raw.decode('utf-8',errors='strict')
    boundary=source.find('# 13. Current Pavilion / Golden Ting state')
    need(boundary>0,'R129_ACTIVE_MASTER_PROCESS_SOURCE_MISSING')
    source=source[:boundary]
    headings=re.findall(r'(?m)^## EXEC-(\d{3}) —',source)
    need(headings==[str(i).zfill(3) for i in range(1,26)],
         'R129_25_EXEC_CANONICAL_HEADINGS_CHANGED')
    for rid in IDS:
        entry=inventory['rules'][rid]
        original=block(source,'## '+rid+' —')
        need(entry.get('source')=='master' and entry.get('family')=='EXECUTION'
             and entry.get('source_sha256')==work['master_sha256']
             and entry.get('requirement')==original
             and entry.get('requirement_sha256')==sha(original.encode()),
             'R129_RULE_SOURCE_CHANGED:'+rid)
    rows,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'R129_STATE_AND_ORIGINAL_AUDIT_DRIFT')
    opened=[i for i,r in enumerate(rows) if
            r.get('event')=='SUPERVISOR_OPERATION_OPENED'
            and r.get('step')==step]
    need(len(opened)==1,'R129_ONE_ORIGINAL_OPEN_STEP_REQUIRED')
    position=opened[0]
    need(rows[position].get('operation_sha256')==work['operation_sha256'],
         'R129_OTHER_OPERATION_REPLAY')
    current=rows[position+1:]
    need(not any(r.get('event') in ('STEP_CLOSE','SUPERVISOR_OPERATION_CLOSED')
                 and r.get('step')==step for r in current),
         'R129_ALREADY_CLOSED_STEP')
    artifacts=_registered_artifacts(rows,state,step,source_loader,work)
    exports=[a for a in artifacts if a[0]=='NATIVE_EXPORT']
    deps=plan.get('dependency_files',{})
    need(type(deps) is dict and bool(deps) and
         type(work.get('work_dependencies')) is dict and
         set(deps)==set(work['work_dependencies']),
         'R129_DEPENDENCY_SET_NOT_ORIGINAL')
    verified_dependencies=0
    for key,path in deps.items():
        need(type(key) is str and re.fullmatch(r'[a-f0-9]{64}',key)
             and type(path) is str and path and '\\\\' not in path,
             'R129_DEPENDENCY_SCHEMA')
        p=Path(path)
        need(not p.is_absolute() and '..' not in p.parts,
             'R129_DEPENDENCY_TRAVERSAL')
        f=controller.root/p
        need(f.resolve().is_relative_to(controller.root.resolve())
             and f.is_file() and not f.is_symlink(),
             'R129_DEPENDENCY_ORIGINAL_FILE_NOT_ALLOWED')
        data=f.read_bytes()
        need(data and sha(data)==work['work_dependencies'][key],
             'R129_DEPENDENCY_ORIGINAL_BYTES_CHANGED')
        verified_dependencies+=1
    history=[r for r in rows[:position] if
             r.get('event')=='STEP_CLOSE' and r.get('result')=='PASS']
    prior_artifacts=[r for r in rows[:position] if
                     r.get('event')=='ARTIFACT_RECORDED']
    issues=[r for r in rows if r.get('event')=='QUALITY_FINDING']
    # One independent, bounded observation PER original clause. The other
    # predicate is deliberately not asserted: actual quality, outcome and
    # professional behavior cannot be proved by a signed claim or event name.
    checks={
  1:{'pre_D_scope_authentically_enrolled':bool(plan.get('operation',{}).get('action')),'post_D_expected_result_measured':False},
  2:{'existing_VERIFIED_baseline_observed':bool(history),'all_affected_VERIFIED_invalidated_and_rechecked':False},
  3:{'declared_direct_dependency_bytes_authenticated':verified_dependencies > 0,'complete_transitive_dependency_chain_evaluated':False},
  4:{'pre_D_plan_authentically_enrolled':bool(plan.get('operation',{}).get('action')),'objective_immutable_PASS_criteria_verified':False},
  5:{'registered_output_bytes_independently_read':bool(exports),'full_geometry_visual_runtime_evidence_certified':False},
  6:{'original_issue_register_scanned':bool(issues),'all_mandatory_OPEN_issues_closed_before_optional_polish':False},
  7:{'work_scope_and_operation_bound_to_one_attempt':bool(plan.get('operation',{}).get('action')),'timebox_budget_breach_escalation_correlated':False},
  8:{'historical_protected_work_records_present':bool(prior_artifacts),'actual_restorable_rollback_bytes_verified':False},
  9:{'real_quality_findings_in_audit_examined':bool(issues),'all_unregistered_discovered_issues_exhaustively_excluded':False},
  10:{'declared_input_dependency_files_hash_verified':verified_dependencies > 0,'all_necessary_models_references_images_prior_states_checked':False},
  11:{'actual_operation_scope_identified':bool(plan.get('operation',{}).get('action')),'critical_facts_inferences_assumptions_independently_discriminated':False},
  12:{'root_cause_audit_event_observed':any(r.get('event')=='MG0_PROCESS_ROOT_CAUSE' and r.get('step')==step for r in current),'correction_really_addressed_the_root_cause':False},
  13:{'subcomponents_explicitly_named':bool(plan.get('operation',{}).get('sections')),'recursion_only_for_material_scope_changes_proven':False},
  14:{'historical_PASS_baseline_seen':bool(history),'whole_system_before_after_no_regression_verified':False},
  15:{'internal_delivery_gate_was_run':any(r.get('event')=='DELIVERY_GATE_CHECK' and r.get('step')==step for r in current),'independent_preflight_would_pass_without_owner_QA':False},
  16:{'fresh_eye_audit_event_seen':any(r.get('event')=='FRESH_EYES_REVIEW' and r.get('step')==step for r in current),'alternate_view_with_independent_CG1_CG4_qa_verified':False},
  17:{'25_original_process_rule_sources_verified':True,'bidirectional_requirement_piece_evidence_traceability_proven':False},
  18:{'direct_dependency_bytes_unchanged':verified_dependencies > 0,'all_decision_and_interface_contradictions_resolved':False},
  19:{'actual_native_export_recorded':bool(exports),'visual_hierarchy_density_and_rest_zones_verified':False},
  20:{'original_export_bytes_exist':bool(exports),'intention_blind_independent_player_view_passed':False},
  21:{'pre_D_scope_was_pre_enrolled':bool(plan.get('operation',{}).get('action')),'objective_measurable_independent_pass_fail_oracle_proven':False},
  22:{'original_export_bytes_registered':bool(exports),'view_angle_distance_light_scale_perturbation_qa_passed':False},
  23:{'current_dependencies_rechecked':verified_dependencies > 0,'all_geometry_boundary_transitions_separately_qa_passed':False},
  24:{'audited_failure_classes_measurably_counted':bool(issues),'global_cumulative_defect_impact_independently_verified':False},
  25:{'historical_source_artifacts_in_audit':bool(prior_artifacts),'component_reuse_in_new_context_independently_reverified':False}
    }
    need(len(checks)==25 and all(len(v)==2 and
         all(type(x) is bool for x in v.values()) and
         sum(x is False for x in v.values())>=1 for v in checks.values()),
         'R129_MUST_NEVER_CREATE_FAKE_FULL_NATIVE_PASS')
    detail={}
    for i,rid in enumerate(IDS,1):
        c=checks[i]
        detail[rid]={
          'rule_id':rid,
          'requirement_sha256':inventory['rules'][rid]['requirement_sha256'],
          'source_sha256':inventory['rules'][rid]['source_sha256'],
          'scoped_machine_predicates':c,
          'actually_observed':sorted(k for k,v in c.items() if v),
          'missing_independent_semantics':sorted(k for k,v in c.items() if not v),
          'full_rule_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
          'native_git_reviewer':'UNKNOWN','owner_approval':'UNKNOWN',
          'full_rule_pass':False,'advancement_authorized':False
        }
    return {'schema':SCHEMA,'source_rule_count':25,
            'source_rule_ids':list(IDS),'rule_ids_sha256':sha(
                ('|'.join(IDS)).encode()),
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'master_sha256':work['master_sha256'],
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'registered_artifact_bytes_verified':len(artifacts),
            'dependency_bytes_verified':verified_dependencies,
            'machine_predicates_observed':sum(len(x['actually_observed'])
                                             for x in detail.values()),
            'full_rule_passes':0,'individual_mg0_passes':0,
            'advancement_authorized':False,'rules':detail}
