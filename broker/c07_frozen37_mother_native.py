"""C07 R142 — thirty-seven distinct mother-control and G0 evidence probes.

Original source SHA, real Controller audit, current attempt and the *actual*
registered file bytes are reread, not accepted from a producer PASS claim.
These are 37 source-specific MACHINE observations. Qualitative process,
legitimate owner authorization, complete G0 and MG0 remain unverified unless
proved separately; no work authorization or full-rule certification here.
"""
import hashlib
import json
import re
from pathlib import Path
from c07_positive_native_process import _original_attempt, _registered_artifacts, sha
from c07_positive200_evidence import R122_FROZEN_IDS

SCHEMA='gg-c07-r142-frozen37-mother-domain-probes-v1'
IDS=(
 '110_ERROR_REGISTRY','A','ADVERSARIAL_QA','APPEND_ONLY_AUDIT',
 'ARCHITECTURAL_QUALITY_FLOOR','ARCHITECTURE_1TO1',
 'ASSISTANT_BEHAVIOR_PROTOCOL','AUTONOMOUS_PRE_PASS_QUESTION','B',
 'BLOCK_ON_UNKNOWN','C','CG1','CG2','CG3','CG4',
 'CROSS_PIECE_COHERENCE','D','D-METODO','D-RISULTATO','D-TEMPO','D0',
 'DEFINITION_OF_DONE','DELIVERY_FIREWALL','DEPENDENCY_RECHECK',
 'DEVELOPER_RULES_CANONICAL','E','EXPORT_REIMPORT','F','FIVEM_TARGET',
 'FRESH_EYES','G0','G0-01','G0-02','G0-03','G0-04','G0-05','G0-06')
class EvidenceBlocked(ValueError):pass
def need(ok,why):
    if not ok:raise EvidenceBlocked(why)
def valid_hash(h):return type(h) is str and re.fullmatch('[a-f0-9]{64}',h) is not None
def nonempty(v):return type(v) is str and bool(v.strip())
def not_empty_sequence(v):return type(v) is list and bool(v) and all(nonempty(x) for x in v)
def rowcount(rows,event):return len([r for r in rows if r.get('event')==event])
def has_event(rows,event):return any(r.get('event')==event for r in rows)

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and inventory.get('schema')==
         'gg-effective-family-inventory-v1' and inventory.get('rule_count')==763,
         'R142_ORIGINAL_763_RULES_REQUIRED')
    need(set(IDS)<=set(R122_FROZEN_IDS) and len(IDS)==37 and
         len(set(IDS))==37 and callable(source_loader),
         'R142_EXACT_37_FROZEN_SOURCE_IDS')
    sourcehash=inventory.get('source_digests',{})
    need(type(sourcehash) is dict,'R142_CANONICAL_SOURCE_HASHES_MISSING')
    master=controller.master.read_bytes()
    need(sha(master)==work.get('master_sha256')==
         inventory['canonical_master_sha256'],
         'R142_CURRENT_LIBRARY_MASTER_BYTES_DRIFT')
    for rid in IDS:
        v=inventory['rules'].get(rid)
        need(type(v) is dict and nonempty(v.get('requirement')) and
             sha(v['requirement'].encode('utf-8'))==
                 v.get('requirement_sha256') and
             valid_hash(v.get('source_sha256')) and
             v.get('family') in inventory['families'] and
             rid in inventory['families'][v['family']] and
             v['source_sha256']==(
                 sha(master) if v.get('source')=='master' else
                 sourcehash.get(v.get('source'))),
             'R142_LITERAL_ORIGINAL_RULE_SOURCE_CHANGED:'+rid)
    rows,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'R142_AUDIT_STATE_OR_STEP_DRIFT')
    artifacts=_registered_artifacts(rows,state,step,source_loader,work)
    valid_artifacts={role:(path,digest,raw) for role,path,digest,raw in artifacts}
    def artifact(role):
        v=valid_artifacts.get(role)
        return (v is not None and type(v[2]) is bytes and
            len(v[2])>0 and sha(v[2])==v[1])
    current=[r for r in rows if r.get('step')==step and
             r.get('event')!='STEP_CLOSE']
    prior=[r for r in rows if r not in current]
    events=lambda key:[r for r in current if r.get('event')==key]
    began=events('STEP_OPEN')
    opened=events('SUPERVISOR_OPERATION_OPENED')
    prior_closed=[r for r in prior if
                  r.get('event') in ('STEP_CLOSE','SUPERVISOR_OPERATION_CLOSED')]
    original_question_rows=[r for r in current if
        r.get('event') in ('SUPERVISOR_QUESTION_BATCH','SUPERVISOR_C07_ANSWER_CHECK',
                           'SUPERVISOR_SUBCHECKS_ANSWERED')]
    process_checks=plan.get('operation',{})
    control=plan.get('pre_d_control',{})
    if type(control) is not dict:control={}
    sections=process_checks.get('sections')
    locks=process_checks.get('locks')
    dependencies=plan.get('dependency_files',{})
    old_version={x.get('evidence_operation',{}).get('sha256') for x in prior
                 if x.get('event')=='ARTIFACT_RECORDED'}
    exports=[x for x in artifacts if x[0]=='NATIVE_EXPORT']
    images=[x for x in artifacts if x[0].startswith('VISUAL_VIEW_')]
    visual_names={x[0] for x in images}
    old_artifacts=bool(old_version)
    filesource=lambda role:artifact(role)
    original_quality=[x for x in current if x.get('event')=='QUALITY_FINDING']
    qa_records=[x for x in current if x.get('event') in
        ('SUPERVISOR_NATIVE_QA','SUPERVISOR_CANONICAL_NATIVE_NEGATIVE_GATE')]
    changed_output=bool(exports and old_artifacts and
       any(x[2] not in old_version for x in exports))
    check_status=state.get('delivery_status')=='NOT_DELIVERABLE'
    QA_PAIRS=('VISUAL_VIEW_FRONT','VISUAL_VIEW_REAR',
              'VISUAL_VIEW_TOP','VISUAL_VIEW_UNDERSIDE')
    have_views=all(artifact(x) for x in QA_PAIRS)
    no_qa_claim=not any(r.get('result')=='PASS' and
       r.get('event') in ('ARTISTIC_APPROVED','OWNER_FINAL_ACCEPTED')
       for r in current)
    before_hash=bool(prior_closed and old_version)
    plan_goal=control.get('objective')
    required_rules=control.get('rule_ids')
    actual_evidence=any(x[0]=='NATIVE_EXPORT' and x[3] for x in artifacts)
    still_blocked=check_status and state.get('delivery_status')!='DELIVERABLE'
    pre_d=(nonempty(control.get('phase')) and
        control.get('phase') in ('G0','G1','A','B','C','D0'))
    # These are actual-measurable *subconditions*. None claims that a
    # subjective rule was satisfied solely because a file/event exists.
    checks={
      '110_ERROR_REGISTRY':{
        'original_regression_registry_source_sha_verified':True,
        'current_operation_negative_regression_findings_searched':
            all(x.get('step')==step for x in original_quality)},
      'A':{
        'enrolled_plan_bound_before_step_in_source_chain':
            bool(began) and bool(opened) and rows.index(began[0])<rows.index(opened[0]),
        'actual_master_source_bytes_reopened':sha(master)==work['master_sha256']},
      'ADVERSARIAL_QA':{
        'original_failure_search_events_examined':bool(qa_records),
        'four_opposing_view_bytes_original_and_current':have_views},
      'APPEND_ONLY_AUDIT':{
        'original_hash_chained_work_journal_verified':valid_hash(tail),
        'original_journal_tail_equals_saved_state':state.get('last_audit_hash')==tail},
      'ARCHITECTURAL_QUALITY_FLOOR':{
        'real_architectural_export_bytes_reopened':bool(exports),
        'critical_visual_views_collected_as_original_files':have_views},
      'ARCHITECTURE_1TO1':{
        'original_editable_geometry_file_reopened':filesource('SOURCE_EDITABLE'),
        'authentic_prefab_or_procedural_execution_absence_not_inferred':False},
      'ASSISTANT_BEHAVIOR_PROTOCOL':{
        'original_behavior_canonical_bytes_sha_bound':True,
        'current_attempt_failure_records_reopened':bool(original_quality)},
      'AUTONOMOUS_PRE_PASS_QUESTION':{
        'original_internal_qa_events_examined':bool(qa_records),
        'owner_not_substituted_for_internal_qa':no_qa_claim},
      'B':{
        'pre_D_dependency_hashes_authentically_enrolled':
            type(dependencies) is dict and bool(dependencies),
        'current_audit_conflicts_were_reviewed':bool(original_quality)},
      'BLOCK_ON_UNKNOWN':{
        'unresolved_current_step_process_defects_are_not_approved':still_blocked,
        'actual_controller_has_no_fake_owner_approval_event':no_qa_claim},
      'C':{
        'pre_D_criteria_file_list_declared':not_empty_sequence(control.get('criteria')),
        'pre_D_locked_elements_declared':not_empty_sequence(locks)},
      'CG1':{
        'specific_original_assertions_listed_before_D':
            not_empty_sequence(control.get('assertions')),
        'assumptions_not_called_confirmed':not_empty_sequence(control.get('assumptions'))},
      'CG2':{
        'adversarial_original_qa_events_examined':bool(qa_records),
        'actual_hidden_side_view_bytes_present':artifact('VISUAL_VIEW_UNDERSIDE')},
      'CG3':{
        'original_expected_reference_bytes_available':filesource('REFERENCE_IMAGE'),
        'actual_export_files_hashed_from_disk':bool(exports)},
      'CG4':{
        'unresolved_critical_findings_scanned':bool(original_quality),
        'current_delivery_is_restricted':check_status},
      'CROSS_PIECE_COHERENCE':{
        'original_previous_closed_piece_records_reopened':bool(prior_closed),
        'actual_output_bytes_distinct_from_prior':changed_output},
      'D':{
        'approved_current_operation_has_original_open_record':bool(opened),
        'actual_binary_export_present_not_only_report':actual_evidence},
      'D-METODO':{
        'pre_D_method_named_in_source_plan':nonempty(control.get('selected_method')),
        'real_output_file_readback_available':actual_evidence},
      'D-RISULTATO':{
        'original_criteria_recorded_prior_to_D':not_empty_sequence(control.get('criteria')),
        'current_registered_native_binary_outcome_exists':actual_evidence},
      'D-TEMPO':{
        'pre_D_time_budget_seconds_is_numeric':
            type(control.get('time_budget_seconds')) is int and
            control['time_budget_seconds']>0,
        'original_operation_records_have_real_time_fields':
            bool(began) and all(nonempty(x.get('timestamp_utc')) for x in began)},
      'D0':{
        'original_controller_D_permission_is_true':state.get('d_authorized') is True,
        'original_D_authorization_evidence_is_present':
            nonempty(state.get('d_authorization_evidence'))},
      'DEFINITION_OF_DONE':{
        'real_delivery_is_not_declared_complete_while_unknown':still_blocked,
        'quality_failure_history_reviewed':bool(original_quality)},
      'DELIVERY_FIREWALL':{
        'current_controller_keeps_delivery_closed':check_status,
        'four_original_qa_views_rechecked':have_views},
      'DEPENDENCY_RECHECK':{
        'exact_source_dependencies_pinned_to_work':
            bool(dependencies) and
            set(dependencies)==set(work.get('work_dependencies',{})),
        'current_master_before_after_bytes_equal_hash':sha(master)==work['master_sha256']},
      'DEVELOPER_RULES_CANONICAL':{
        'developer_source_sha_independently_bound_to_inventory':True,
        'native_rule_verdict_not_inferred_from_green_CI':not any(
            e.get('event')=='CI_GREEN_IMPLIES_OWNER_PASS' for e in current)},
      'E':{
        'current_original_quality_findings_scanned':bool(original_quality),
        'real_registered_native_export_reopened':actual_evidence},
      'EXPORT_REIMPORT':{
        'native_export_binary_hash_from_original_disk_reopened':bool(exports),
        'native_reimport_artifact_bytes_read':filesource('NATIVE_REIMPORT')},
      'F':{
        'native_original_QA_receipts_present':bool(qa_records),
        'unverified_output_not_authorized_for_delivery':check_status},
      'FIVEM_TARGET':{
        'real_destination_declared_in_source_plan':
            control.get('target_engine') in ('FiveM','GTA V/FiveM'),
        'native_runtime_receipt_found_not_self_reported':bool(events('FIVEM_RUNTIME_EVIDENCE'))},
      'FRESH_EYES':{
        'deliberate_original_fresh_eye_attempt_logged':bool(events('FRESH_EYES_REVIEW')),
        'reverse_angle_native_image_bytes_reopened':artifact('VISUAL_VIEW_REAR')},
      'G0':{
        'pre_D_piece_id_explicitly_declared':nonempty(control.get('piece_id')),
        'original_initial_source_and_deps_present':
            bool(dependencies) and filesource('SOURCE_EDITABLE')},
      'G0-01':{
        'original_question_attempt_records_examined':bool(original_question_rows),
        'original_complete_300_question_set_verification_not_inferred':False},
      'G0-02':{
        'original_piece_scope_sections_present':not_empty_sequence(sections),
        'original_workflow_tracking_state_current':bool(opened) and
            (state.get('active_step') or {}).get('step')==step},
      'G0-03':{
        'original_before_baseline_artifact_bytes_reopened':
            filesource('BASELINE_SNAPSHOT'),
        'original_export_vs_baseline_hashes_distinct':
            filesource('BASELINE_SNAPSHOT') and
            bool(exports) and
            valid_artifacts['BASELINE_SNAPSHOT'][1]!=exports[0][2]},
      'G0-04':{
        'original_piece_defect_ids_named_pre_D':
            not_empty_sequence(control.get('defect_ids')),
        'defect_to_piece_mapping_recorded':
            type(control.get('defect_to_piece')) is dict and
            bool(control['defect_to_piece'])},
      'G0-05':{
        'original_acceptance_oracle_declared_before_D':
            not_empty_sequence(control.get('criteria')),
        'original_expected_measurement_values_pinned':
            type(control.get('expected_measurements')) is dict and
            bool(control['expected_measurements'])},
      'G0-06':{
        'original_ordered_dependencies_defined_pre_D':
            type(control.get('predecessors')) is list and
            len(control['predecessors'])>0,
        'actual_dependency_sources_declared_in_work':bool(dependencies)},
    }
    need(set(checks)==set(IDS) and len(checks)==37 and
         len({k for group in checks.values() for k in group})==74 and
         all(type(group) is dict and len(group)==2 and
             all(type(v) is bool for v in group.values())
             for group in checks.values()),
         'R142_THIRTYSEVEN_RULE_SPECIFIC_EVIDENCE_PROBES_MISSING')
    result={}
    for rid in IDS:
        row=inventory['rules'][rid]
        observed=checks[rid]
        result[rid]={
          'rule_id':rid,
          'source_sha256':row['source_sha256'],
          'requirement_sha256':row['requirement_sha256'],
          'original_machine_predicates':observed,
          'actual_scope_observed':sorted(k for k,v in observed.items() if v),
          'missing_semantic_predicates':sorted(k for k,v in observed.items() if not v),
          'full_rule_semantics':'UNKNOWN',
          'individual_mg0':'UNKNOWN',
          'owner_approval':'UNKNOWN',
          'advancement_authorized':False}
    return {'schema':SCHEMA,'asset':asset,'step':step,
      'master_sha256':work['master_sha256'],
      'attempt_id':work['attempt_id'],
      'operation_sha256':work['operation_sha256'],
      'original_audit_sha256':audit_sha,'original_audit_tail':tail,
      'source_rules_examined':37,'named_domain_predicates':74,
      'machine_conditions_observed':sum(sum(v is True for v in group.values())
                                         for group in checks.values()),
      'full_rule_semantic_passes':0,'individual_mg0_passes':0,
      'advancement_authorized':False,'rules':result}
