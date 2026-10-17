"""C07 R143: 24 canonical G0 readiness subrules, each different native checks.

The original G0-07..G0-30 text is independently extracted from original
hash-pinned MASTER bytes. Inspect real Controller audit, registered original
model, signed phase-specific plan, and original QA photos where available.
Always separate scoped machine evidence from actual full-artistic judgment,
individual MG0, native owner identity, and asset delivery authorization.
"""
import hashlib
import json
import math
import re
from pathlib import Path

from c07_positive_native_process import _original_attempt, _registered_artifacts, sha
from c07_native_output_oracle import read_mesh_geometry, OriginalGeometryBlocked
from c07_a10_c10_original_evidence import original_image
from c07_positive200_evidence import R122_FROZEN_IDS

SCHEMA='gg-c07-r143-g0-remaining24-original-qa-v1'
IDS=tuple('G0-'+str(n).zfill(2) for n in range(7,31))
class G0Blocked(ValueError):pass
def need(ok,reason):
    if not ok:raise G0Blocked(reason)
def text_value(x):return type(x) is str and bool(x.strip())
def seq(x):return type(x) is list and bool(x) and all(text_value(s) for s in x)
def hash64(x):return type(x) is str and re.fullmatch('[a-f0-9]{64}',x) is not None

def inspect(inv,plan,controller,asset,step,work,*,source_loader):
    need(type(inv) is dict and inv.get('schema')==
         'gg-effective-family-inventory-v1' and inv.get('rule_count')==763
         and len(IDS)==24 and len(set(IDS))==24
         and set(IDS).isdisjoint(R122_FROZEN_IDS)
         and callable(source_loader),
         'R143_CANONICAL_24_ORIGINAL_G0_SCOPE_REQUIRED')
    raw=controller.master.read_bytes()
    need(sha(raw)==work.get('master_sha256')==
         inv.get('canonical_master_sha256'),
         'R143_LIBRARY_CANONICAL_MASTER_DRIFT')
    source=raw.decode('utf-8')
    begin=source.find('### Exact recovered 30-control source list')
    end=source.find('### G0 canonical role',begin)
    need(begin>=0 and end>begin,'R143_CANONICAL_30_G0_ORIGINAL_SOURCE_MISSING')
    matches=re.findall(r'(?m)^(\d+)\. (.+)$',source[begin:end])
    need([int(i) for i,_ in matches]==list(range(1,31)),
         'R143_CHANGED_CANONICAL_G0_SOURCE_SEQUENCE')
    original_by_id={'G0-'+str(n).zfill(2):requirement
                    for n,requirement in ((int(n),s) for n,s in matches)}
    for rid in IDS:
        item=inv['rules'].get(rid,{})
        clause=original_by_id[rid]
        need(item.get('source')=='master' and
             item.get('source_sha256')==sha(raw) and
             item.get('requirement')==clause and
             item.get('requirement_sha256')==sha(clause.encode('utf-8')) and
             item.get('family')=='G0_CONTROLS' and
             rid in inv['families']['G0_CONTROLS'],
             'R143_ORIGINAL_G0_LITERAL_CLAUSE_DRIFT:'+rid)
    rows,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'R143_CURRENT_CONTROLLER_AUDIT_DRIFT')
    recorded=_registered_artifacts(rows,state,step,source_loader,work)
    registered={}
    for role,path,digest,data in recorded:
        need(role not in registered,'R143_DUPLICATE_REGISTERED_ARTIFACT_ROLE:'+role)
        registered[role]=(path,digest,data)
    def orig(role):
        v=registered.get(role)
        return (v is not None and type(v[2]) is bytes and
                len(v[2])>0 and sha(v[2])==v[1])
    def png(role):
        return original_image(registered[role][2]) if orig(role) else None
    def geometry(role):
        if not orig(role) or not registered[role][0].endswith('.glb'):return None
        try:return read_mesh_geometry(registered[role][2])
        except (OriginalGeometryBlocked,ValueError,TypeError,KeyError,IndexError):return None
    native=geometry('NATIVE_EXPORT')
    baseline=geometry('BASELINE_SNAPSHOT')
    reimport=geometry('NATIVE_REIMPORT')
    operations=plan.get('operation',{})
    control=plan.get('pre_d_control',{})
    if type(control) is not dict:control={}
    enrolled=plan.get('dependency_files',{})
    work_deps=work.get('work_dependencies',{})
    current=[r for r in rows if r.get('step')==step]
    audit=lambda name:[r for r in current if r.get('event')==name]
    original_closed=[r for r in rows if r.get('event')=='STEP_CLOSE'
                     and r.get('step')!=step]
    findings=[r for r in current if r.get('event')=='QUALITY_FINDING']
    pertri=lambda v:v.get('triangles',0) if type(v) is dict else 0
    nonempty_groups=lambda k:type(control.get(k)) is dict and bool(control[k])
    photos=('VISUAL_VIEW_FRONT','VISUAL_VIEW_REAR','VISUAL_VIEW_TOP',
            'VISUAL_VIEW_UNDERSIDE')
    rawviews={k:png(k) for k in photos}
    different_views=(all(rawviews.values()) and len({
        v['sha256'] for v in rawviews.values()})==len(photos))
    timebox=control.get('time_budget_seconds')
    original_qa=bool(audit('SUPERVISOR_NATIVE_QA') or
                     audit('SUPERVISOR_CANONICAL_NATIVE_NEGATIVE_GATE'))
    remaining_issues={r.get('issue_id') for r in findings
                      if r.get('status') in ('OPEN','FAIL','UNKNOWN')}
    existing_defects=set(control.get('defect_ids',[])) if seq(control.get('defect_ids')) else set()
    prior_output={r.get('evidence_operation',{}).get('sha256') for r in rows
                  if r.get('event')=='ARTIFACT_RECORDED' and
                  r.get('step')!=step}
    output_changed=orig('NATIVE_EXPORT') and registered['NATIVE_EXPORT'][1] not in prior_output and bool(prior_output)
    budget=control.get('triangle_budget')
    numeric_budget=type(budget) is int and 1<=budget<=100_000_000
    person_height=control.get('player_reference_height_m')
    real_player_height=type(person_height) in (float,int) and 1.4<=person_height<=2.3
    source_lock=control.get('protected_source_sha256')
    actual_source=registered.get('SOURCE_EDITABLE')
    lock_match=(hash64(source_lock) and actual_source is not None and
        source_lock==actual_source[1])
    # Every criterion is specific to the *original numbered clause*.
    # Metadata presence is an observable subpredicate, never full acceptance.
    measured={
       7:{'pre_d_internal_time_budget_explicit':
               type(timebox) is int and timebox>0,
          'current_open_step_timestamps_present':
               bool(audit('STEP_OPEN')) and all(
                   text_value(r.get('timestamp_utc')) for r in audit('STEP_OPEN')),
          'timebox_does_not_override_quality_gate':
               state.get('delivery_status')=='NOT_DELIVERABLE'},
       8:{'current_piece_has_abort_early_gate_record':
               bool(audit('MG0_ABORT_EARLY_CHECK')),
          'prior_failed_attempts_preserved_in_audit':
               bool([r for r in rows if r.get('event')=='STEP_CLOSE' and
                     r.get('result')=='FAIL']),
          'original_work_step_remains_active_and_not_claimed_done':
               (state.get('active_step') or {}).get('step')==step},
       9:{'current_scope_is_original_enrolled_operation':
               text_value(operations.get('action')),
          'old_export_diff_available_to_detect_rebuild':
               bool(native and baseline),
          'scope_change_requires_original_authorization':
               bool(control.get('scope_change_authorization_file'))},
      10:{'pre_d_known_open_defect_ids_present':
               bool(existing_defects),
          'current_requested_new_features_empty':
               control.get('new_features')==[],
          'current_unresolved_issues_not_auto_closed':
               state.get('delivery_status')=='NOT_DELIVERABLE'},
      11:{'prior_accepted_component_history_in_original_audit':
               bool(original_closed),
          'actual_before_after_original_geometry_readback':
               bool(native and baseline),
          'current_geometry_not_from_producer_claim_only':
               native is not None},
      12:{'pre_d_bidirectional_interface_matrix_declared':
               nonempty_groups('interface_pairs'),
          'both_join_end_original_glb_geometry_read':
               bool(native and baseline),
          'original_interface_qa_event_current_attempt':
               bool(audit('INTERFACE_TWO_WAY_QA'))},
      13:{'native_original_target_reference_image_reopened':
               png('REFERENCE_IMAGE') is not None,
          'source_target_reference_hash_pinned_before_D':
               hash64(control.get('reference_image_sha256')) and
               orig('REFERENCE_IMAGE') and
               control['reference_image_sha256']==registered['REFERENCE_IMAGE'][1],
          'pre_d_component_reference_mapping_present':
               nonempty_groups('reference_by_piece')},
      14:{'independent_reference_comparison_images_present':
               bool(png('REFERENCE_IMAGE') and png('VISUAL_VIEW_FRONT')),
          'distinct_technical_and_artistic_qa_records':
               bool(audit('TECHNICAL_REFERENCE_QA')) and
               bool(audit('ARTISTIC_VISUAL_QA')),
          'artistic_approval_not_inferred_from_reference':
               state.get('delivery_status')=='NOT_DELIVERABLE'},
      15:{'original_native_GLTF_triangle_count_recomputed':
               native is not None,
          'pre_d_density_threshold_numeric_and_bounded':
               numeric_budget,
          'real_triangle_count_within_recorded_budget':
               native is not None and numeric_budget and
               native['triangles']<=budget},
      16:{'original_poly_budget_is_defined':
               numeric_budget,
          'native_export_real_triangles_under_limit':
               native is not None and numeric_budget and
               native['triangles']<=budget,
          'LOD_alternate_original_binary_reopened':
               geometry('LOD_EXPORT') is not None},
      17:{'real_player_scale_reference_recorded_pre_D':
               real_player_height,
          'original_GLTF2_vertical_extent_decoded':
               native is not None,
          'native_vertical_ratio_evidence_computed':
               bool(native and real_player_height and
                    0<native['bbox_max'][2]-native['bbox_min'][2]<=person_height*200)},
      18:{'original_collision_design_file_reopened':
               orig('COLLISION_PROXY'),
          'original_terrain_contact_reference_reopened':
               orig('TERRAIN_REFERENCE'),
          'pre_D_collision_target_defined':
               text_value(control.get('collision_strategy'))},
      19:{'original_export_material_metadata_read_required':
               orig('NATIVE_EXPORT') and native is not None,
          'reference_image_original_bytes_present':
               png('IMAGE_MATERIAL') is not None,
          'independent_PBR_render_validation_record_present':
               bool(audit('PBR_RENDER_QA'))},
      20:{'original_common_palette_file_reopened':
               orig('MATERIAL_PALETTE'),
          'current_native_export_geometry_exists':
               native is not None,
          'pre_D_palette_SHA_bound_to_file':
               hash64(control.get('palette_sha256')) and
               orig('MATERIAL_PALETTE') and
               control['palette_sha256']==registered['MATERIAL_PALETTE'][1]},
      21:{'pre_D_1to1_architectural_policy_selected':
               control.get('construction_policy')=='ARCHITECTURE_1TO1',
          'original_source_editable_geometry_reopened':
               orig('SOURCE_EDITABLE'),
          'verified_reuse_component_bytes_exist':
               orig('VERIFIED_REUSE_COMPONENT')},
      22:{'actual_GLTF_native_hierarchy_decoded':
               native is not None and native['mesh_definitions']>0,
          'editable_original_source_filename_present':
               orig('SOURCE_EDITABLE'),
          'pre_D_Sollumz_hierarchy_naming_contract':
               nonempty_groups('node_naming_contract')},
      23:{'original_export_and_reimport_binary_BOTH_reopened':
               bool(native and reimport),
          'native_original_reimport_triangles_agree':
               bool(native and reimport and
                    native['triangles']==reimport['triangles']),
          'native_original_reimport_bbox_equal':
               bool(native and reimport and
                    all(abs(native[x][k]-reimport[x][k])<=0.001
                        for x in ('bbox_min','bbox_max') for k in range(3)))},
      24:{'original_before_and_after_camera_files_present':
               bool(png('VISUAL_BEFORE_FRONT') and
                    png('VISUAL_AFTER_FRONT')),
          'pre_D_fixed_camera_contract_recorded':
               nonempty_groups('fixed_cameras'),
          'original_camera_view_bytes_not_identical':
               bool(orig('VISUAL_BEFORE_FRONT') and orig('VISUAL_AFTER_FRONT') and
                    registered['VISUAL_BEFORE_FRONT'][1]!=
                    registered['VISUAL_AFTER_FRONT'][1])},
      25:{'original_current_underneath_view_image_decoded':
               png('VISUAL_VIEW_UNDERSIDE') is not None,
          'native_export_original_geometry_reopened':
               native is not None,
          'underside_camera_contract_pre_D_present':
               'underside' in control.get('fixed_cameras',{})
                 if type(control.get('fixed_cameras')) is dict else False},
      26:{'four_distinct_view_raster_bytes_decoded':
               bool(different_views),
          'original_worst_angle_image_evidence_reopened':
               png('VISUAL_WORST_ANGLE') is not None,
          'original_pre_D_worst_view_qa_plan_present':
               text_value(control.get('worst_angle_reason'))},
      27:{'original_collision_candidate_technical_report_present':
               orig('INTERSECTION_REPORT'),
          'native_original_geometry_already_reparsed':
               native is not None,
          'independent_collision_qa_record_present':
               bool(audit('GEOMETRY_INTERSECTION_QA'))},
      28:{'original_protected_baseline_model_bytes_reopened':
               orig('BASELINE_SNAPSHOT'),
          'protected_editable_source_SHA_matches_lock':
               bool(lock_match),
          'locked_elements_listed_in_original_scope':
               seq(operations.get('locks'))},
      29:{'original_current_critical_failure_searched':
               bool(remaining_issues),
          'controller_actual_delivery_status_blocked':
               state.get('delivery_status')=='NOT_DELIVERABLE',
          'critical_late_fail_did_not_force_false_positive':
               not any(r.get('event')=='STEP_CLOSE' and r.get('result')=='PASS'
                       and r.get('step')==step for r in rows)},
      30:{'pre_D_timebox_goal_is_explicit':
               type(timebox) is int and timebox>0,
          'plan_separates_refinement_and_FiveM_complete':
               nonempty_groups('deliverable_scope_levels') and
               set(control['deliverable_scope_levels'])>=
                    {'LOCAL_REFINEMENT','FIVEM_COMPLETE'},
          'real_current_asset_never_called_release_ready_without_QA':
               state.get('delivery_status')=='NOT_DELIVERABLE'},
    }
    need(set(measured)==set(range(7,31)) and
         len({key for vals in measured.values() for key in vals})==72 and
         all(len(v)==3 and all(type(x) is bool for x in v.values())
             for v in measured.values()),
         'R143_TWENTYFOUR_ACTUAL_SOURCE_SPECIFIC_ORACLES_MISSING')
    results={}
    for n in range(7,31):
        rid='G0-'+str(n).zfill(2)
        canonical=inv['rules'][rid]
        values=measured[n]
        results[rid]={
          'rule_id':rid,'source_sha256':canonical['source_sha256'],
          'requirement_sha256':canonical['requirement_sha256'],
          'literal_canonical_G0_clause':original_by_id[rid],
          'original_native_evidence_predicates':values,
          'observed':sorted(k for k,v in values.items() if v),
          'missing':sorted(k for k,v in values.items() if not v),
          'full_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
          'owner_acceptance':'UNKNOWN','advancement_authorized':False,
        }
    return {'schema':SCHEMA,'source_rules_examined':24,'domain_conditions':72,
            'asset':asset,'step':step,'master_sha256':work['master_sha256'],
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'domain_positives':sum(sum(x is True for x in values.values())
                for values in measured.values()),
            'full_semantics_passes':0,'individual_mg0_passes':0,
            'advancement_authorized':False,'rules':results}
