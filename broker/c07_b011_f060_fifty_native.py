"""C07 B-011..F-060: fifty canonical byte-bound native source observations.

This is machine-verifiable *scope*, not a full semantic/MG0/owner PASS.
A/C original-reference evidence reuses the existing independent R140 engine;
a new B/D/E/F consumer checks the real audited Controller operation,
authenticated original source files, hashes, render receipts and GLB geometry.
"""
import math
import re
from pathlib import Path
from c07_positive_native_process import _original_attempt,_registered_artifacts,sha
from c07_a10_c10_original_evidence import (
    inspect as inspect_existing_reference, _note, _pdf, original_image
)
from glb_machine_qa import audit_bytes,parse,GLBError,MAX_BYTES
from glb_winding_readback import scan_bytes as native_winding, WindingBlocked
from c07_bf50_canonical import CLAUSES,IDS,CATALOG_SHA
from c07_bf50_predicates import SPEC

SCHEMA="gg-c07-b011-f060-fifty-original-native-v1"
class BF50Blocked(ValueError):pass
def need(ok,reason):
    if not ok:raise BF50Blocked(reason)
def positive(v):return type(v) in (float,int) and math.isfinite(v) and v>0
def words(v):return type(v) is list and bool(v) and all(type(x) is str and bool(x.strip()) for x in v)
def string(v):return type(v) is str and bool(v.strip())
def original_sources(inv):
    need(type(inv) is dict and inv.get('schema')=='gg-effective-family-inventory-v1'
         and inv.get('rule_count')==763
         and inv.get('source_digests',{}).get('aaa_catalog')==CATALOG_SHA
         and len(CLAUSES)==len(IDS)==len(SPEC)==50
         and set(CLAUSES)==set(SPEC),
         'BF50_CANONICAL_INVENTORY_OR_RULE_SET_CHANGED')
    for n,(section,sentence,phase,kind) in CLAUSES.items():
        rid=IDS[n-11];row=inv.get('rules',{}).get(rid,{})
        need(row.get('family')=='AAA-200'
             and row.get('source_sha256')==CATALOG_SHA
             and row.get('catalog_number')==n
             and row.get('catalog_section')==section
             and row.get('catalog_phase')==phase
             and row.get('asset_type')==kind
             and row.get('requirement')==sentence
             and row.get('requirement_sha256')==sha(sentence.encode('utf-8')),
             'BF50_ORIGINAL_RULE_CHANGED:'+rid)

def observed_originals(records,artifacts,plan,work,step,asset,controller,source_loader):
    files={};allpaths=set()
    for role,path,digest,raw in artifacts:
        need(type(role) is str and type(path) is str and path not in allpaths and
             type(raw) is bytes and len(raw)>0 and sha(raw)==digest,
             'BF50_DUPLICATE_OR_UNVERIFIED_ORIGINAL_ARTIFACT')
        allpaths.add(path)
        files.setdefault(role,[]).append((path,digest,raw))
    def unique(role):
        v=files.get(role,[])
        return v[0] if len(v)==1 else None
    contract=plan.get('reference_evidence_contract')
    bound={}
    if type(contract) is dict and contract.get('schema')==(
            'gg-c07-original-pre-d-research-contract-v1') and
            type(contract.get('artifact_sha256')) is dict:
        bound={role:unique(role) for role in contract['artifact_sha256']
               if unique(role) is not None and
               unique(role)[1]==contract['artifact_sha256'][role]}
    def note(role):
        v=bound.get(role)
        return _note(v[2]) if v else {}
    def png(role):
        v=unique(role)
        return bool(v and original_image(v[2]))
    def doc(role):
        v=bound.get(role)
        return bool(v and _pdf(v[2]))
    goal=note('NOTE_OBJECTIVE')
    refs=note('NOTE_REFERENCE_INDEX')
    materials=note('NOTE_MATERIALS')
    qa=note('NOTE_QA')
    props=note('NOTE_PROPORTIONS')
    control=plan.get('pre_d_control',{})
    if type(control) is not dict:control={}
    op=plan.get('operation',{})
    if type(op) is not dict:op={}
    deps=plan.get('dependency_files',{})
    real_deps=(type(deps) is dict and bool(deps)
               and type(work.get('work_dependencies')) is dict
               and set(deps)==set(work['work_dependencies']))
    if real_deps:
        for key,path in deps.items():
            need(type(key) is str and re.fullmatch('[0-9a-f]{64}',key)
                 and type(path) is str and path and
                 not Path(path).is_absolute() and '\\' not in path
                 and '..' not in Path(path).parts and
                 (controller.root/path).resolve().is_relative_to(controller.root.resolve()),
                 'BF50_DEPENDENCY_FILE_PATH_ESCAPE')
            raw=source_loader(str(controller.root/path))
            if type(raw) is not bytes or sha(raw)!=work['work_dependencies'][key]:
                real_deps=False
                break
    glbs=[v for v in files.get('NATIVE_EXPORT',())
          if Path(v[0]).suffix.lower()=='.glb']
    need(len(glbs)<=1,'BF50_AMBIGUOUS_ORIGINAL_CURRENT_GLB')
    glb=None;model=None;machine=None;winding=None
    if glbs:
        glb=glbs[0][2]
        need(len(glb)<=MAX_BYTES,'BF50_GLB_TOO_LARGE')
        try:
            machine=audit_bytes(glb)
            model,_=parse(glb)
        except (GLBError,ValueError,TypeError,KeyError,IndexError,
                OverflowError) as exc:
            raise BF50Blocked('BF50_CORRUPT_REGISTERED_GLB:'+str(exc)) from exc
        need(machine['source_sha256']==glbs[0][1],
             'BF50_REGISTERED_GLB_SHA_MISMATCH')
    meshes=(model or {}).get('meshes',[])
    nodes=(model or {}).get('nodes',[])
    model_names=[str(v.get('name','')) for v in meshes+nodes if type(v) is dict]
    def name(pattern):return any(re.search(pattern,n,re.I) for n in model_names)
    controls=list(control.get('locks',[])) if type(control.get('locks')) is list else []
    if not controls and type(op.get('locks')) is list:controls=op['locks']
    original_current=[r for r in records if r.get('step')==step and
          r.get('attempt_id')==work.get('attempt_id') and
          r.get('operation_sha256')==work.get('operation_sha256')]
    def event(key):
        return any(r.get('event')==key for r in original_current)
    prior=[r for r in records if r.get('step')!=step and
           r.get('event')=='ARTIFACT_RECORDED' and
           r.get('result')=='PASS' and
           type(r.get('evidence_operation')) is dict and
           r['evidence_operation'].get('role')=='NATIVE_EXPORT']
    mats=[m for m in (model or {}).get('materials',[]) if type(m) is dict]
    material_factors={
        (tuple(m.get('pbrMetallicRoughness',{}).get('baseColorFactor',[1,1,1,1])),
         m.get('pbrMetallicRoughness',{}).get('metallicFactor',1),
         m.get('pbrMetallicRoughness',{}).get('roughnessFactor',1))
        for m in mats
    } if machine else set()
    baseline=unique('BASELINE_SNAPSHOT')
    export=unique('NATIVE_EXPORT')
    actual_sha_distinct=bool(baseline and export and baseline[1]!=export[1])
    F={
      'original_objective_note_verified':bool(goal),
      'goal_asset_matches_controller':bool(goal and goal.get('asset')==asset),
      'declared_piece_id':string(control.get('piece_id')),
      'planned_target_engine_is_explicit':string(control.get('target_engine')),
      'target_is_fivem':control.get('target_engine') in ('FiveM','GTA V/FiveM'),
      'pre_d_locked_engine':bool(string(control.get('target_engine')) and controls),
      'planned_unit_scale_declared':positive(control.get('unit_scale_m')),
      'original_coordinate_origin_declared':type(control.get('origin')) in (dict,list)
               and bool(control.get('origin')),
      'model_world_bounds_observed':bool(machine and machine['geometry_groups_with_bounds']>0),
      'original_dependency_files_declared':bool(deps),
      'existing_baseline_original_bytes':bool(baseline),
      'prior_real_asset_outputs_in_audit':bool(prior),
      'locked_elements_declared':words(controls),
      'original_baseline_original_bytes':bool(baseline),
      'protected_source_identity_pinned':bool(baseline and words(controls)),
      'original_dependency_hashes_enrolled':bool(deps and real_deps),
      'real_dependencies_sha_readback':real_deps,
      'original_output_and_terrain_discriminated':bool(
           real_deps and name(r'ground|terrain') and
           name(r'building|wall|roof')),
      'original_deliverable_list':words(goal.get('deliverables')),
      'native_model_export_original_bytes':bool(export),
      'delivery_target_role_explicit':bool(unique('DELIVERY_PACKAGE')),
      'original_failure_modes_listed':words(qa.get('failure_classes')),
      'pre_d_assumptions_declared':words(control.get('assumptions')),
      'current_audit_quality_findings_scanned':bool(event('QUALITY_FINDING')),
      'time_budget_predeclared':positive(control.get('time_budget_seconds')),
      'opened_step_has_original_time':bool(event('SUPERVISOR_OPERATION_OPENED')) and
          any(string(x.get('timestamp_utc')) for x in original_current if
              x.get('event')=='SUPERVISOR_OPERATION_OPENED'),
      'real_export_byte_evidence_present':bool(export),
      'original_acceptance_criteria_declared':words(control.get('criteria')),
      'expected_numeric_measurements_present':bool(
          type(control.get('expected_measurements')) is dict and
          control['expected_measurements'] and
          all(positive(v) for v in control['expected_measurements'].values())),
      'original_qa_note_present':bool(qa),
      'original_canonical_visual_style_note':bool(note('NOTE_HISTORY')),
      'original_material_palette_declared':words(materials.get('palette')),
      'original_reference_image_bytes':bool(bound.get('PHOTO_FRONT')),
      'several_original_scene_meshes':len(meshes)>=2,
      'registered_reference_images_distinct':bool(
          len({v[1] for k in ('PHOTO_FRONT','PHOTO_SIDE','PHOTO_REAR')
               for v in files.get(k,())})>=2),
      'shared_style_materials_observed':len(mats)>0,
      'original_palette_nonempty':words(materials.get('palette')),
      'material_factors_computed_from_glb':bool(machine and mats),
      'material_count_observed':bool(machine and len(mats)>0),
      'scene_world_bounds_measured':bool(machine and machine['geometry_groups_with_bounds']>0),
      'visible_mesh_instances_counted':bool(machine and machine['scene_mesh_nodes']>0),
      'original_front_view_png_valid':png('VISUAL_VIEW_FRONT'),
      'original_top_view_png_valid':png('VISUAL_VIEW_TOP'),
      'original_rear_view_png_valid':png('VISUAL_VIEW_REAR'),
      'scene_mesh_geometry_original':bool(machine and machine['triangles_examined']>0),
      'winding_scan_completed':winding is not None,
      'original_point_of_interest_declared':words(control.get('focal_points')),
      'player_camera_qa_original':bool(event('PLAYER_CAMERA_QA')),
      'original_mesh_name_repetitions_measured':len(model_names)>0,
      'real_mesh_instances_observed':bool(machine and machine['scene_mesh_nodes']>1),
      'numeric_material_variation_computed':len(material_factors)>1,
      'player_view_png_valid':png('VISUAL_VIEW_PLAYER'),
      'model_mesh_count_original':bool(machine and machine['mesh_primitives']>0),
      'original_site_dimensions_declared':bool(
          type(control.get('site_dimensions_m')) is dict and
          len(control['site_dimensions_m'])>=2 and
          all(positive(v) for v in control['site_dimensions_m'].values())),
      'verified_reference_plan_bytes':doc('DOC_PLAN'),
      'scene_transform_matrix_validated':bool(machine and
          machine['checks']['static_world_transform']=='VERIFIED'),
      'original_orientation_declared':string(control.get('orientation')),
      'multiple_architecture_meshes_present':sum(
          bool(re.search('building|wall|roof|column|facade',n,re.I))
          for n in model_names)>=2,
      'walkway_meshes_observed':name('path|walkway|sentiero'),
      'primary_route_plan_declared':words(control.get('primary_routes')),
      'secondary_route_plan_declared':words(control.get('secondary_routes')),
      'accessibility_zones_plan_declared':words(control.get('accessible_zones')),
      'collision_geometry_hint_present':name('collision|bound|colmesh'),
      'original_player_view_png':png('VISUAL_VIEW_PLAYER'),
      'entry_exit_meshes_observed':name('entry|entrance|exit|door|gate|ingresso'),
      'planned_footprints_declared':bool(
           type(control.get('planned_footprints')) is dict and
           control['planned_footprints']),
      'terrain_meshes_present':name('terrain|ground|landscape'),
      'building_meshes_present':name('building|wall|roof|facade'),
      'glb_overlap_candidate_count_observed':bool(machine and
           type(machine['aabb_overlap_candidates_count']) is int),
      'blockout_meshes_named':name('blockout|block_out|prototype'),
      'original_editable_model_present':bool(unique('SOURCE_EDITABLE')),
      'original_glb_geometry_present':bool(machine and machine['triangles_examined']>0),
      'original_glb_bounds_computed':bool(machine and machine['geometry_groups_with_bounds']>0),
      'reference_dimensions_original':bool(note('NOTE_PROPORTIONS')),
      'original_blockout_qa_original':bool(event('SUPERVISOR_NATIVE_QA')),
      'original_quality_findings_scanned':bool(event('QUALITY_FINDING')),
      'new_native_output_differs_from_baseline':actual_sha_distinct,
      'blockout_acceptance_declared':words(control.get('criteria')),
      'phase_is_before_detail':work.get('phase') in ('P0','P1'),
      'real_strict_crossing_scan_completed':bool(
          machine and machine.get('triangle_surface_crossing_evidence',{})
          .get('all_requested_pairs_fully_scanned') is True),
    }
    # No word/name/file-only inference can establish design or owner acceptance.
    return F,machine

def inspect(inv,plan,controller,asset,step,work,*,source_loader):
    need(callable(source_loader),'BF50_ORIGINAL_SOURCE_LOADER_REQUIRED')
    original_sources(inv)
    records,tail,state,audit_sha=_original_attempt(inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==inv['canonical_master_sha256']
         ==work['master_sha256']
         and state.get('last_audit_hash')==tail
         and (state.get('active_step') or {}).get('step')==step,
         'BF50_ORIGINAL_MASTER_OR_AUDIT_STATE_DRIFT')
    artifacts=_registered_artifacts(records,state,step,source_loader,work)
    F,technical=observed_originals(records,artifacts,plan,work,step,asset,
                                   controller,source_loader)
    # C21-C30: genuinely independently validated original reference documents.
    existing=inspect_existing_reference(
        inv,plan,controller,asset,step,work,source_loader=source_loader)
    need(existing['source_rules_examined']==20 and
         existing['full_rule_passes']==0 and existing['individual_mg0_passes']==0
         and existing['advancement_authorized'] is False,
         'BF50_R140_REUSED_REFERENCE_EVIDENCE_NOT_TRUSTED')
    for n in range(21,31):
        rid=IDS[n-11]
        original=existing['rules'][rid]['native_original_file_criteria']
        need(len(original)==3,'BF50_C_RESEARCH_PROOF_INCOMPLETE:'+rid)
        for new,yes in zip(SPEC[n][:3],original.values()):
            need(new not in F,'BF50_DUPLICATE_C_RESEARCH_FEATURE')
            F[new]=yes
    known_false={scope[-1] for scope in SPEC.values()}
    missing={x for scope in SPEC.values() for x in scope if x not in F}
    need(missing==known_false and all(x not in F for x in known_false),
         'BF50_UNEXPECTED_UNIMPLEMENTED_SOURCE_SCOPE:'+repr(sorted(missing^known_false)))
    F.update({x:False for x in known_false})
    need(all(type(v) is bool for v in F.values()),'BF50_BOOLEAN_PROOF_SCHEMA')
    results={};checks=0;observed=0
    for n,(section,text,phase,kind) in CLAUSES.items():
        rid=IDS[n-11]
        scope=SPEC[n]
        need(len(scope)==4 and len(set(scope))==4
             and all(k in F for k in scope),
             'BF50_EXACT_FOUR_PER_RULE_PROOFS_REQUIRED:'+rid)
        obs={k:F[k] for k in scope}
        checks+=len(obs);observed+=sum(obs.values())
        phase_due=(work.get('phase') in ('P0','P1','P2','P3','P4','P5','P6','P7','P8')
                   if phase=='P0' else
                   work.get('phase') in ('P1','P2','P3','P4','P5','P6','P7','P8'))
        results[rid]={
            'rule_id':rid,'requirement_sha256':inv['rules'][rid]['requirement_sha256'],
            'source_sha256':CATALOG_SHA,'canonical_requirement':text,
            'applicability':'DUE' if phase_due else 'FUTURE_PHASE',
            'original_native_predicates':obs,
            'observed':sorted(k for k,v in obs.items() if v),
            'missing':sorted(k for k,v in obs.items() if not v),
            'full_rule_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
            'owner_approval':'UNKNOWN','advancement_authorized':False,
        }
    need(checks==200 and len(results)==50,'BF50_FIFTY_ORIGINAL_SCOPES_MISSING')
    return {'schema':SCHEMA,'asset':asset,'step':step,'original_audit_sha256':audit_sha,
            'original_audit_tail':tail,'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'native_glb_sha256':technical['source_sha256'] if technical else None,
            'source_rules_examined':50,'native_conditions_evaluated':checks,
            'native_conditions_observed':observed,
            'full_rule_passes':0,'individual_mg0_passes':0,
            'advancement_authorized':False,'rules':results}
