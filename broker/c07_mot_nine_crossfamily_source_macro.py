"""C07 AAA-200 unresolved M/O/T macro: nine distinct original-source preflights.

The nine user literals are evaluated together against one immutable Controller
operation, while each rule independently cross-checks original GLB, PBR/RAGE
descriptor, PNG, LOD, performance evidence, ZIP, Blender SDNA or maintenance
guide. No trusted renderer, FiveM, owner signoff or MG0 is inferred from a
producer-labelled log. NEVER enroll this macro in FULL_LITERAL_REVIEWED.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p4_material_macro_full_review import inspect as inspect_material,original_drawable_shader_compatibility
from c07_p345_remaining_original_review import inspect as inspect_lod,triangle_counts,lod_surface_coherence
from c07_p8_delivery_macro_full_review import inspect as inspect_delivery,blender_blocks
from c07_p8_closure_semantics import inspect as inspect_closure
from c07_p4_texture_semantics import rgba,_embedded
from c07_p5_budget_semantics import _glb_parts
from c07_p8_delivery_semantics import _zip,safe_member
from c07_native_output_oracle import read_mesh_geometry
from c07_p345_forty_native_evidence import binary_json
from c07_p345_light_pixel_replay import triplet_light_response

M=(122,129,130)
O=(145,150)
T=(191,193,195,200)
IDS=tuple('AAA-200-'+family+'-%03d'%n
          for family,numbers in (('M',M),('O',O),('T',T))
          for n in numbers)
CRITERIA={
 122:('pre_d_original_pbr_lighting_contract_reopened',
      'native_material_attributes_and_three_actual_original_pixels_consistent',
      'independent_authentic_light_rig_and_renderer_provenance'),
 129:('original_rage_drawable_shader_source_and_glb_pinned',
      'native_shader_names_material_uv_maps_cross_replayed',
      'actual_supported_rage_shader_runtime_attested'),
 130:('three_distinct_original_lighting_rasters_and_glb_sha_bound',
      'actual_color_light_response_recomputed_against_source_policy',
      'independent_real_rendered_multilight_provenance'),
 145:('pre_d_original_native_lod_and_views_sha_pinned',
      'near_far_triangles_bbox_surface_and_raster_contract_recomputed',
      'independent_engine_lod_switch_no_popping_confirmed'),
 150:('original_asset_perf_budget_and_capture_sha_bound',
      'registered_frame_sample_p95_and_mesh_budget independently_recomputed'.replace(' ','_'),
      'real_fivem_scene_benchmark_trusted_provenance'),
 191:('original_source_native_manifest_archive_hashes_reopened',
      'all_required_original_zip_members_blender_structure_and_glb_parsed',
      'actual_usable_delivery_in_target_environment_attested'),
 193:('all_crc_safe_original_required_archive_members_reopened',
      'each original_blender_and_native_binary_structurally_parseable',
      'target_blender_and_fivem_files_independently_opened'),
 195:('original_editable_export_and_guide_sha_bound',
      'exact_original_package_install_paths_and_maintenance_documented',
      'guide_instructions_actually_validated_in_target_workflow'),
 200:('original_full_acceptance_contract_and_current_source_qa_present',
      'all_verified_subcriteria_have_source_and_no_known_open_critical',
      'independent_all_requirements_mg0_engine_and_owner_acceptance')
}
class NineMacroBlocked(ValueError):pass
def need(v,r):
    if not v:raise NineMacroBlocked(r)
def sha(b):return hashlib.sha256(b).hexdigest()
def numeric(x):return type(x) in (int,float) and math.isfinite(x)

def inspect(ctx,rid):
    need(rid in IDS and type(ctx) is dict and
         set(ctx)=={'inventory','plan','controller','asset',
                    'step','work','source_loader'},
         'C07_MOT_NINE_EXACT_SOURCE_CONTEXT_AND_LITERAL')
    inv,plan,controller,asset,step,work,loader=(
       ctx[k] for k in ('inventory','plan','controller','asset','step',
                        'work','source_loader'))
    family=rid.split('-')[2];n=int(rid[-3:])
    # Recompute the existing scoped canonical domain separately. It already
    # binds exact catalog text, all 763 source SHA values, current MASTER,
    # original open operation and the phase-specific rules.
    if family=='M':scoped=inspect_material(ctx,rid)
    elif family=='O':scoped=inspect_lod(ctx,rid)
    elif n in (191,193,195):scoped=inspect_delivery(ctx,rid)
    else:
        scoped=inspect_closure(inv,plan,controller,asset,step,work,
                               source_loader=loader)
    audit,tail,state,auditsha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(scoped.get('original_audit_sha256')==auditsha and
         scoped.get('original_audit_tail')==tail and
         state.get('last_audit_hash')==tail and
         sha(controller.master.read_bytes())==work['master_sha256'] and
         (state.get('active_step') or {}).get('step')==step,
         'C07_MOT_NINE_CURRENT_ORIGINAL_AUDIT_BINDING')
    pin_family=('p345_evidence_contract' if family in ('M','O')
                else 'p678_evidence_contract')
    pins=plan.get(pin_family,{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_MOT_NINE_PRE_D_PIN_REQUIRED')
    items={}
    for role,path,digest,raw in _registered_artifacts(
        audit,state,step,loader,work):
        need(role not in items,'C07_MOT_NINE_DUPLICATE_ROLE')
        items[role]=(path,digest,raw)
    def original(role,ext):
        a=items.get(role)
        return a[2] if (a and a[0].lower().endswith(ext)
            and a[1]==pins.get(role) and sha(a[2])==a[1]) else None
    export=original('NATIVE_EXPORT','.glb')
    doc,buffer=_glb_parts(export) if export else ({},b'')
    mesh=None
    if export:
        try:mesh=read_mesh_geometry(export)
        except (ValueError,IndexError,KeyError,OverflowError,TypeError):pass
    checks=[False,False,False]
    scope={}
    complete=False
    if family=='M':
        raw_contract=original('P4_MATERIAL_CONFORMANCE','.json')
        policy=binary_json(raw_contract) if raw_contract else {}
        valid=bool(export and raw_contract and mesh and doc.get('meshes'))
        if n==129:
            xml=original('P4_NATIVE_DRAWABLE_XML','.xml')
            complete=bool(valid and xml)
            parsed,compatible=(original_drawable_shader_compatibility(
                xml,doc,policy,_embedded(doc,buffer))
                if xml and export else (False,False))
            checks=[complete and parsed,bool(complete and compatible),False]
            scope={'actual_original_drawable_shader_parsed':parsed,
                   'real_native_uv_shader_binding_matches':compatible}
        else:
            views=[original(r,'.png') for r in (
                'P4_VIEW_NEUTRAL','P4_VIEW_DIRECT','P4_VIEW_SHADOW')]
            complete=bool(valid and all(views))
            decoded=[rgba(x) if x is not None else None for x in views]
            light=policy.get('light_response',{})
            direct=light.get('min_direct_neutral_delta')
            shadow=light.get('min_neutral_shadow_delta')
            bounded=bool(numeric(direct) and numeric(shadow) and
                1<=direct<=254 and 1<=shadow<=254)
            imgs=bool(complete and all(decoded) and
                len({x['pixel_sha256'] for x in decoded})==3 and
                len({(x['width'],x['height']) for x in decoded})==1)
            physical=bool(all(type(m) is dict and
                type(m.get('pbrMetallicRoughness')) is dict and
                all(numeric(m['pbrMetallicRoughness'].get(k)) and
                    0<=m['pbrMetallicRoughness'][k]<=1 for k in
                    ('roughnessFactor','metallicFactor'))
                for m in doc.get('materials',[])) and
                doc.get('materials'))
            response=bool(imgs and bounded and physical and
                decoded[1]['mean']-decoded[0]['mean']>=direct and
                decoded[0]['mean']-decoded[2]['mean']>=shadow and
                triplet_light_response(*views,
                    min_direct_delta=direct,min_shadow_delta=shadow))
            checks=[valid and bounded,bool(response),False]
            scope={'actual_pbr_source_valid':physical,
                   'original_multilight_raster_response':response}
    elif family=='O':
        budgetraw=original('P5_PERF_BUDGET','.json')
        budget=binary_json(budgetraw) if budgetraw else {}
        if n==145:
            lodraw=original('LOD_EXPORT','.glb')
            near=original('LOD_NEAR_VIEW','.png')
            far=original('LOD_FAR_VIEW','.png')
            complete=bool(export and lodraw and budgetraw and near and far)
            ratio=budget.get('lod_max_triangle_ratio')
            threshold=budget.get('lod_surface_deviation_m')
            allowed=bool(numeric(ratio) and 0<ratio<1 and
                         numeric(threshold) and 0<=threshold<=.5)
            measure=False
            if complete and mesh and allowed:
                try:
                    lm=read_mesh_geometry(lodraw)
                    x,y=rgba(near),rgba(far)
                    measure=bool(lm and x and y and
                       lm['triangles']>0 and
                       lm['triangles']/mesh['triangles']<=ratio and
                       lm['triangles']<mesh['triangles'] and
                       len(triangle_counts(export))>0 and
                       lod_surface_coherence(export,lodraw,threshold) and
                       x['width']==y['width'] and
                       x['height']==y['height'] and
                       x['pixel_sha256']!=y['pixel_sha256'])
                except (ValueError,KeyError,TypeError,IndexError):
                    pass
            checks=[complete and allowed,measure,False]
            scope={'independent_near_far_original_lod_geometry':measure}
        else:
            samples_raw=original('P5_RUNTIME_CAPTURE','.json')
            complete=bool(export and mesh and budgetraw and samples_raw)
            data=binary_json(samples_raw) if samples_raw else {}
            frames=data.get('frame_ms_samples')
            target=budget.get('target_frame_ms')
            valid=bool(complete and type(frames) is list and
                  10<=len(frames)<=10000 and
                  all(numeric(x) and 0<x<5000 for x in frames)
                  and numeric(target) and 0<target<=100)
            p95=(sorted(frames)[math.ceil(len(frames)*.95)-1]
                 if valid else None)
            checks=[valid,bool(valid and p95<=target and
                   mesh['triangles']>0),False]
            scope={'source_original_p95_frame_ms':p95,
                   'pre_d_target_frame_ms':target}
    else:
        source=original('SOURCE_EDITABLE','.blend')
        package=original('DELIVERY_PACKAGE','.zip')
        planraw=original('P8_DELIVERY_PLAN','.json')
        guide=original('P8_MAINTENANCE_GUIDE','.json')
        expected=binary_json(planraw) if planraw else {}
        guide_doc=binary_json(guide) if guide else {}
        members=_zip(package) if package else None
        source_name=expected.get('source_member')
        export_name=expected.get('export_member')
        required=expected.get('required_members')
        names=bool(type(required) is list and len(required)>=3
             and len(required)==len(set(required))
             and all(safe_member(x) for x in required)
             and safe_member(source_name) and safe_member(export_name)
             and {source_name,export_name,'DELIVERY_MANIFEST.json'}<=set(required))
        same=bool(source and export and planraw and members and names
             and set(members)>=set(required)
             and members.get(source_name)==source
             and members.get(export_name)==export)
        manifest=binary_json(members['DELIVERY_MANIFEST.json']) if same else {}
        identity=bool(same and manifest.get('asset')==asset and
             manifest.get('source_sha256')==sha(source) and
             manifest.get('export_sha256')==sha(export) and
             expected.get('source_sha256')==sha(source) and
             expected.get('export_sha256')==sha(export) and
             expected.get('version')==manifest.get('version'))
        structurally_valid=bool(identity and mesh and
             mesh['triangles']>0 and blender_blocks(source))
        if n==191:
            complete=bool(package and source and export and planraw)
            checks=[complete and identity,structurally_valid,False]
        elif n==193:
            complete=bool(package and source and export and planraw)
            checks=[complete and names and members is not None,
                    structurally_valid,False]
        elif n==195:
            complete=bool(source and export and planraw and guide)
            paths=guide_doc.get('install_paths')
            steps=guide_doc.get('maintenance_steps')
            instruction=bool(structurally_valid and
              type(guide_doc) is dict and set(guide_doc)=={
                'asset','source_sha256','export_sha256','install_paths',
                'maintenance_steps','status','owner_approved'}
              and guide_doc.get('asset')==asset
              and guide_doc.get('source_sha256')==sha(source)
              and guide_doc.get('export_sha256')==sha(export)
              and type(paths) is list and set(paths)=={source_name,export_name}
              and len(paths)==2 and
              type(steps) is list and len(steps)==3 and
              all(type(x) is str and 5<=len(x)<=300 for x in steps)
              and all(token in ' '.join(steps).casefold()
                      for token in ('source','version','revalidate'))
              and guide_doc.get('status')=='CANDIDATE'
              and guide_doc.get('owner_approved') is False)
            checks=[complete and identity,instruction,False]
        else:
            # T200 is the global gate. Source evidence alone can never
            # establish the complete contractual requirements, real FiveM
            # runtime, independent MG0 and owner's final acceptance.
            quality=original('P8_DELIVERY_QA','.json')
            complete=bool(source and export and planraw and quality)
            defects=[e for e in audit if
                e.get('event')=='QUALITY_FINDING'
                and e.get('step')==step
                and e.get('attempt_id')==work['attempt_id']
                and e.get('operation_sha256')==work['operation_sha256']
                and e.get('severity')=='CRITICAL'
                and e.get('status') in ('OPEN','FAIL','UNKNOWN')]
            checks=[complete and identity,
                    bool(identity and quality and not defects and
                         state.get('delivery_status')!='DELIVERABLE'),
                    False]
            scope={'current_operation_open_critical':len(defects)}
    need(len(checks)==3 and all(type(v) is bool for v in checks)
         and checks[-1] is False,'C07_MOT_NINE_NO_UNATTESTED_PASS')
    return {'rule_id':rid,'checks':dict(zip(CRITERIA[n],checks)),
        'evidence_complete':complete,
        'original_cross_source_observations':scope,
        'original_audit_sha256':auditsha,'original_audit_tail':tail,
        'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'full_rule_semantics':'UNKNOWN',
        'individual_mg0':'UNKNOWN',
        'real_blender_fivem_or_owner_provenance':'UNVERIFIED',
        'advancement_authorized':False}
