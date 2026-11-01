"""C07 P8 three-rule final visual and environment source QA macro.

Source-specific coverage of S184 normal/surface artifacts, S185 PBR materials,
and S186 original environment coherence. Real source GLBs, embedded PNGs,
the separately registered multi-view images and operation-scoped audit are
independently reopened, never replaced with producer summary flags.
Source FULL reviewer != artistic approval, Blender run, MG0 or FiveM PASS.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p8_final_qa_semantics import inspect as qa_inspect
from c07_camera_views_full_review import inspect as camera_inspect,P8 as SIX
from c07_p345_forty_native_evidence import binary_json
from c07_p3_geometry_semantics import geometry,_read_accessor
from c07_p4_texture_semantics import rgba,_embedded
from c07_p5_budget_semantics import _glb_parts
from c07_native_output_oracle import read_mesh_geometry
from c07_p345_five_macro_full_review import all_embedded_textures_really_used

RULES=frozenset(('AAA-200-S-184','AAA-200-S-185','AAA-200-S-186'))
CRITERIA={
'AAA-200-S-184':(
 'pre_d_original_normals_defect_policy_and_six_view_audit_sha_pinned',
 'original_face_winding_unit_normals_and_non_degenerate_surfaces_recomputed',
 'original_six_distinct_capture_pixels_and_zero_surface_qa_artifacts_replayed'),
'AAA-200-S-185':(
 'pre_d_original_export_material_reference_and_texture_policy_sha_pinned',
 'all_actual_original_uv_primitives_bind_decodable_embedded_pbr_textures',
 'original_material_qa_image_color_and_physical_factors_match_reference_limits'),
'AAA-200-S-186':(
 'pre_d_original_context_scene_reference_and_anchor_policy_sha_pinned',
 'original_asset_and_environment_geometry_spatially_compatible_with_anchor',
 'original_area_context_capture_and_environment_palette_meet_site_reference_limits'),
}
class FinalThreeBlocked(ValueError):pass
def need(value,reason):
    if not value:raise FinalThreeBlocked(reason)
def sha(data):return hashlib.sha256(data).hexdigest()
def numeric(value):return type(value) in (int,float) and math.isfinite(value)
def xyz(values):return type(values) is list and len(values)==3 and all(numeric(x) for x in values)
def distance(a,b):return math.dist(a,b)

def original_scope(ctx):
    inv,plan,ctl,asset,step,work,loader=(
      ctx[k] for k in ('inventory','plan','controller','asset',
                       'step','work','source_loader'))
    qa=qa_inspect(inv,plan,ctl,asset,step,work,source_loader=loader)
    camera=camera_inspect(ctx,SIX)
    audit,tail,state,auditsha=_original_attempt(inv,plan,ctl,asset,step,work)
    need(qa['original_audit_sha256']==auditsha
         and camera['original_audit_sha256']==auditsha
         and state.get('last_audit_hash')==tail
         and sha(ctl.master.read_bytes())==work['master_sha256']
         and (state.get('active_step') or {}).get('step')==step,
         'C07_P8_FINAL_THREE_EXACT_AUDIT_REQUIRED')
    pins=plan.get('p678_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_P8_FINAL_THREE_PRE_D_PINS')
    found={}
    for role,path,digest,raw in _registered_artifacts(
      audit,state,step,loader,work):
        need(role not in found,'C07_P8_FINAL_THREE_DUPLICATE_SOURCE')
        found[role]=(path,digest,raw)
    def original(role,extension):
        x=found.get(role)
        return (x[2] if x and x[0].lower().endswith(extension)
                and pins.get(role)==x[1] and sha(x[2])==x[1] else None)
    return qa,camera,original,auditsha,tail

def inspect(ctx,rule_id):
    need(type(ctx) is dict and set(ctx)=={
      'inventory','plan','controller','asset','step','work','source_loader'}
      and rule_id in RULES,'C07_P8_FINAL_THREE_EXACT_CONTEXT')
    qa,camera,src,auditsha,tail=original_scope(ctx)
    native=src('NATIVE_EXPORT','.glb')
    policyraw=src('P8_FINAL_SURFACE_POLICY','.json')
    policy=binary_json(policyraw) if policyraw else {}
    checks={name:False for name in CRITERIA[rule_id]}
    view_ok=bool(camera['evidence_complete'] and
                 all(camera['checks'].values()))
    native_ok=bool(native)
    complete=False
    observations={}
    if rule_id.endswith('184'):
        report=src('P8_NORMALS_REPORT','.json')
        defect=src('P8_SURFACE_DEFECT_MATRIX','.json')
        normal_report=binary_json(report) if report else {}
        defect_report=binary_json(defect) if defect else {}
        roles={'FRONT','REAR','LEFT','RIGHT','TOP','UNDERSIDE'}
        clean=bool(policy.get('schema')=='gg-c07-p8-three-final-source-v1'
           and policy.get('max_surface_defects')==0
           and normal_report.get('native_sha256')==(sha(native) if native else None)
           and defect_report.get('native_sha256')==(sha(native) if native else None)
           and type(defect_report.get('per_view_surface_defects')) is dict
           and set(defect_report['per_view_surface_defects'])==roles
           and all(type(x) is int and x==0 for x in
                    defect_report['per_view_surface_defects'].values()))
        complete=bool(native and policyraw and report and defect)
        checks[CRITERIA[rule_id][0]]=bool(complete and clean and view_ok)
        faces=False
        if native:
            metrics=geometry(native)
            doc,blob=_glb_parts(native)
            primitives=[p for mesh in doc['meshes']
                        for p in mesh['primitives']]
            correct=all(m['declared_vertex_normals']
                and m['degenerate_triangles']==0
                and m['duplicate_geometric_faces']==0
                and m['opposed_face_normals']==0
                for m in metrics)
            unit=True
            for primitive in primitives:
                idx=primitive.get('attributes',{}).get('NORMAL')
                if type(idx) is not int:unit=False;break
                normals=_read_accessor(doc,blob,idx)
                if not normals or any(len(v)!=3 or
                    not all(numeric(k) for k in v) or
                    not 0.99<=math.sqrt(sum(k*k for k in v))<=1.01
                    for v in normals):
                    unit=False;break
            faces=bool(correct and unit)
        checks[CRITERIA[rule_id][1]]=faces
        checks[CRITERIA[rule_id][2]]=bool(faces and clean and view_ok)
        observations={'native_surface_geometry_clean':faces,
                      'original_view_defect_matrix_clean':clean}
    elif rule_id.endswith('185'):
        reference=src('P8_MATERIAL_REFERENCE','.png')
        render=src('P8_MATERIAL_RENDER','.png')
        complete=bool(native and policyraw and reference and render)
        contract=bool(policy.get('schema')=='gg-c07-p8-three-final-source-v1'
            and numeric(policy.get('max_material_reference_mean_delta'))
            and 0<=policy['max_material_reference_mean_delta']<=64
            and numeric(policy.get('min_material_variance'))
            and 0<policy['min_material_variance']<=65025)
        checks[CRITERIA[rule_id][0]]=bool(complete and contract)
        physical=False;measured=False
        if native:
            doc,blob=_glb_parts(native)
            images=_embedded(doc,blob)
            materials=doc.get('materials',[])
            physical=bool(images and all_embedded_textures_really_used(doc)
                and materials and all(
                    type(mat.get('pbrMetallicRoughness')) is dict and
                    numeric(mat['pbrMetallicRoughness'].get('roughnessFactor'))
                    and 0<=mat['pbrMetallicRoughness']['roughnessFactor']<=1
                    and numeric(mat['pbrMetallicRoughness'].get('metallicFactor'))
                    and 0<=mat['pbrMetallicRoughness']['metallicFactor']<=1
                    for mat in materials))
        if complete and contract and physical:
            ref=rgba(reference);shown=rgba(render)
            measured=bool(ref and shown and ref['width']==shown['width']
                and ref['height']==shown['height']
                and ref['pixel_sha256']!=shown['pixel_sha256']
                and abs(ref['mean']-shown['mean'])<=
                    policy['max_material_reference_mean_delta']
                and shown['variance']>=policy['min_material_variance']
                and ref['variance']>=policy['min_material_variance'])
        checks[CRITERIA[rule_id][1]]=physical
        checks[CRITERIA[rule_id][2]]=measured
        observations={'all_original_uv_pbr_images_active':physical,
                      'source_material_reference_pixels_compatible':measured}
    else:
        environment=src('P8_ENVIRONMENT_REFERENCE','.glb')
        context=src('P8_AREA_CONTEXT','.png')
        original_view=src('VISUAL_VIEW_FRONT','.png')
        complete=bool(native and policyraw and environment
            and context and original_view)
        anchor=policy.get('asset_anchor_xyz')
        site=policy.get('environment_anchor_xyz')
        radius=policy.get('max_anchor_distance_m')
        scale=policy.get('max_asset_to_environment_span_ratio')
        contract=bool(policy.get('schema')=='gg-c07-p8-three-final-source-v1'
            and xyz(anchor) and xyz(site)
            and numeric(radius) and 0<radius<=30
            and numeric(scale) and 0<scale<=1)
        checks[CRITERIA[rule_id][0]]=bool(complete and contract and view_ok)
        spatial=False;visual=False
        if complete and contract:
            actual=read_mesh_geometry(native)
            env=read_mesh_geometry(environment)
            amin,amax=actual['bbox_min'],actual['bbox_max']
            emin,emax=env['bbox_min'],env['bbox_max']
            center=[(amin[i]+amax[i])*.5 for i in range(3)]
            ec=[(emin[i]+emax[i])*.5 for i in range(3)]
            assetspan=math.dist(amin,amax)
            envspan=math.dist(emin,emax)
            spatial=bool(envspan>0 and assetspan>0 and
                assetspan/envspan<=scale and
                distance(center,anchor)<=radius and
                distance(ec,site)<=radius and
                all(emin[k]<=amin[k]<=amax[k]<=emax[k] for k in range(3)))
            scene=rgba(context);front=rgba(original_view)
            visual=bool(spatial and scene and front
                and scene['width']==front['width']
                and scene['height']==front['height']
                and scene['pixel_sha256']!=front['pixel_sha256']
                and scene['variance']>0 and front['variance']>0)
        checks[CRITERIA[rule_id][1]]=spatial
        checks[CRITERIA[rule_id][2]]=visual
        observations={'original_asset_within_source_site_geometry':spatial,
                      'original_raster_scene_and_view_decoded':visual}
    return {'rule_id':rule_id,'checks':checks,'evidence_complete':complete,
        'original_evidence':observations,
        'original_audit_sha256':auditsha,'original_audit_tail':tail,
        'attempt_id':ctx['work']['attempt_id'],
        'operation_sha256':ctx['work']['operation_sha256'],
        'render_provenance':'UNVERIFIED',
        'owner_acceptance':'UNVERIFIED','fivem_runtime':'UNVERIFIED',
        'advancement_authorized':False}
