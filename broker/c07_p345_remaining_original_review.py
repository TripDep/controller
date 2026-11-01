"""C07 P3/P4/P5: thirteen remaining literal-specific original-byte reviews.

This module deliberately returns source-scoped predicates, NOT FULL semantics:
an atlas decision, baking necessity, approved visual equivalence, renderer light
rig, occlusion intent, LOD transition, aesthetic reuse and FiveM profiling
cannot be inferred from a producer's policy or a registered PNG/JSON alone.
Each candidate is tied to the current Controller operation, canonical literal,
SHA-pinned pre-D sources and independently decoded native bytes.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p345_forty_native_evidence import inspect as inspect_p345, binary_json
from c07_p5_budget_semantics import _glb_parts
from c07_p5_optimization_semantics import _mesh, _references
from c07_p5_full_review import material_bindings
from c07_p4_texture_semantics import rgba, _embedded

NUMBERS=(118,119,120,133,134,135,136,139,140,143,145,147,150)
RULES=frozenset('AAA-200-'+('L' if n<=120 else 'N' if n<=140 else 'O')+
                '-%03d'%n for n in NUMBERS)
CRITERIA={
118:('pre_d_original_atlas_and_baseline_contract_sha_bound',
     'actual_native_and_baseline_material_texture_bindings_recomputed',
     'measured_original_atlas_binding_reduction_and_texture_quality_retained'),
119:('pre_d_original_bake_necessity_and_source_normal_map_sha_bound',
     'actual_exported_normal_texture_and_baked_png_pixels_redecoded',
     'actual_baked_map_channels_and_exported_normal_image_match'),
120:('pre_d_original_approved_mesh_and_current_export_sha_bound',
     'actual_approved_and_current_native_triangle_geometry_compared',
     'trusted_original_visual_approval_and_renderer_equivalence_confirmed'),
133:('pre_d_original_lighting_defect_policy_and_capture_sha_bound',
     'actual_original_native_triangles_and_defect_report_recomputed',
     'trusted_lighting_renderer_and_geometry_defect_provenance_confirmed'),
134:('pre_d_original_direct_light_policy_and_view_sha_bound',
     'actual_direct_light_pixels_and_original_pbr_materials_recomputed',
     'trusted_direct_light_renderer_and_physical_material_response_confirmed'),
135:('pre_d_original_shadow_policy_and_view_sha_bound',
     'actual_shadow_and_neutral_pixels_and_materials_recomputed',
     'trusted_shadow_renderer_and_physical_material_response_confirmed'),
136:('pre_d_original_reflective_material_policy_and_view_sha_bound',
     'actual_original_metal_glass_pbr_and_reflection_pixels_recomputed',
     'trusted_reflection_renderer_and_real_material_behavior_confirmed'),
139:('pre_d_original_underside_qa_scope_and_view_sha_bound',
     'actual_underside_pixels_and_unresolved_qa_findings_recomputed',
     'trusted_renderer_provenance_and_complete_defect_coverage_confirmed'),
140:('pre_d_original_separate_presentation_and_technical_qa_sha_bound',
     'actual_distinct_original_visual_capture_and_machine_report_recomputed',
     'trusted_independent_artistic_vs_technical_review_confirmed'),
143:('pre_d_original_hidden_face_policy_and_baseline_sha_bound',
     'actual_before_after_native_triangle_counts_and_bounds_recomputed',
     'original_hidden_face_intent_and_nonessential_geometry_proven'),
145:('pre_d_original_lod_transition_policy_and_views_sha_bound',
     'actual_original_near_far_lod_geometry_and_pixels_recomputed',
     'trusted_renderer_continuity_and_no_visible_lod_popping_confirmed'),
147:('pre_d_original_texture_reuse_and_quality_policy_sha_bound',
     'actual_shared_original_glb_image_bindings_and_pixels_recomputed',
     'independent_scene_quality_not_degraded_by_reuse_confirmed'),
150:('pre_d_original_platform_scene_benchmark_contract_sha_bound',
     'actual_registered_frame_samples_and_source_scene_bytes_recomputed',
     'trusted_real_fivem_runtime_capture_provenance_confirmed'),
}

class OriginalP345RemainingBlocked(ValueError):pass
def need(ok,reason):
    if not ok:raise OriginalP345RemainingBlocked(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def numeric(v):return type(v) in (int,float) and math.isfinite(v)
def positive(v):return numeric(v) and v>0
def rgb_different(a,b):
    return bool(a and b and a['pixel_sha256']!=b['pixel_sha256'] and
                a['width']==b['width'] and a['height']==b['height'])
def boxes_close(a,b,tol):
    return bool(a and b and numeric(tol) and 0<=tol<=10 and all(
        abs(a['bounds'][k][j]-b['bounds'][k][j])<=tol
        for k in range(2) for j in range(3)))
def bindings(raw):
    if raw is None:return None
    try:return material_bindings(raw)
    except (ValueError,KeyError,TypeError,IndexError):return None

def inspect(source_context,rule_id):
    need(type(source_context) is dict and
         set(source_context)=={'inventory','plan','controller','asset',
                               'step','work','source_loader'} and
         rule_id in RULES,'C07_P345_REMAINING_EXACT_CONTEXT')
    inv,plan,controller,asset,step,work,loader=(
        source_context[k] for k in ('inventory','plan','controller',
                                    'asset','step','work','source_loader'))
    need(plan.get('phase') in ('P5','P6','P7','P8','VERIFY','G2','G3','G4','DELIVERY'),
         'C07_P345_REMAINING_PHASE')
    # The original forty-rule reader enforces every canonical literal,
    # catalog digest, phase, current master and active operation.
    report=inspect_p345(inv,plan,controller,asset,step,work,source_loader=loader)
    rows,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256']
         and state.get('last_audit_hash')==tail
         and (state.get('active_step') or {}).get('step')==step
         and report['original_audit_sha256']==audit_sha
         and report['original_audit_tail']==tail,
         'C07_P345_REMAINING_CURRENT_AUDIT_DRIFT')
    pins=plan.get('p345_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_P345_REMAINING_PRE_D_PINS')
    records={}
    for role,path,digest,raw in _registered_artifacts(
            rows,state,step,loader,work):
        need(role not in records,'C07_P345_REMAINING_DUPLICATE_ROLE')
        records[role]=(path,digest,raw)
    def original(role,ext):
        row=records.get(role)
        return (row[2] if row and row[0].lower().endswith(ext)
                and pins.get(role)==row[1] and sha(row[2])==row[1]
                else None)
    def policy(role):
        raw=original(role,'.json')
        return binary_json(raw) if raw is not None else {}
    def view(role):
        raw=original(role,'.png')
        return rgba(raw) if raw is not None else None
    raw=original('NATIVE_EXPORT','.glb')
    doc,binary=_glb_parts(raw) if raw is not None else ({},b'')
    native=_mesh(raw) if raw is not None else None
    embedded=_embedded(doc,binary) if raw is not None else None
    mats=doc.get('materials',[])
    images=doc.get('images',[])
    refs=_references(doc) if raw is not None else None
    prims=[p for m in doc.get('meshes',[]) if type(m) is dict
           for p in m.get('primitives',[]) if type(p) is dict]
    pbr=bool(prims and mats and all(type(p.get('attributes')) is dict
         and 'POSITION' in p['attributes'] for p in prims)
         and all(type(m) is dict and
                 type(m.get('pbrMetallicRoughness')) is dict for m in mats))
    n=int(rule_id.rsplit('-',1)[1])
    if n==118:
        baseline_raw=original('P3_ATLAS_BASELINE','.glb')
        baseline=_mesh(baseline_raw) if baseline_raw else None
        atlas_policy=policy('P3_ATLAS_POLICY')
        before,after=bindings(baseline_raw),bindings(raw)
        target=atlas_policy.get('min_material_binding_reduction')
        quality=atlas_policy.get('min_atlas_color_variance')
        atlas_images=bool(embedded and numeric(quality) and quality>0 and
                          all(x['variance']>=quality for x in embedded))
        measured=bool(before is not None and after is not None and
                      before>after>=1 and type(target) is int and target>=1
                      and before-after>=target and atlas_images and
                      boxes_close(native,baseline,0.01))
        checks=(bool(baseline_raw and original('P3_ATLAS_POLICY','.json')
                     and raw),before is not None and after is not None,measured)
    elif n==119:
        bake_policy=policy('P3_BAKE_POLICY')
        baked_raw=original('P3_BAKED_NORMAL','.png')
        baked=view('P3_BAKED_NORMAL')
        normal_refs=[m.get('normalTexture',{}).get('index') for m in mats
                     if type(m) is dict and type(m.get('normalTexture')) is dict]
        textures=doc.get('textures',[])
        matching=False
        if baked and embedded and normal_refs and type(textures) is list:
            matching=all(type(i) is int and 0<=i<len(textures)
                         and type(textures[i].get('source')) is int
                         and 0<=textures[i]['source']<len(embedded)
                         and embedded[textures[i]['source']]['sha256']==sha(baked_raw)
                         for i in normal_refs)
        checks=(bool(original('P3_BAKE_POLICY','.json') and
                     bake_policy.get('normal_bake_required') is True
                     and baked_raw and raw),
                bool(baked and matching and
                     all('TEXCOORD_0' in p.get('attributes',{}) for p in prims)),
                bool(matching and baked['variance']>1 and
                     baked['unique_rgb']>=4))
    elif n==120:
        approved_raw=original('P3_APPROVED_EXPORT','.glb')
        approved=_mesh(approved_raw) if approved_raw else None
        exact=bool(native and approved and
                   native['triangles']==approved['triangles'] and
                   boxes_close(native,approved,0.000001))
        checks=(bool(approved_raw and raw),exact,False)
    elif n==133:
        defects=policy('P4_GEOMETRY_DEFECT_REPORT')
        count=defects.get('degenerate_triangle_count')
        measured=bool(native and type(count) is int and count>=0 and
                      count==sum(x['degenerate_triangles']
                                 for x in native['metrics']))
        checks=(bool(original('P4_GEOMETRY_DEFECT_REPORT','.json') and
                     view('LIGHT_NEUTRAL_VIEW')),
                measured,False)
    elif n==134:
        direct=view('LIGHT_DIRECT_VIEW')
        neutral=view('LIGHT_NEUTRAL_VIEW')
        checks=(bool(original('P4_LIGHTING_QA','.json') and direct),
                bool(pbr and rgb_different(direct,neutral) and
                     direct['mean']>neutral['mean']),False)
    elif n==135:
        shadow=view('LIGHT_SHADOW_VIEW')
        neutral=view('LIGHT_NEUTRAL_VIEW')
        checks=(bool(original('P4_LIGHTING_QA','.json') and shadow),
                bool(pbr and rgb_different(shadow,neutral) and
                     shadow['mean']<neutral['mean']),False)
    elif n==136:
        reflection=view('REFLECTION_VIEW')
        material_plan=policy('P4_MATERIAL_PLAN')
        metal=bool(mats and any(
            type(m) is dict and type(m.get('pbrMetallicRoughness')) is dict
            and numeric(m['pbrMetallicRoughness'].get('metallicFactor'))
            and m['pbrMetallicRoughness']['metallicFactor']>=0.7 for m in mats))
        checks=(bool(original('P4_MATERIAL_PLAN','.json') and
                     material_plan.get('fivem_shader_profile') and reflection),
                bool(metal and reflection and
                     rgb_different(reflection,view('LIGHT_NEUTRAL_VIEW'))),False)
    elif n==139:
        underside=view('VISUAL_VIEW_UNDERSIDE')
        qa=policy('P345_QA_REPORT')
        findings=qa.get('unresolved_findings')
        checks=(bool(original('P345_QA_REPORT','.json') and underside),
                bool(underside and type(findings) is list and
                     all(type(x) is str and x.strip() for x in findings)
                     and native),False)
    elif n==140:
        presentation=view('LIGHT_CINEMATIC_VIEW')
        technical=view('LIGHT_NEUTRAL_VIEW')
        qa=policy('P345_QA_REPORT')
        light=policy('P4_LIGHTING_QA')
        checks=(bool(original('P345_QA_REPORT','.json') and
                     original('P4_LIGHTING_QA','.json')),
                bool(presentation and technical and
                     rgb_different(presentation,technical) and
                     type(qa.get('unresolved_findings')) is list and
                     light.get('presentation_mode')=='STUDIO_ONLY'),False)
    elif n==143:
        before_raw=original('P5_HIDDEN_BASELINE','.glb')
        before=_mesh(before_raw) if before_raw else None
        hidden=policy('P5_HIDDEN_GEOMETRY_POLICY')
        target=hidden.get('min_removed_triangles')
        checks=(bool(before_raw and original('P5_HIDDEN_GEOMETRY_POLICY','.json')
                     and raw),
                bool(before and native and type(target) is int and target>0
                     and before['triangles']-native['triangles']>=target
                     and boxes_close(before,native,0.001)),False)
    elif n==145:
        lod_raw=original('LOD_EXPORT','.glb')
        lod=_mesh(lod_raw) if lod_raw else None
        budget=policy('P5_PERF_BUDGET')
        near,far=view('LOD_NEAR_VIEW'),view('LOD_FAR_VIEW')
        ratio=budget.get('lod_max_triangle_ratio')
        checks=(bool(raw and lod_raw and
                     original('P5_PERF_BUDGET','.json')),
                bool(native and lod and numeric(ratio) and 0<ratio<1
                     and lod['triangles']<native['triangles']
                     and lod['triangles']/native['triangles']<=ratio
                     and near and far and rgb_different(near,far)
                     and boxes_close(native,lod,budget.get(
                         'lod_bounds_tolerance_m',0.01))),False)
    elif n==147:
        budget=policy('P5_PERF_BUDGET')
        min_shared=budget.get('min_shared_texture_bindings')
        quality=budget.get('min_reused_texture_variance')
        checks=(bool(raw and original('P5_PERF_BUDGET','.json')),
                bool(refs is not None and type(min_shared) is int
                     and min_shared>=2 and len(refs)>=min_shared
                     and len(set(refs))<len(refs)
                     and embedded and numeric(quality) and quality>0
                     and all(im['variance']>=quality for im in embedded)),False)
    else:
        budget=policy('P5_PERF_BUDGET')
        capture=policy('P5_RUNTIME_CAPTURE')
        samples=capture.get('frame_ms_samples')
        target=budget.get('target_frame_ms')
        checks=(bool(raw and original('P5_PERF_BUDGET','.json') and
                     original('P5_RUNTIME_CAPTURE','.json')),
                bool(type(samples) is list and len(samples)>=10 and
                     all(positive(x) and x<10000 for x in samples) and
                     positive(target) and
                     sum(samples)/len(samples)<=target),False)
    criteria=CRITERIA[n]
    need(len(criteria)==3 and len(checks)==3 and
         all(type(x) is bool for x in checks),
         'C07_P345_REMAINING_SOURCE_PREDICATE_SCHEMA')
    return {'rule_id':rule_id,'checks':dict(zip(criteria,checks)),
            'evidence_complete':False,
            'full_rule_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
            'owner_acceptance':'UNKNOWN','fivem_runtime':'UNKNOWN',
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'advancement_authorized':False}
