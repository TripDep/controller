"""C07 P3-P5 remaining 14: independently reread ORIGINAL cross-source semantics.

One current Controller attempt, hash-chained audit and pre-D SHA-pinned source
snapshot; distinct actual material, geometry, pixel, camera, LOD and timing
predicates. This is source-level evidence, not external renderer, CodeWalker,
FiveM, owner or independent MG0 certification. NEVER enroll from this report.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p345_forty_native_evidence import inspect as original_forty, binary_json
from c07_p5_budget_semantics import _glb_parts
from c07_p4_texture_semantics import rgba
from c07_p6_collision_semantics import _triangles
from c07_native_output_oracle import read_mesh_geometry
from c07_p4_material_macro_full_review import original_drawable_shader_compatibility
from c07_p345_light_pixel_replay import (
    neutral_pixel_qa, pixel_light_response, triplet_light_response,
    lod_view_color_distance, frame_samples_within_budget,
    player_camera_horizontal_alignment)

NUMBERS=(122,129,130,131,132,133,134,135,136,137,139,140,145,150)
IDS=tuple('AAA-200-'+('M' if n<=130 else 'N' if n<=140 else 'O')
          +'-'+str(n).zfill(3) for n in NUMBERS)
ROLES={
 122:('NATIVE_EXPORT','P4_MATERIAL_CONFORMANCE','P4_VIEW_NEUTRAL',
      'P4_VIEW_DIRECT','P4_VIEW_SHADOW'),
 129:('NATIVE_EXPORT','P4_MATERIAL_CONFORMANCE','P4_NATIVE_DRAWABLE_XML'),
 130:('NATIVE_EXPORT','P4_MATERIAL_CONFORMANCE','P4_VIEW_NEUTRAL',
      'P4_VIEW_DIRECT','P4_VIEW_SHADOW'),
 131:('NATIVE_EXPORT','P4_LIGHTING_QA','LIGHT_NEUTRAL_VIEW'),
 132:('P4_LIGHTING_QA','LIGHT_NEUTRAL_VIEW','LIGHT_CINEMATIC_VIEW'),
 133:('NATIVE_EXPORT','P4_GEOMETRY_DEFECT_REPORT','LIGHT_NEUTRAL_VIEW'),
 134:('NATIVE_EXPORT','P4_LIGHTING_QA','LIGHT_NEUTRAL_VIEW',
      'LIGHT_DIRECT_VIEW','LIGHT_SHADOW_VIEW'),
 135:('NATIVE_EXPORT','P4_LIGHTING_QA','LIGHT_NEUTRAL_VIEW',
      'LIGHT_DIRECT_VIEW','LIGHT_SHADOW_VIEW'),
 136:('NATIVE_EXPORT','P4_MATERIAL_PLAN','LIGHT_NEUTRAL_VIEW','REFLECTION_VIEW'),
 137:('NATIVE_EXPORT','P4_LIGHTING_QA','P4_PLAYER_CAMERA','VISUAL_PLAYER_VIEW'),
 139:('NATIVE_EXPORT','P345_QA_REPORT','VISUAL_VIEW_UNDERSIDE'),
 140:('P345_QA_REPORT','P4_LIGHTING_QA','LIGHT_NEUTRAL_VIEW',
      'LIGHT_CINEMATIC_VIEW'),
 145:('NATIVE_EXPORT','LOD_EXPORT','P5_PERF_BUDGET','LOD_NEAR_VIEW','LOD_FAR_VIEW'),
 150:('NATIVE_EXPORT','P5_PERF_BUDGET','P5_RUNTIME_CAPTURE'),
}
EXT={
 'NATIVE_EXPORT':'.glb','LOD_EXPORT':'.glb',
 'P4_NATIVE_DRAWABLE_XML':'.xml',
}
class RemainingCrossSourceBlocked(ValueError): pass
def need(ok,why):
    if not ok: raise RemainingCrossSourceBlocked(why)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def finite(v): return type(v) in (int,float) and math.isfinite(v)
def vec(v): return type(v) is list and len(v)==3 and all(finite(x) for x in v)
def triangle_ok(tri):
    a,b,c=tri
    u=[b[i]-a[i] for i in range(3)]
    v=[c[i]-a[i] for i in range(3)]
    cross=(u[1]*v[2]-u[2]*v[1],u[2]*v[0]-u[0]*v[2],
           u[0]*v[1]-u[1]*v[0])
    return all(finite(x) for x in cross) and sum(x*x for x in cross)>1e-16
def used_materials(doc):
    mats=doc.get('materials',[])
    if type(mats) is not list:return []
    result=[]
    for mesh in doc.get('meshes',[]):
        if type(mesh) is not dict:return []
        for p in mesh.get('primitives',[]):
            i=p.get('material') if type(p) is dict else None
            if type(i) is not int or not 0<=i<len(mats):return []
            result.append(mats[i])
    return result
def pbr_ok(materials):
    return bool(materials) and all(
        type(m) is dict and
        type(m.get('pbrMetallicRoughness')) is dict and
        all(finite(m['pbrMetallicRoughness'].get(k)) and
            0<=m['pbrMetallicRoughness'][k]<=1
            for k in ('metallicFactor','roughnessFactor'))
        for m in materials)
def metal_glass(materials):
    if not pbr_ok(materials):return False
    metal=any(m['pbrMetallicRoughness']['metallicFactor']>=0.6
              and m['pbrMetallicRoughness']['roughnessFactor']<=0.6
              for m in materials)
    glass=any(m.get('alphaMode') in ('BLEND','MASK') and
              m['pbrMetallicRoughness']['metallicFactor']<=0.2 and
              m['pbrMetallicRoughness']['roughnessFactor']<=0.3
              for m in materials)
    return metal and glass
def inspect_family(ctx):
    need(type(ctx) is dict and set(ctx)=={
        'inventory','plan','controller','asset','step','work','source_loader'},
        'C07_P345_REMAINING_TRUSTED_CONTEXT')
    inv,plan,ctl,asset,step,work,loader=(
        ctx[k] for k in ('inventory','plan','controller','asset',
                         'step','work','source_loader'))
    need(plan.get('phase') in ('P5','P6','P7','P8','VERIFY',
                               'G2','G3','G4','DELIVERY') and
         plan.get('phase')==work.get('phase') and callable(loader),
         'C07_P345_REMAINING_DUE_PHASE')
    report=original_forty(inv,plan,ctl,asset,step,work,source_loader=loader)
    rows,tail,state,auditsha=_original_attempt(inv,plan,ctl,asset,step,work)
    need(report['original_audit_sha256']==auditsha and
         report['original_audit_tail']==tail and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step and
         sha(ctl.master.read_bytes())==work['master_sha256'],
         'C07_P345_REMAINING_ORIGINAL_AUDIT_MASTER_DRIFT')
    contract=plan.get('p345_evidence_contract')
    pins=contract.get('original_artifact_sha256') if type(contract) is dict else None
    need(type(pins) is dict,'C07_P345_REMAINING_PRE_D_PINS_REQUIRED')
    registered={}
    for role,path,digest,raw in _registered_artifacts(
            rows,state,step,loader,work):
        need(role not in registered,'C07_P345_REMAINING_DUPLICATE_SOURCE_ROLE')
        registered[role]=(path,digest,raw)
    def original(role):
        item=registered.get(role)
        ext=EXT.get(role,'.png' if 'VIEW' in role else '.json')
        if not (item and item[0].lower().endswith(ext)
                and pins.get(role)==item[1] and sha(item[2])==item[1]):
            return None
        return item[2]
    def policy(role):
        raw=original(role)
        return binary_json(raw) if raw is not None else {}
    def image(role):
        raw=original(role)
        return rgba(raw) if raw is not None else None
    def captured(role,kind='RENDER_CAPTURED',mode=None):
        raw=original(role)
        if raw is None:return False
        found=[(i,r) for i,r in enumerate(rows) if
            r.get('event')==kind and r.get('step')==step and
            r.get('attempt_id')==work['attempt_id'] and
            r.get('operation_sha256')==work['operation_sha256'] and
            r.get('source_role')==role and r.get('image_sha256')==sha(raw)
            and (mode is None or r.get('mode')==mode)]
        return len(found)==1
    native=original('NATIVE_EXPORT')
    doc,_=_glb_parts(native) if native else ({},b'')
    materials=used_materials(doc)
    tris=_triangles(native) if native else []
    native_geometry=read_mesh_geometry(native) if native else None
    native_valid=bool(tris and all(triangle_ok(t) for t in tris))
    rows_out={}
    for n,rid in zip(NUMBERS,IDS):
        roles=ROLES[n]
        pinned=all(original(role) is not None for role in roles)
        measured=False
        if n in (122,130):
            pol=policy('P4_MATERIAL_CONFORMANCE')
            lp=pol.get('light_response',{})
            d=lp.get('min_direct_neutral_delta') if type(lp) is dict else None
            sh=lp.get('min_neutral_shadow_delta') if type(lp) is dict else None
            measured=bool(pbr_ok(materials) and finite(d) and finite(sh)
                and d>0 and sh>0 and
                triplet_light_response(original('P4_VIEW_NEUTRAL'),
                  original('P4_VIEW_DIRECT'),original('P4_VIEW_SHADOW'),
                  min_direct_delta=d,min_shadow_delta=sh))
            if n==130:
                measured=bool(measured and all(captured(role) for role in
                    ('P4_VIEW_NEUTRAL','P4_VIEW_DIRECT','P4_VIEW_SHADOW')))
        elif n==129:
            pol=policy('P4_MATERIAL_CONFORMANCE')
            xml=original('P4_NATIVE_DRAWABLE_XML')
            if xml is not None and native is not None:
                from c07_p4_texture_semantics import _embedded
                _,binary=_glb_parts(native)
                embedded=_embedded(doc,binary)
                parsed,compatible=original_drawable_shader_compatibility(
                    xml,doc,pol,embedded)
                measured=bool(parsed and compatible)
        elif n==131:
            measured=bool(native_valid and
                captured('LIGHT_NEUTRAL_VIEW','LIGHT_CAPTURED','neutral') and
                neutral_pixel_qa(original('LIGHT_NEUTRAL_VIEW')))
        elif n==132:
            measured=bool(
                captured('LIGHT_NEUTRAL_VIEW','LIGHT_CAPTURED','neutral') and
                captured('LIGHT_CINEMATIC_VIEW','LIGHT_CAPTURED','cinematic') and
                pixel_light_response(original('LIGHT_NEUTRAL_VIEW'),
                    original('LIGHT_CINEMATIC_VIEW'),direction=0,
                    minimum_delta=20))
        elif n==133:
            defects=policy('P4_GEOMETRY_DEFECT_REPORT')
            measured=bool(native_valid and
                defects.get('native_sha256')==sha(native) and
                defects.get('degenerate_triangle_count')==0 and
                captured('LIGHT_NEUTRAL_VIEW') and
                image('LIGHT_NEUTRAL_VIEW') is not None)
        elif n in (134,135):
            measured=bool(native_valid and pbr_ok(materials) and
                all(captured(role) for role in
                    ('LIGHT_NEUTRAL_VIEW','LIGHT_DIRECT_VIEW','LIGHT_SHADOW_VIEW')) and
                triplet_light_response(original('LIGHT_NEUTRAL_VIEW'),
                    original('LIGHT_DIRECT_VIEW'),original('LIGHT_SHADOW_VIEW'),
                    min_direct_delta=5,min_shadow_delta=5))
            if n==135:
                measured=bool(measured and pixel_light_response(
                    original('LIGHT_NEUTRAL_VIEW'),original('LIGHT_SHADOW_VIEW'),
                    direction=-1,minimum_delta=5))
        elif n==136:
            measured=bool(native_valid and metal_glass(materials) and
                captured('REFLECTION_VIEW') and
                captured('LIGHT_NEUTRAL_VIEW') and
                pixel_light_response(original('LIGHT_NEUTRAL_VIEW'),
                    original('REFLECTION_VIEW'),direction=0,minimum_delta=5))
        elif n==137:
            cam=policy('P4_PLAYER_CAMERA')
            pos,forward=cam.get('camera_xyz'),cam.get('forward_xyz')
            measured=bool(native_geometry and vec(pos) and vec(forward) and
                abs(math.sqrt(sum(x*x for x in forward))-1)<1e-5 and
                captured('VISUAL_PLAYER_VIEW',mode='player') and
                image('VISUAL_PLAYER_VIEW') is not None and
                player_camera_horizontal_alignment(pos,forward,native_geometry))
        elif n==139:
            qa=policy('P345_QA_REPORT')
            bottom=any(triangle_ok(t) and (
                (t[1][0]-t[0][0])*(t[2][1]-t[0][1])-
                (t[1][1]-t[0][1])*(t[2][0]-t[0][0]))< -1e-8 for t in tris)
            measured=bool(native_valid and bottom and
                captured('VISUAL_VIEW_UNDERSIDE') and
                qa.get('underside_qa_sha256')==sha(original('VISUAL_VIEW_UNDERSIDE')))
        elif n==140:
            events=[r for r in rows if r.get('event')=='VISUAL_QA_REVIEWED'
                and r.get('step')==step and r.get('attempt_id')==work['attempt_id']
                and r.get('operation_sha256')==work['operation_sha256']]
            tech=[r for r in events if r.get('review_kind')=='TECHNICAL' and
                r.get('image_sha256')==sha(original('LIGHT_NEUTRAL_VIEW'))]
            art=[r for r in events if r.get('review_kind')=='PRESENTATION' and
                r.get('image_sha256')==sha(original('LIGHT_CINEMATIC_VIEW'))]
            measured=bool(len(tech)==len(art)==1 and
                tech[0].get('reviewer_id') and art[0].get('reviewer_id') and
                tech[0]['reviewer_id']!=art[0]['reviewer_id'] and
                pixel_light_response(original('LIGHT_NEUTRAL_VIEW'),
                    original('LIGHT_CINEMATIC_VIEW'),direction=0,minimum_delta=5))
        elif n==145:
            budget=policy('P5_PERF_BUDGET')
            lod=original('LOD_EXPORT')
            lod_tri=_triangles(lod) if lod else []
            ratio=budget.get('lod_max_triangle_ratio')
            bound=budget.get('lod_max_view_rgb_delta')
            measured=bool(native_valid and lod_tri and
                all(triangle_ok(t) for t in lod_tri) and finite(ratio)
                and 0<ratio<1 and len(lod_tri)/len(tris)<=ratio and
                finite(bound) and 0<=bound<=255 and
                lod_view_color_distance(original('LOD_NEAR_VIEW'),
                    original('LOD_FAR_VIEW'),bound))
        else:
            budget=policy('P5_PERF_BUDGET')
            capture=policy('P5_RUNTIME_CAPTURE')
            measured=frame_samples_within_budget(
                capture.get('frame_ms_samples'),budget.get('target_frame_ms'))
        rows_out[rid]={
            'source_pins_complete':bool(pinned),
            'original_literal_measurement':bool(pinned and measured),
            'external_provenance':'UNKNOWN',
            'individual_mg0':'UNKNOWN','owner_acceptance':'UNKNOWN',
            'fivem_runtime':'UNKNOWN','advancement_authorized':False,
            'source_sha256':inv['rules'][rid]['source_sha256'],
            'requirement_sha256':inv['rules'][rid]['requirement_sha256'],
            'original_sha256':{role:sha(original(role))
                for role in roles if original(role) is not None},
        }
    need(len(rows_out)==14 and set(rows_out)==set(IDS),
         'C07_P345_REMAINING_FOURTEEN_LITERAL_DRIFT')
    return {'schema':'c07-p345-remaining14-original-crosssource-v1',
        'rule_count':14,'rules':rows_out,
        'original_audit_sha256':auditsha,'original_audit_tail':tail,
        'master_sha256':work['master_sha256'],
        'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'original_measured_count':sum(r['original_literal_measurement']
                                      for r in rows_out.values()),
        'full_semantic_passes':0,'individual_mg0_passes':0,
        'advancement_authorized':False}
