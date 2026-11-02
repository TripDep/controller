"""C07 P3/P5 original texture macro: baking and reuse without lost detail.

L119 verifies actual original tangent-space baked normal map on UV-bound
primitives, not a policy label. O147 verifies active reused real textures and
unchanged independently sampled surface colors against a pinned baseline GLB.
Documentary source result is not renderer, MG0 or owner approval.
"""
import hashlib
import math
from c07_p345_remaining_original_review import (
    inspect as remaining,atlas_surface_fidelity,triangle_counts,
    actual_primitive_texture_reuse,baked_normal_channels_valid)
from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p5_budget_semantics import _glb_parts
from c07_p345_forty_native_evidence import binary_json
from c07_p4_texture_semantics import _embedded
from visual_content_metrics import decode_grid,VisualContentBlocked

L='AAA-200-L-119'
O='AAA-200-O-147'
RULES=frozenset((L,O))
class NativeTextureMacroBlocked(ValueError):pass
def need(test,reason):
    if not test:raise NativeTextureMacroBlocked(reason)
def sha(b):return hashlib.sha256(b).hexdigest()

def inspect(ctx,rid):
    need(rid in RULES and type(ctx) is dict and
         set(ctx)=={'inventory','plan','controller','asset',
                   'step','work','source_loader'},
         'C07_TEXTURE_MACRO_CURRENT_CONTEXT')
    inv,plan,controller,asset,step,work,loader=(
        ctx[k] for k in ('inventory','plan','controller',
                         'asset','step','work','source_loader'))
    base=remaining(ctx,rid)
    audit,tail,state,auditsha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(base['original_audit_sha256']==auditsha and
         base['original_audit_tail']==tail and
         sha(controller.master.read_bytes())==work['master_sha256']
         and state.get('last_audit_hash')==tail,
         'C07_TEXTURE_MACRO_AUDIT_DRIFT')
    pins=plan.get('p345_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_TEXTURE_MACRO_PRE_D_PINS')
    known={}
    for role,path,digest,raw in _registered_artifacts(
            audit,state,step,loader,work):
        need(role not in known,'C07_TEXTURE_MACRO_DUPLICATE_SOURCE_ROLE')
        known[role]=(path,digest,raw)
    def source(role,ext):
        v=known.get(role)
        return v[2] if (v and v[0].lower().endswith(ext)
             and pins.get(role)==v[1] and sha(v[2])==v[1]) else None
    native=source('NATIVE_EXPORT','.glb')
    checks=dict(base['checks'])
    complete=False;proof={}
    if rid==L:
        bake=source('P3_BAKED_NORMAL','.png')
        policy=source('P3_BAKE_POLICY','.json')
        complete=bool(native and bake and policy)
        doc,binary=_glb_parts(native) if native else ({},b'')
        embedded=_embedded(doc,binary) if native else None
        materials=doc.get('materials',[])
        textures=doc.get('textures',[])
        used=[]
        for mesh in doc.get('meshes',[]):
            for prim in mesh.get('primitives',[]):
                material_id=prim.get('material')
                if not (type(material_id) is int and
                    0<=material_id<len(materials) and
                    'TEXCOORD_0' in prim.get('attributes',{})):
                    used=[];break
                mat=materials[material_id]
                idx=mat.get('normalTexture',{}).get('index')
                if not (type(idx) is int and 0<=idx<len(textures)
                    and type(textures[idx].get('source')) is int):
                    used=[];break
                used.append(textures[idx]['source'])
        bound=bool(bake is not None and embedded and used and len(used)==sum(
            len(m.get('primitives',[])) for m in doc.get('meshes',[]))
            and all(0<=index<len(embedded)
               and embedded[index]['sha256']==sha(bake) for index in used))
        physically=False
        if complete and bound and baked_normal_channels_valid(bake):
            try:
                w,h,pixels=decode_grid(bake,step=1)
                tangent_samples={
                    (r,g,b) for r,g,b in pixels if b>=170}
                physically=bool(w>=4 and h>=4 and len(tangent_samples)>=4
                    and any(abs(r-128)>=3 or abs(g-128)>=3
                            for r,g,b in tangent_samples))
            except (VisualContentBlocked,ValueError,TypeError,KeyError):
                pass
        checks[list(checks)[1]]=bool(checks[list(checks)[1]] and bound)
        checks[list(checks)[2]]=bool(checks[list(checks)[2]] and physically)
        proof={'original_active_normal_bindings':bound,
               'original_tangent_space_perturbation_measured':physically}
    else:
        before=source('P5_REUSE_BASELINE','.glb')
        policyraw=source('P5_PERF_BUDGET','.json')
        complete=bool(native and before and policyraw)
        policy=binary_json(policyraw) if policyraw else {}
        limit=policy.get('max_reuse_rgb_delta')
        reuse=False;same=False
        if complete:
            doc,bindata=_glb_parts(native)
            prior,binprior=_glb_parts(before)
            quality=_embedded(doc,bindata)
            used=actual_primitive_texture_reuse(doc)
            min_shared=policy.get('min_shared_texture_bindings')
            reuse=bool(quality and
                type(min_shared) is int and min_shared>=2
                and sum(used.values())>=min_shared and
                any(x>=2 for x in used.values()))
            original_faces=triangle_counts(before)
            current_faces=triangle_counts(native)
            same=bool(reuse and
                original_faces and current_faces and
                set(original_faces)==set(current_faces) and
                all(original_faces[k]>=current_faces[k]>=1
                    for k in current_faces) and
                type(limit) in (int,float) and math.isfinite(limit)
                and 0<=limit<=16 and
                atlas_surface_fidelity(before,native,limit))
        # If the separately required before/after quality baseline is not
        # source-pinned, retain the existing positive observation that real
        # images are reused, but NEVER promote a full source verdict.
        checks[list(checks)[1]]=bool(checks[list(checks)[1]] and
                                       (reuse if complete else True))
        checks[list(checks)[2]]=same
        proof={'original_multiple_native_primitive_reuse':reuse,
               'no_uv_surface_color_loss_vs_pinned_original_glb':same}
    need(len(checks)==3 and all(type(v) is bool for v in checks.values()),
         'C07_TEXTURE_MACRO_LITERAL_CRITERIA')
    return {'rule_id':rid,'checks':checks,'evidence_complete':complete,
            'original_evidence':proof,'original_audit_sha256':auditsha,
            'original_audit_tail':tail,'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'mg0':'UNKNOWN','owner_acceptance':'UNKNOWN',
            'fivem_runtime':'UNVERIFIED','advancement_authorized':False}
