"""M123 source-specific glTF2 PBR normal and roughness map evidence.

Only the explicitly source-pinned P4 glTF2 preview shader is assessed. It
does not assert RAGE shader compatibility, FiveM runtime, owner acceptance
or independent MG0. Original embedded PNG pixel channels are decoded.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p345_forty_native_evidence import inspect as inspect_p345, binary_json
from c07_p5_budget_semantics import _glb_parts
from visual_content_metrics import decode_grid, VisualContentBlocked

RULE = 'AAA-200-M-123'
CRITERIA = (
    'pre_d_gltf2_pbr_supported_normal_roughness_channels_and_original_export_sha_pinned',
    'every_original_native_material_references_two_valid_distinct_embedded_png_maps_with_uv',
    'independently_decoded_original_normal_and_roughness_pixel_channels_physically_nontrivial',
)

class PBRMapBlocked(ValueError):
    pass

def need(value, code):
    if not value:
        raise PBRMapBlocked(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def inspect(source_context, rule_id):
    need(rule_id == RULE and type(source_context) is dict and
         set(source_context) == {'inventory','plan','controller',
                                 'asset','step','work','source_loader'},
         'C07_M123_RULE_OR_CONTEXT')
    inv,plan,controller = (source_context[k] for k in
                           ('inventory','plan','controller'))
    asset,step,work,loader = (source_context[k] for k in
                              ('asset','step','work','source_loader'))
    need(plan.get('phase') in ('P4','P5','P6','P7','P8','VERIFY',
                              'G2','G3','G4','DELIVERY'),
         'C07_M123_P4_PHASE_REQUIRED')
    inspect_p345(inv,plan,controller,asset,step,work,source_loader=loader)
    rows,tail,state,audit_sha = _original_attempt(
        inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes()) == work['master_sha256'] and
         state.get('last_audit_hash') == tail and
         (state.get('active_step') or {}).get('step') == step,
         'C07_M123_ORIGINAL_AUDIT_DRIFT')
    contract=plan.get('p345_evidence_contract',{})
    pins=contract.get('original_artifact_sha256',{}) if type(contract) is dict else {}
    need(type(pins) is dict,'C07_M123_PRE_D_PINS')
    found={}
    for role,path,digest,raw in _registered_artifacts(
            rows,state,step,loader,work):
        need(role not in found,'C07_M123_DUPLICATE_ROLE')
        found[role]=(path,digest,raw)
    def original(role,ext):
        item=found.get(role)
        return item[2] if (item and item[0].lower().endswith(ext)
            and pins.get(role)==item[1] and sha(item[2])==item[1]) else None
    policy_raw=original('P4_SHADER_CAPABILITIES','.json')
    native_raw=original('NATIVE_EXPORT','.glb')
    policy=binary_json(policy_raw) if policy_raw is not None else {}
    allowed=bool(policy.get('shader_family')=='glTF2_PBR' and
        policy.get('target_phase')=='P4_GLTF_PREVIEW' and
        policy.get('supported_texture_channels')==
            ['normal','metallicRoughness'] and
        policy.get('texcoord_set')==0)
    doc,binary=_glb_parts(native_raw) if native_raw is not None else ({},b'')
    materials=doc.get('materials',[])
    textures=doc.get('textures',[])
    images=doc.get('images',[])
    views=doc.get('bufferViews',[])
    primitives=[p for mesh in doc.get('meshes',[])
                for p in mesh.get('primitives',[])]
    valid_structure=bool(allowed and materials and textures and images and
        primitives and all(type(v) is list for v in
            (materials,textures,images,views)) and
        all(type(p) is dict and
            type(p.get('material')) is int and
            0<=p['material']<len(materials) and
            type(p.get('attributes')) is dict and
            'TEXCOORD_0' in p['attributes'] for p in primitives))
    decoded=[]
    if valid_structure:
        for primitive in primitives:
            mat=materials[primitive['material']]
            pbr=mat.get('pbrMetallicRoughness',{})
            normal=mat.get('normalTexture',{})
            rough=pbr.get('metallicRoughnessTexture',{}) if type(pbr) is dict else {}
            if not (type(normal) is dict and type(rough) is dict and
                    type(normal.get('index')) is int and
                    type(rough.get('index')) is int and
                    normal['index']!=rough['index']):
                valid_structure=False
                break
            channels=[]
            for index in (normal['index'],rough['index']):
                if not 0<=index<len(textures):
                    valid_structure=False
                    break
                source=textures[index].get('source')
                if type(source) is not int or not 0<=source<len(images):
                    valid_structure=False
                    break
                image=images[source]
                view_index=image.get('bufferView')
                if (image.get('mimeType')!='image/png' or
                    type(view_index) is not int or not 0<=view_index<len(views)):
                    valid_structure=False
                    break
                view=views[view_index]
                off=view.get('byteOffset',0)
                size=view.get('byteLength')
                if (type(off) is not int or type(size) is not int or
                    off<0 or size<=0 or off+size>len(binary)):
                    valid_structure=False
                    break
                raw=binary[off:off+size]
                try:
                    w,h,pixels=decode_grid(raw,step=1)
                    if w<2 or h<2 or not pixels:
                        valid_structure=False
                        break
                    channels.append((sha(raw),pixels))
                except (VisualContentBlocked,ValueError,TypeError):
                    valid_structure=False
                    break
            if not valid_structure:
                break
            if channels[0][0]==channels[1][0]:
                valid_structure=False
                break
            decoded.append(channels)
    pixel_semantics=bool(valid_structure and decoded and all(
        all(90<=p[0]<=165 and 90<=p[1]<=165 and p[2]>=200
            for p in normal[1]) and
        max(p[1] for p in rough[1])-min(p[1] for p in rough[1])>=20
        for normal,rough in decoded))
    checks=dict(zip(CRITERIA,(
        bool(allowed and policy_raw is not None and native_raw is not None),
        valid_structure,pixel_semantics)))
    complete=bool(policy_raw and native_raw and allowed and doc and
                  materials and primitives)
    need(set(checks)==set(CRITERIA) and
         all(type(v) is bool for v in checks.values()),
         'C07_M123_EXACT_LITERAL_CRITERIA_CHANGED')
    return {'rule_id':rule_id,'checks':checks,
            'evidence_complete':complete,
            'source_sha256':inv['rules'][rule_id]['source_sha256'],
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'original_audit_sha256':audit_sha,
            'original_audit_tail':tail,
            'individual_mg0':'UNKNOWN','advancement_authorized':False}
