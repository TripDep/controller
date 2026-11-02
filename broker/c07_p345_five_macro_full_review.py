"""C07 P3-P5 macro: five independent original-source physical/atlas QA gates.

This is one P3-P5 coherent macro spanning L118, M121, M125, M127, O143.
Original hashes, operation audit and source-specific proof are never replaced
by producer attestations or self-reported PASS. Source PASS != MG0/FiveM.
"""
import hashlib
from collections import Counter

from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p345_remaining_original_review import (
    inspect as remaining,triangle_counts,atlas_surface_fidelity)
from c07_p4_material_macro_full_review import inspect as material
from c07_p5_budget_semantics import _glb_parts
from c07_p4_texture_semantics import _embedded
from c07_p345_forty_native_evidence import binary_json

IDS=frozenset(('AAA-200-L-118','AAA-200-M-121','AAA-200-M-125',
               'AAA-200-M-127','AAA-200-O-143'))
class CrossMacroBlocked(ValueError):pass
def need(ok,msg):
    if not ok:raise CrossMacroBlocked(msg)
def sha(raw):return hashlib.sha256(raw).hexdigest()

def all_embedded_textures_really_used(doc):
    """Every independently decoded embedded image must feed a real native
    primitive via an actual UV0 accessor. An unused pretty PNG is no proof."""
    materials=doc.get('materials')
    images=doc.get('images')
    textures=doc.get('textures')
    if not (type(materials) is list and type(images) is list
            and type(textures) is list and images):
        return False
    used=set()
    for mesh in doc.get('meshes',[]):
        if type(mesh) is not dict:return False
        for primitive in mesh.get('primitives',[]):
            if type(primitive) is not dict:return False
            attrib=primitive.get('attributes')
            mid=primitive.get('material')
            if (type(attrib) is not dict or
                    type(attrib.get('TEXCOORD_0')) is not int or
                    type(mid) is not int or not 0<=mid<len(materials)):
                return False
            mat=materials[mid]
            if type(mat) is not dict:return False
            pbr=mat.get('pbrMetallicRoughness')
            base=pbr.get('baseColorTexture') if type(pbr) is dict else None
            if type(base) is not dict:return False
            tid=base.get('index')
            if type(tid) is not int or not 0<=tid<len(textures):
                return False
            texture=textures[tid]
            img=texture.get('source') if type(texture) is dict else None
            if type(img) is not int or not 0<=img<len(images):
                return False
            used.add(img)
    return used==set(range(len(images)))


def inspect(ctx,rule_id):
    need(type(ctx) is dict and set(ctx)=={
        'inventory','plan','controller','asset','step','work','source_loader'}
        and rule_id in IDS,'C07_P345_FIVE_MACRO_TRUSTED_CONTEXT')
    inv,plan,ctl,asset,step,work,loader=(
        ctx[k] for k in ('inventory','plan','controller','asset',
                         'step','work','source_loader'))
    # Keep the existing 40-rule canonical byte/literal audit, plus material
    # and geometry source readers. No duplicate or user-fed summary proofs.
    base=(material(ctx,rule_id) if '-M-' in rule_id
          else remaining(ctx,rule_id))
    rows,tail,state,auditsha=_original_attempt(inv,plan,ctl,asset,step,work)
    need(base['original_audit_sha256']==auditsha and
         base['original_audit_tail']==tail and
         state.get('last_audit_hash')==tail and
         sha(ctl.master.read_bytes())==work['master_sha256'],
         'C07_P345_FIVE_MACRO_ORIGINAL_AUDIT_MISMATCH')
    pins=plan.get('p345_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_P345_FIVE_MACRO_PRE_D_PINS')
    originals={}
    for role,path,digest,raw in _registered_artifacts(
        rows,state,step,loader,work):
        need(role not in originals,'C07_P345_FIVE_MACRO_DUPLICATE_ROLE')
        originals[role]=(path,digest,raw)
    def src(role,ext):
        item=originals.get(role)
        return (item[2] if item and item[0].lower().endswith(ext)
                and pins.get(role)==item[1]
                and sha(item[2])==item[1] else None)
    raw=src('NATIVE_EXPORT','.glb')
    checks=dict(base['checks'])
    complete=False
    evidence={}
    if rule_id=='AAA-200-L-118':
        before=src('P3_ATLAS_BASELINE','.glb')
        policy_raw=src('P3_ATLAS_POLICY','.json')
        complete=bool(raw and before and policy_raw)
        if complete:
            earlier=triangle_counts(before)
            later=triangle_counts(raw)
            policy=binary_json(policy_raw)
            geometry=bool(earlier and later and
                set(later)==set(earlier) and
                all(earlier[t]>=later[t]>=1 for t in earlier))
            quality=atlas_surface_fidelity(before,raw,
                    policy.get('max_atlas_sample_rgb_delta'))
            # Require both benefit and NO altered original surface.
            key=list(checks)[-1]
            checks[key]=bool(checks[key] and geometry and quality)
            evidence={'same_oriented_surfaces':geometry,
                      'actual_source_texture_fidelity':quality}
    elif rule_id=='AAA-200-O-143':
        before=src('P5_HIDDEN_BASELINE','.glb')
        policy_raw=src('P5_HIDDEN_GEOMETRY_POLICY','.json')
        complete=bool(raw and before and policy_raw)
        if complete:
            prior=triangle_counts(before)
            after=triangle_counts(raw)
            policy=binary_json(policy_raw)
            discarded=prior-after if prior and after else Counter()
            # Mathematically redundant: remove only exact overlapping
            # identical winding duplicates; ALL unique surfaces remain.
            # No inference from merely lowering triangle count or bbox.
            removal=bool(prior and after and set(prior)==set(after) and
                all(after[t]>=1 and after[t]<=prior[t] for t in prior)
                and all(prior[t]>1 and after[t]>=1 for t in discarded)
                and type(policy.get('min_removed_triangles')) is int
                and sum(discarded.values())>=
                     policy['min_removed_triangles']>0)
            checks[list(checks)[-1]]=bool(checks[list(checks)[1]]
                                           and removal)
            evidence={'all_original_unique_oriented_faces_preserved':removal,
                      'actual_redundant_triangles_removed':
                        sum(discarded.values())}
    else:
        policy_raw=src('P4_MATERIAL_CONFORMANCE','.json')
        complete=bool(raw and policy_raw)
        if complete:
            policy=binary_json(policy_raw)
            doc,binary=_glb_parts(raw)
            images=_embedded(doc,binary)
            # Prove physical classification on all actual used materials,
            # not a list of names alone. M126 independently enforces five
            # distinct used wood/stone/metal/glass/plaster signatures.
            if rule_id=='AAA-200-M-121':
                independent=material(ctx,'AAA-200-M-126')
                physically=bool(independent['evidence_complete']
                                  and all(independent['checks'].values()))
                checks[list(checks)[-1]]=bool(checks[list(checks)[-1]]
                                               and physically)
                evidence={'independent_five_physical_class_replay':physically}
            else:
                # M125 and M127 concern actual surface pixels versus
                # approved original reference, never fabricated shader labels.
                sibling=('AAA-200-M-127' if rule_id.endswith('125')
                         else 'AAA-200-M-125')
                independent=material(ctx,sibling)
                corroborated=bool(independent['evidence_complete'] and
                                   all(independent['checks'].values()) and
                                   images and
                                   len(images)==len(doc.get('images',[]))
                                   and all_embedded_textures_really_used(doc))
                checks[list(checks)[-1]]=bool(checks[list(checks)[-1]]
                                               and corroborated)
                evidence={'independent_surface_reference_replay':corroborated}
    need(len(checks)==3 and all(type(v) is bool for v in checks.values()),
         'C07_P345_FIVE_MACRO_EXACT_RULE_CRITERIA')
    return {'rule_id':rule_id,'checks':checks,'evidence_complete':complete,
            'original_replayed_evidence':evidence,
            'original_audit_sha256':auditsha,'original_audit_tail':tail,
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'individual_mg0':'UNKNOWN','fivem_runtime':'UNVERIFIED',
            'owner_acceptance':'UNVERIFIED','advancement_authorized':False}
