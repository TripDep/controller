"""C07 P3 L-118/119/120: original atlas, normal-map and mesh comparison.

All three are scoped observations on exact SHA-pinned GLB/PNG bytes. A
texture reuse measurement does not prove an atlas was worthwhile; a linked
normal map does not prove its bake; matching vertices does not authenticate
an owner-approved visual reference or grant individual MG0.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p3_geometry_semantics import geometry, _read_accessor
from c07_p5_budget_semantics import _glb_parts, _texture_bytes, _json
from c07_a10_c10_original_evidence import original_image
from c07_p345_forty_native_evidence import TEXT, PHASE_INDEX

NUMBERS=(118,119,120)
IDS=tuple("AAA-200-L-%03d"%n for n in NUMBERS)
SCHEMA="gg-c07-p3-three-original-finalization-oracles-v1"

class OriginalFinalizationBlocked(ValueError):
    pass

def need(ok,why):
    if not ok:
        raise OriginalFinalizationBlocked(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def finite(x):
    return type(x) in (int,float) and math.isfinite(x)

def _scene(raw):
    if raw is None:
        return None
    measured=geometry(raw)
    doc,binary=_glb_parts(raw)
    points=[]
    for mesh in doc["meshes"]:
        for prim in mesh["primitives"]:
            points.extend(_read_accessor(doc,binary,
                         prim["attributes"]["POSITION"]))
    return {"doc":doc,"binary":binary,"points":sorted(points),
            "triangles":sum(x["triangles"] for x in measured),
            "primitives":sum(len(x["primitives"]) for x in doc["meshes"])}

def _shared_atlas(scene):
    if scene is None:
        return None
    doc=scene["doc"]
    materials=doc.get("materials",[])
    textures=doc.get("textures",[])
    images=_texture_bytes(doc,scene["binary"])
    if images is None:
        return None
    uses={}
    for mesh in doc["meshes"]:
        for prim in mesh["primitives"]:
            idx=prim.get("material")
            if type(idx) is not int or not 0<=idx<len(materials):
                return None
            pbr=materials[idx].get("pbrMetallicRoughness",{})
            tex=pbr.get("baseColorTexture",{})
            if type(tex) is not dict or type(tex.get("index")) is not int:
                return None
            tidx=tex["index"]
            if not 0<=tidx<len(textures):
                return None
            source=textures[tidx].get("source")
            if type(source) is not int or not 0<=source<len(images):
                return None
            uses[source]=uses.get(source,0)+1
    return {"images":images,"uses":uses}

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and inventory.get("rule_count")==763
         and inventory.get("schema")=="gg-effective-family-inventory-v1"
         and type(plan) is dict and type(work) is dict
         and plan.get("phase") in PHASE_INDEX
         and PHASE_INDEX[plan["phase"]]>=3
         and work.get("phase")==plan["phase"] and callable(source_loader),
         "C07_P3_FINALIZATION_CONTEXT")
    catalog=inventory.get("source_digests",{}).get("aaa_catalog")
    need(type(catalog) is str and len(catalog)==64
         and all(c in "0123456789abcdef" for c in catalog),
         "C07_P3_FINALIZATION_CATALOG")
    for n,rid in zip(NUMBERS,IDS):
        literal,phase=TEXT[str(n)]
        row=inventory["rules"].get(rid,{})
        need(phase=="P3" and row.get("family")=="AAA-200"
             and row.get("catalog_number")==n
             and row.get("catalog_section")=="L"
             and row.get("catalog_phase")==phase
             and row.get("requirement")==literal
             and row.get("requirement_sha256")==sha(literal.encode())
             and row.get("source_sha256")==catalog,
             "C07_P3_FINALIZATION_LITERAL_CHANGED:"+rid)
    audit,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get("last_audit_hash")==tail
         and sha(controller.master.read_bytes())==work["master_sha256"]
         and (state.get("active_step") or {}).get("step")==step,
         "C07_P3_FINALIZATION_AUDIT_DRIFT")
    artifacts=_registered_artifacts(audit,state,step,source_loader,work)
    roles={"NATIVE_EXPORT","P3_ATLAS_PLAN","P3_BAKE_PLAN",
           "P3_HIGH_POLY_SOURCE","P3_APPROVED_REFERENCE",
           "P3_APPROVED_COMPARISON","P3_COMPARE_FRONT","P3_COMPARE_SIDE"}
    found={}
    for role,path,digest,raw in artifacts:
        if role in roles:
            need(role not in found,"C07_P3_FINALIZATION_DUPLICATE_ROLE:"+role)
            found[role]=(path,digest,raw)
    contract=plan.get("p345_evidence_contract",{})
    pins=contract.get("original_artifact_sha256",{}) if type(contract) is dict else {}
    if type(pins) is not dict:pins={}
    def original(role,ext):
        row=found.get(role)
        return (row[2] if row and row[0].lower().endswith(ext)
                and pins.get(role)==row[1] and sha(row[2])==row[1]
                else None)
    export_raw=original("NATIVE_EXPORT",".glb")
    scene=_scene(export_raw)
    atlas_raw=original("P3_ATLAS_PLAN",".json")
    atlas_plan=_json(atlas_raw) if atlas_raw is not None else {}
    bake_raw=original("P3_BAKE_PLAN",".json")
    bake_plan=_json(bake_raw) if bake_raw is not None else {}
    high_raw=original("P3_HIGH_POLY_SOURCE",".glb")
    high=_scene(high_raw)
    reference_raw=original("P3_APPROVED_REFERENCE",".glb")
    reference=_scene(reference_raw)
    compare_raw=original("P3_APPROVED_COMPARISON",".json")
    compare=_json(compare_raw) if compare_raw is not None else {}
    atlas=_shared_atlas(scene)
    max_images=atlas_plan.get("max_images")
    min_shared=atlas_plan.get("min_primitives_per_atlas")
    atlas_shared=bool(
        atlas and type(max_images) is int and 1<=max_images<=128
        and len(atlas["images"])<=max_images
        and type(min_shared) is int and 2<=min_shared<=100
        and max(atlas["uses"].values(),default=0)>=min_shared)
    atlas_pinned=bool(
        atlas and type(atlas_plan.get("expected_atlas_image_sha256")) is str
        and any(img["sha256"]==atlas_plan["expected_atlas_image_sha256"]
                for img in atlas["images"]))
    high_ratio=bake_plan.get("min_high_to_low_triangle_ratio")
    high_low=bool(
        high and scene and finite(high_ratio) and 1<high_ratio<=1000
        and high["triangles"]/scene["triangles"]>=high_ratio
        and bake_plan.get("high_poly_sha256")==sha(high_raw)
        and bake_plan.get("low_poly_sha256")==sha(export_raw))
    normal_link=False
    if scene and atlas:
        textures=scene["doc"].get("textures",[])
        mats=scene["doc"].get("materials",[])
        normal_link=bool(mats and all(
            type(m.get("normalTexture")) is dict
            and type(m["normalTexture"].get("index")) is int
            and 0<=m["normalTexture"]["index"]<len(textures)
            for m in mats))
    tolerance=compare.get("max_vertex_delta_m")
    same_points=bool(
        scene and reference and finite(tolerance) and 0<=tolerance<=1
        and compare.get("reference_sha256")==sha(reference_raw)
        and scene["triangles"]==reference["triangles"]
        and len(scene["points"])==len(reference["points"])
        and all(abs(a[k]-b[k])<=tolerance
                for a,b in zip(scene["points"],reference["points"])
                for k in range(3)))
    front_raw=original("P3_COMPARE_FRONT",".png")
    side_raw=original("P3_COMPARE_SIDE",".png")
    front=original_image(front_raw) if front_raw is not None else None
    side=original_image(side_raw) if side_raw is not None else None
    views=bool(front and side and front["sha256"]!=side["sha256"])
    checks={
        118:{"original_glb_primitives_share_actual_embedded_atlas":atlas_shared,
             "original_atlas_image_sha_matches_pre_d_source":atlas_pinned},
        119:{"original_high_and_low_poly_triangles_and_hashes_verified":high_low,
             "actual_exported_normal_map_texture_slot_linked":normal_link},
        120:{"original_reference_and_export_vertex_geometry_within_tolerance":
             same_points,
             "two_distinct_original_visual_comparison_png_bytes_decoded":views},
    }
    rules={}
    for n,rid in zip(NUMBERS,IDS):
        measured={k:bool(v) for k,v in checks[n].items()}
        rules[rid]={
            "requirement_sha256":inventory["rules"][rid]["requirement_sha256"],
            "source_sha256":catalog,
            "exact_attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "original_machine_checks":measured,
            "machine_scope":"OBSERVED_SCOPE_PASS" if all(measured.values())
                            else "UNKNOWN_OR_DEFECT",
            "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
            "owner_acceptance":"UNKNOWN","advancement_authorized":False,
        }
    return {
        "schema":SCHEMA,"source_rule_count":len(IDS),"rules":rules,
        "original_audit_sha256":audit_sha,"original_audit_tail":tail,
        "attempt_id":work["attempt_id"],"operation_sha256":work["operation_sha256"],
        "metrics":{"native_triangles":scene["triangles"] if scene else None,
                   "high_poly_triangles":high["triangles"] if high else None,
                   "atlas_images":len(atlas["images"]) if atlas else None,
                   "atlas_max_primitive_sharing":
                       max(atlas["uses"].values(),default=0) if atlas else None,
                   "reference_geometry_within_tolerance":same_points,
                   "comparison_views":int(bool(front))+int(bool(side))},
        "machine_positive_obligations":sum(
            v["machine_scope"]=="OBSERVED_SCOPE_PASS" for v in rules.values()),
        "full_rule_semantic_passes":0,"individual_mg0_passes":0,
        "advancement_authorized":False}
