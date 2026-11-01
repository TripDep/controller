"""C07 P4 M-121/122/123/126: actual GLB material/PBR/PNG observations.

Checks original pre-D material assignments against exact Controller-recorded GLB
and embedded texture bytes. No subjective material realism or MG0 is certified.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p3_geometry_semantics import geometry
from c07_p5_budget_semantics import _glb_parts, _texture_bytes, _json
from c07_p345_forty_native_evidence import TEXT, PHASE_INDEX

NUMBERS=(121,122,123,126)
IDS=tuple("AAA-200-M-%03d"%n for n in NUMBERS)
SCHEMA="gg-c07-p4-four-original-pbr-oracles-v1"
CLASSES={"wood","stone","metal","glass","plaster"}

class OriginalMaterialBlocked(ValueError):
    pass

def need(ok,why):
    if not ok:raise OriginalMaterialBlocked(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def fraction(x):
    return type(x) in (int,float) and math.isfinite(x) and 0<=x<=1

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and inventory.get("rule_count")==763
         and inventory.get("schema")=="gg-effective-family-inventory-v1"
         and type(plan) is dict and type(work) is dict
         and plan.get("phase") in PHASE_INDEX
         and PHASE_INDEX[plan["phase"]]>=4
         and plan["phase"]==work.get("phase") and callable(source_loader),
         "C07_P4_ORIGINAL_CONTEXT")
    catalog=inventory.get("source_digests",{}).get("aaa_catalog")
    need(type(catalog) is str and len(catalog)==64
         and all(c in "0123456789abcdef" for c in catalog),
         "C07_P4_ORIGINAL_CATALOG")
    for n,rid in zip(NUMBERS,IDS):
        source,phase=TEXT[str(n)]
        row=inventory["rules"].get(rid,{})
        need(phase=="P4" and row.get("family")=="AAA-200"
             and row.get("catalog_number")==n
             and row.get("catalog_section")=="M"
             and row.get("catalog_phase")==phase
             and row.get("requirement")==source
             and row.get("requirement_sha256")==sha(source.encode())
             and row.get("source_sha256")==catalog,
             "C07_P4_ORIGINAL_LITERAL_CHANGED:"+rid)
    audit,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get("last_audit_hash")==tail
         and sha(controller.master.read_bytes())==work["master_sha256"]
         and (state.get("active_step") or {}).get("step")==step,
         "C07_P4_ORIGINAL_AUDIT_DRIFT")
    records=_registered_artifacts(audit,state,step,source_loader,work)
    found={}
    for role,path,digest,raw in records:
        if role in ("P4_MATERIAL_PLAN","NATIVE_EXPORT"):
            need(role not in found,"C07_P4_DUPLICATE_ROLE:"+role)
            found[role]=(path,digest,raw)
    contract=plan.get("p345_evidence_contract",{})
    pins=contract.get("original_artifact_sha256",{}) if type(contract) is dict else {}
    if type(pins) is not dict:pins={}
    def original(role,suffix):
        row=found.get(role)
        return (row[2] if row and row[0].lower().endswith(suffix)
                and pins.get(role)==row[1] and sha(row[2])==row[1]
                else None)
    plan_raw=original("P4_MATERIAL_PLAN",".json")
    material_plan=_json(plan_raw) if plan_raw is not None else {}
    raw=original("NATIVE_EXPORT",".glb")
    scanned=geometry(raw) if raw is not None else None
    doc,binary=_glb_parts(raw) if scanned is not None else ({},b"")
    images=_texture_bytes(doc,binary) if scanned is not None else None
    materials=doc.get("materials",[])
    primitives=[p for mesh in doc.get("meshes",[])
                for p in mesh.get("primitives",[])]
    refs=material_plan.get("physical_materials")
    tolerance=material_plan.get("roughness_tolerance")
    valid_refs=(type(refs) is list and bool(refs) and len(refs)<=50
                and all(type(r) is dict
                        and type(r.get("name")) is str and bool(r["name"])
                        and r.get("class") in CLASSES
                        and fraction(r.get("roughness_target"))
                        and fraction(r.get("metallic_target")) for r in refs))
    names=[r["name"] for r in refs] if valid_refs else []
    valid_refs=valid_refs and len(names)==len(set(names))
    glb_by_name={m.get("name"):m for m in materials
                 if type(m) is dict and type(m.get("name")) is str}
    all_assigned=(bool(primitives) and bool(materials)
                  and all(type(p.get("material")) is int
                          and 0<=p["material"]<len(materials)
                          for p in primitives))
    assigned={materials[p["material"]].get("name")
              for p in primitives} if all_assigned else set()
    matched=(valid_refs and all_assigned
             and len(glb_by_name)==len(materials)
             and set(names)==set(glb_by_name)==assigned)
    pbr_ok=(matched and all(
        type(glb_by_name[r["name"]].get("pbrMetallicRoughness")) is dict
        and fraction(glb_by_name[r["name"]]["pbrMetallicRoughness"].get(
            "roughnessFactor"))
        and fraction(glb_by_name[r["name"]]["pbrMetallicRoughness"].get(
            "metallicFactor")) for r in refs))
    measured={}
    if pbr_ok:
        for r in refs:
            m=glb_by_name[r["name"]]["pbrMetallicRoughness"]
            measured[r["name"]]=(m["roughnessFactor"],m["metallicFactor"])
    targets_ok=(pbr_ok and fraction(tolerance)
                and all(abs(measured[r["name"]][0]-r["roughness_target"])
                        <=tolerance
                        and abs(measured[r["name"]][1]-r["metallic_target"])
                        <=tolerance for r in refs))
    textures=doc.get("textures",[])
    all_image_refs=(images is not None and len(images)==len(doc.get("images",[]))
                    and type(textures) is list and bool(textures)
                    and all(type(t) is dict and type(t.get("source")) is int
                            and 0<=t["source"]<len(images) for t in textures))
    def linked(slot):
        if not all_image_refs or not matched:return False
        for m in materials:
            v=m.get(slot)
            if slot=="metallicRoughnessTexture":
                v=m.get("pbrMetallicRoughness",{}).get(slot)
            if type(v) is not dict or type(v.get("index")) is not int:
                return False
            if not 0<=v["index"]<len(textures):
                return False
        return True
    classes={r["class"] for r in refs} if valid_refs else set()
    distinct_pbr=len(set(measured.values())) if measured else 0
    checks={
        121:{
            "original_physical_material_classes_explicit":
                valid_refs and bool(classes),
            "all_original_glb_materials_matched_to_source_plan":
                bool(matched),
        },
        122:{
            "actual_exported_roughness_metalness_recomputed":
                bool(pbr_ok and measured),
            "original_physical_targets_respected_with_tolerance":
                bool(targets_ok),
        },
        123:{
            "original_embedded_texture_pixels_decoded_and_referenced":
                bool(all_image_refs and linked("normalTexture")),
            "original_pbr_metallic_roughness_texture_slot_linked":
                bool(linked("metallicRoughnessTexture")),
        },
        126:{
            "all_five_original_physical_classes_assigned_to_export":
                bool(matched and CLASSES<=classes),
            "five_materials_have_independently_different_pbr_values":
                bool(pbr_ok and CLASSES<=classes and distinct_pbr>=5),
        },
    }
    rules={}
    for n,rid in zip(NUMBERS,IDS):
        measured_checks=checks[n]
        rules[rid]={
            "requirement_sha256":inventory["rules"][rid]["requirement_sha256"],
            "source_sha256":catalog,"exact_attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "original_machine_checks":measured_checks,
            "machine_scope":"OBSERVED_SCOPE_PASS" if all(
                measured_checks.values()) else "UNKNOWN_OR_DEFECT",
            "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
            "owner_acceptance":"UNKNOWN","advancement_authorized":False,
        }
    return {"schema":SCHEMA,"source_rule_count":4,"rules":rules,
            "original_audit_sha256":audit_sha,"original_audit_tail":tail,
            "attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "original_material_metrics":{
                "exported_materials":len(materials),
                "original_classes_matched":len(classes) if matched else 0,
                "distinct_measured_pbr_pairs":distinct_pbr,
                "decoded_embedded_png_images":len(images) if images else 0},
            "machine_positive_obligations":sum(
                v["machine_scope"]=="OBSERVED_SCOPE_PASS"
                for v in rules.values()),
            "full_rule_semantic_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False}
