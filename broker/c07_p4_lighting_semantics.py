"""C07 P4 N-131..140: ten original-lighting and visual-QA pixel oracles.

Reconstruct PNG pixels and actual GLB topology/material values, not filenames,
producer QA flags or hashes alone. Pixel metrics do not certify lighting
realism, camera authenticity, owner acceptance, FiveM or individual MG0.
"""
import hashlib
import math
from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p3_geometry_semantics import geometry
from c07_p5_budget_semantics import _glb_parts,_json
from c07_p4_texture_semantics import rgba
from c07_p345_forty_native_evidence import TEXT,PHASE_INDEX

NUMBERS=tuple(range(131,141))
IDS=tuple("AAA-200-N-%03d"%n for n in NUMBERS)
SCHEMA="gg-c07-p4-ten-original-lighting-qa-oracles-v1"
VIEW_ROLES=("LIGHT_NEUTRAL_VIEW","LIGHT_CINEMATIC_VIEW",
            "LIGHT_DIRECT_VIEW","LIGHT_SHADOW_VIEW",
            "VISUAL_VIEW_FRONT","VISUAL_VIEW_REAR",
            "VISUAL_VIEW_SIDE","VISUAL_VIEW_TOP",
            "VISUAL_VIEW_UNDERSIDE","REFLECTION_VIEW")
class OriginalLightingBlocked(ValueError):pass
def need(ok,why):
    if not ok:raise OriginalLightingBlocked(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def finite(x):return type(x) in (int,float) and math.isfinite(x)
def positive(x):return finite(x) and x>0

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and inventory.get("rule_count")==763
         and inventory.get("schema")=="gg-effective-family-inventory-v1"
         and type(plan) is dict and type(work) is dict
         and plan.get("phase") in PHASE_INDEX
         and PHASE_INDEX[plan["phase"]]>=4
         and plan["phase"]==work.get("phase") and callable(source_loader),
         "C07_P4_LIGHTING_CONTEXT")
    catalog=inventory.get("source_digests",{}).get("aaa_catalog")
    need(type(catalog) is str and len(catalog)==64
         and all(x in "0123456789abcdef" for x in catalog),
         "C07_P4_LIGHTING_CATALOG")
    for n,rid in zip(NUMBERS,IDS):
        literal,phase=TEXT[str(n)]
        row=inventory["rules"].get(rid,{})
        need(phase=="P4" and row.get("family")=="AAA-200"
             and row.get("catalog_number")==n
             and row.get("catalog_section")=="N"
             and row.get("catalog_phase")==phase
             and row.get("requirement")==literal
             and row.get("requirement_sha256")==sha(literal.encode())
             and row.get("source_sha256")==catalog,
             "C07_P4_LIGHTING_LITERAL_CHANGED:"+rid)
    audit,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get("last_audit_hash")==tail
         and sha(controller.master.read_bytes())==work["master_sha256"]
         and (state.get("active_step") or {}).get("step")==step,
         "C07_P4_LIGHTING_AUDIT_DRIFT")
    found={}
    for role,path,digest,raw in _registered_artifacts(
            audit,state,step,source_loader,work):
        if role in set(VIEW_ROLES)|{"NATIVE_EXPORT","P4_LIGHTING_POLICY",
                                   "P4_MACHINE_REPORT"}:
            need(role not in found,"C07_P4_LIGHTING_DUPLICATE_ROLE:"+role)
            found[role]=(path,digest,raw)
    contract=plan.get("p345_evidence_contract",{})
    pins=contract.get("original_artifact_sha256",{}) if type(contract) is dict else {}
    if type(pins) is not dict:pins={}
    def original(role,ext):
        row=found.get(role)
        return (row[2] if row and row[0].lower().endswith(ext)
                and pins.get(role)==row[1] and sha(row[2])==row[1] else None)
    def document(role):
        raw=original(role,".json")
        return _json(raw) if raw is not None else {}
    views={role:rgba(original(role,".png"))
           if original(role,".png") is not None else None
           for role in VIEW_ROLES}
    policy=document("P4_LIGHTING_POLICY")
    report=document("P4_MACHINE_REPORT")
    native=original("NATIVE_EXPORT",".glb")
    metrics=geometry(native) if native is not None else None
    doc,_=_glb_parts(native) if native is not None else ({},b"")
    neutral=views["LIGHT_NEUTRAL_VIEW"]
    cinematic=views["LIGHT_CINEMATIC_VIEW"]
    direct=views["LIGHT_DIRECT_VIEW"]
    shadow=views["LIGHT_SHADOW_VIEW"]
    front=views["VISUAL_VIEW_FRONT"]
    underside=views["VISUAL_VIEW_UNDERSIDE"]
    reflection=views["REFLECTION_VIEW"]
    min_neutral=policy.get("min_neutral_luma")
    max_neutral=policy.get("max_neutral_luma")
    neutral_range=(finite(min_neutral) and finite(max_neutral)
                   and 0<=min_neutral<max_neutral<=255)
    neutral_ok=(neutral is not None and neutral_range
                and min_neutral<=neutral["mean"]<=max_neutral
                and neutral["variance"]>1)
    mode_names=policy.get("modes")
    modes_ok=(type(mode_names) is list and
              set(mode_names)=={"NEUTRAL","CINEMATIC"}
              and len(mode_names)==2)
    geometry_ok=(metrics is not None and all(
        m["degenerate_triangles"]==0 and m["duplicate_geometric_faces"]==0
        for m in metrics))
    direct_delta=policy.get("min_direct_delta")
    shadow_delta=policy.get("min_shadow_delta")
    direct_ok=(neutral is not None and direct is not None
               and positive(direct_delta) and direct_delta<=255
               and direct["mean"]-neutral["mean"]>=direct_delta)
    shadow_ok=(neutral is not None and shadow is not None
               and positive(shadow_delta) and shadow_delta<=255
               and neutral["mean"]-shadow["mean"]>=shadow_delta)
    materials=doc.get("materials",[])
    metals=(type(materials) is list and any(
        type(m) is dict and type(m.get("pbrMetallicRoughness")) is dict
        and finite(m["pbrMetallicRoughness"].get("metallicFactor"))
        and m["pbrMetallicRoughness"]["metallicFactor"]>=0.5
        for m in materials))
    eye=policy.get("player_eye_height_m")
    eye_ok=finite(eye) and 1.2<=eye<=2.2
    four=[views["VISUAL_VIEW_"+v] for v in
          ("FRONT","REAR","SIDE","TOP")]
    four_ok=all(four) and len({v["sha256"] for v in four})==4
    report_bound=(native is not None
                  and report.get("native_sha256")==sha(native)
                  and report.get("qa_status") in ("PENDING","UNKNOWN","FAIL")
                  and type(report.get("unresolved_findings")) is list)
    checks={
      131:{"neutral_original_png_pixels_reconstructed":neutral is not None,
           "neutral_exposure_measured_against_original_limits":bool(neutral_ok)},
      132:{"original_neutral_cinematic_modes_declared":bool(modes_ok),
           "neutral_cinematic_original_pixel_sources_distinct":
               bool(neutral and cinematic and
                    neutral["sha256"]!=cinematic["sha256"])},
      133:{"original_native_triangle_defects_scanned":bool(geometry_ok),
           "neutral_original_png_has_measurable_surface_variance":
               bool(neutral and neutral["variance"]>10)},
      134:{"original_direct_and_neutral_pngs_decoded":
               bool(direct and neutral),
           "original_direct_luma_delta_measured":bool(direct_ok)},
      135:{"original_shadow_and_neutral_pngs_decoded":
               bool(shadow and neutral),
           "original_shadow_luma_delta_measured":bool(shadow_ok)},
      136:{"actual_export_metallic_material_values_decoded":bool(metals),
           "original_reflection_qa_pixels_reconstructed":
               reflection is not None},
      137:{"original_player_eye_height_contract_numeric":bool(eye_ok),
           "original_front_view_pixels_decoded":front is not None},
      138:{"four_original_views_pixel_decoded":bool(all(four)),
           "four_original_view_bytes_distinct":bool(four_ok)},
      139:{"original_underside_view_pixel_decoded":underside is not None,
           "original_underside_distinct_from_cinematic":
               bool(underside and cinematic and
                    underside["sha256"]!=cinematic["sha256"])},
      140:{"original_technical_qa_report_bound_to_native":bool(report_bound),
           "original_presentation_view_separate_from_neutral":
               bool(cinematic and neutral and
                    cinematic["sha256"]!=neutral["sha256"])},
    }
    rules={}
    for n,rid in zip(NUMBERS,IDS):
        c=checks[n]
        need(len(c)==2 and all(type(v) is bool for v in c.values()),
             "C07_P4_LIGHTING_TWO_CHECKS:"+rid)
        rules[rid]={
            "requirement_sha256":inventory["rules"][rid]["requirement_sha256"],
            "source_sha256":catalog,"exact_attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "original_machine_checks":c,
            "machine_scope":"OBSERVED_SCOPE_PASS" if all(c.values())
                            else "UNKNOWN_OR_DEFECT",
            "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
            "owner_acceptance":"UNKNOWN","advancement_authorized":False}
    return {"schema":SCHEMA,"source_rule_count":10,"rules":rules,
            "original_audit_sha256":audit_sha,"original_audit_tail":tail,
            "attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "metrics":{"decoded_view_count":sum(v is not None for v in views.values()),
                       "native_triangles":sum(m["triangles"] for m in metrics or []),
                       "neutral_mean":neutral["mean"] if neutral else None,
                       "direct_mean":direct["mean"] if direct else None,
                       "shadow_mean":shadow["mean"] if shadow else None},
            "machine_positive_obligations":sum(
                r["machine_scope"]=="OBSERVED_SCOPE_PASS" for r in rules.values()),
            "full_rule_semantic_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False}
