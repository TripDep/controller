"""C07 P8 S-181..190: ten distinct original-byte final QA observations.

This scanner checks original GLB geometry, six real PNG rasters and source-pinned
QA measurements. A self-authored QA report is NOT independent owner/MG0/FiveM
attestation. No result below authorizes delivery.
"""
import hashlib
import math
from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p3_geometry_semantics import geometry, _read_accessor
from c07_p5_budget_semantics import _glb_parts, _json
from c07_p4_texture_semantics import rgba
from c07_p678_forty_native_domain import TEXT, PHASES

NUMBERS=tuple(range(181,191))
IDS=tuple("AAA-200-S-%03d"%n for n in NUMBERS)
SCHEMA="gg-c07-p8-ten-original-final-qa-oracles-v1"
VIEWS=("FRONT","REAR","LEFT","RIGHT","TOP","UNDERSIDE")
class OriginalFinalQABlocked(ValueError):pass
def need(ok,why):
    if not ok:raise OriginalFinalQABlocked(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def finite(v):return type(v) in (int,float) and math.isfinite(v)
def close(a,b,tol=0.0001):return finite(a) and finite(b) and abs(a-b)<=tol
def bounds(raw):
    doc,blob=_glb_parts(raw)
    coords=[]
    for mesh in doc["meshes"]:
        for prim in mesh["primitives"]:
            coords.extend(_read_accessor(doc,blob,prim["attributes"]["POSITION"]))
    need(bool(coords),"C07_P8_NO_POSITION_VERTICES")
    return [[min(v[i] for v in coords) for i in range(3)],
            [max(v[i] for v in coords) for i in range(3)]],doc

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and inventory.get("rule_count")==763
         and inventory.get("schema")=="gg-effective-family-inventory-v1"
         and type(plan) is dict and type(work) is dict
         and plan.get("phase") in PHASES and PHASES[plan["phase"]]>=8
         and plan["phase"]==work.get("phase") and callable(source_loader),
         "C07_P8_FINAL_ORIGINAL_CONTEXT")
    catalog=inventory.get("source_digests",{}).get("aaa_catalog")
    need(type(catalog) is str and len(catalog)==64
         and all(x in "0123456789abcdef" for x in catalog),
         "C07_P8_FINAL_SOURCE")
    for n,rid in zip(NUMBERS,IDS):
        literal,phase=TEXT[str(n)]
        row=inventory["rules"].get(rid,{})
        need(phase=="P8" and row.get("family")=="AAA-200"
             and row.get("catalog_number")==n
             and row.get("catalog_section")=="S"
             and row.get("catalog_phase")==phase
             and row.get("requirement")==literal
             and row.get("requirement_sha256")==sha(literal.encode())
             and row.get("source_sha256")==catalog,
             "C07_P8_FINAL_LITERAL_CHANGED:"+rid)
    audit,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get("last_audit_hash")==tail
         and sha(controller.master.read_bytes())==work["master_sha256"]
         and (state.get("active_step") or {}).get("step")==step,
         "C07_P8_FINAL_AUDIT_DRIFT")
    found={}
    for role,path,digest,raw in _registered_artifacts(
            audit,state,step,source_loader,work):
        need(role not in found,"C07_P8_FINAL_DUPLICATE_ROLE:"+role)
        found[role]=(path,digest,raw)
    contract=plan.get("p678_evidence_contract",{})
    pins=contract.get("original_artifact_sha256",{}) if type(contract) is dict else {}
    if type(pins) is not dict:pins={}
    def original(role,ext=None):
        row=found.get(role)
        if row is None or (ext is not None and not row[0].lower().endswith(ext)):
            return None
        return row[2] if pins.get(role)==row[1] and sha(row[2])==row[1] else None
    def json_role(role):
        raw=original(role,".json")
        return _json(raw) if raw is not None else {}
    def png_role(role):
        raw=original(role,".png")
        return rgba(raw) if raw is not None else None
    native=original("NATIVE_EXPORT",".glb")
    baseline=original("BASELINE_SNAPSHOT",".glb")
    metrics=geometry(native) if native is not None else None
    bbox,doc=bounds(native) if native is not None else (None,{})
    views={v:png_role("VISUAL_VIEW_"+v) for v in VIEWS}
    six=all(views.values())
    unique=six and len({v["pixel_sha256"] for v in views.values()})==6
    aligned=json_role("P8_ALIGNMENT_REPORT")
    intersections=json_role("P8_INTERSECTION_REPORT")
    normals=json_role("P8_NORMALS_REPORT")
    regression=json_role("P8_REGRESSION_REPORT")
    machine=json_role("P8_MACHINE_REPORT")
    test_matrix=json_role("P8_TEST_MATRIX")
    internal=json_role("P8_INTERNAL_QA")
    material=png_role("P8_MATERIAL_RENDER")
    context=png_role("P8_AREA_CONTEXT")
    # Only independently measurable bounds and topology; no visual interpretation.
    declared=aligned.get("actual_bounds_xyz")
    measured=(bbox is not None and type(declared) is list and len(declared)==2
              and all(type(row) is list and len(row)==3 for row in declared)
              and all(close(a,b) for row_a,row_b in zip(bbox,declared)
                      for a,b in zip(row_a,row_b)))
    tolerance=aligned.get("max_axis_error_m")
    origin=aligned.get("expected_origin_xyz")
    origin_ok=(bbox is not None and finite(tolerance) and 0<=tolerance<=1
               and type(origin) is list and len(origin)==3
               and all(finite(v) for v in origin)
               and all(abs(bbox[0][i]-origin[i])<=tolerance for i in range(3)))
    top_ok=(metrics is not None and all(m["duplicate_geometric_faces"]==0
             and m["degenerate_triangles"]==0 for m in metrics))
    normal_ok=(metrics is not None and all(
        m["declared_vertex_normals"] and m["opposed_face_normals"]==0
        for m in metrics))
    # Original prohibited overlap regions are independently checked against
    # recomputed vertex bounds; this is conservative, not exact triangle contact.
    zones=intersections.get("forbidden_regions")
    zones_valid=(type(zones) is list and bool(zones) and len(zones)<=64
                 and all(type(z) is dict
                    and type(z.get("min_xyz")) is list
                    and type(z.get("max_xyz")) is list
                    and len(z["min_xyz"])==len(z["max_xyz"])==3
                    and all(finite(v) for v in z["min_xyz"]+z["max_xyz"])
                    and all(a<b for a,b in zip(z["min_xyz"],z["max_xyz"]))
                    for z in zones))
    # AABB separation proves the entire asset avoids the declared forbidden
    # region, but cannot establish all mesh-to-mesh intersections.
    forbidden_clear=(bbox is not None and zones_valid and all(
        any(bbox[1][i]<z["min_xyz"][i] or bbox[0][i]>z["max_xyz"][i]
            for i in range(3)) for z in zones))
    normal_report=(normals.get("native_sha256")==sha(native)
                   if native is not None else False)
    original_materials=(type(doc.get("materials")) is list
                        and bool(doc["materials"]))
    original_textures=(type(doc.get("textures")) is list
                       and bool(doc["textures"]))
    changed=(native is not None and baseline is not None
             and sha(native)!=sha(baseline))
    regression_bound=(changed
        and regression.get("before_sha256")==sha(baseline)
        and regression.get("after_sha256")==sha(native)
        and type(regression.get("checks")) is list
        and bool(regression["checks"])
        and all(type(x) is dict and x.get("status") in ("RUN","NOT_RUN","FAIL")
                and type(x.get("id")) is str and bool(x["id"])
                for x in regression["checks"]))
    machine_checks=machine.get("checks")
    machine_bound=(native is not None and machine.get("native_sha256")==sha(native)
        and type(machine_checks) is list and bool(machine_checks)
        and all(type(x) is dict and x.get("status") in ("RUN","NOT_RUN","FAIL")
                and type(x.get("id")) is str and bool(x["id"])
                for x in machine_checks))
    # A source-pinned test matrix must separate machine, visual and in-game
    # categories without laundering a producer FiveM RUN claim into proof.
    # Native geometry and six independent pixel rasters are re-read above.
    rows=test_matrix.get("tests")
    by_id={r.get("id"):r for r in rows} if (
        type(rows) is list and len(rows)==3 and
        all(type(r) is dict and type(r.get("id")) is str for r in rows)
        and len({r["id"] for r in rows})==3) else {}
    auto=by_id.get("AUTOMATED_NATIVE",{})
    visual=by_id.get("VISUAL_SIX",{})
    game=by_id.get("FIVEM_RUNTIME",{})
    categories_separated=bool(
        set(by_id)=={"AUTOMATED_NATIVE","VISUAL_SIX","FIVEM_RUNTIME"}
        and auto.get("category")=="AUTOMATED" and auto.get("status")=="RUN"
        and auto.get("evidence_role")=="NATIVE_EXPORT"
        and native is not None and auto.get("evidence_sha256")==sha(native)
        and bool(metrics)
        and visual.get("category")=="VISUAL" and visual.get("status")=="RUN"
        and unique and type(visual.get("view_sha256")) is dict
        and visual["view_sha256"]=={
            "VISUAL_VIEW_"+v:views[v]["sha256"] for v in VIEWS}
        and game.get("category")=="ENGINE" and game.get("status")=="NOT_RUN"
        and game.get("evidence_sha256") is None
        and game.get("evidence_role") is None)
    # A critical finding cannot be self-cleared; we only check fail-closed
    # behavior when a critical OPEN is recorded in original audit.
    critical=[r for r in audit if r.get("step")==step
              and r.get("event")=="QUALITY_FINDING"
              and r.get("severity")=="CRITICAL"
              and r.get("status") in ("OPEN","FAIL","UNKNOWN")]
    blocked=state.get("delivery_status")!="DELIVERABLE"
    internal_roles=internal.get("original_sha256")
    internal_bound=(type(internal_roles) is dict
        and native is not None
        and internal_roles.get("NATIVE_EXPORT")==sha(native)
        and all(internal_roles.get("VISUAL_VIEW_"+v)==views[v]["sha256"]
                for v in VIEWS) if six else False)
    no_self_approval=internal.get("owner_approved") is not True
    checks={
      181:{"six_original_png_views_decoded":bool(six),
           "six_original_views_have_distinct_reconstructed_pixels":bool(unique)},
      182:{"original_glb_bounds_match_measured_report":bool(measured),
           "source_declared_origin_within_measured_tolerance":bool(origin_ok)},
      183:{"no_original_duplicate_or_degenerate_faces":bool(top_ok),
           "original_forbidden_regions_conservatively_disjoint":bool(forbidden_clear)},
      184:{"all_original_primitives_have_normals":bool(normal_ok),
           "source_normals_report_bound_to_actual_glb":bool(normal_report)},
      185:{"original_export_has_material_and_texture_tables":
                bool(original_materials and original_textures),
           "original_material_qa_raster_decoded":material is not None},
      186:{"original_area_context_raster_decoded":context is not None,
           "area_context_differs_from_original_front_view":
                bool(context and views["FRONT"] and
                     context["pixel_sha256"]!=views["FRONT"]["pixel_sha256"])},
      187:{"original_baseline_export_bytes_differ":bool(changed),
           "original_regression_tests_bound_to_before_after":bool(regression_bound)},
      188:{"original_machine_report_bound_to_real_export":bool(machine_bound),
           "six_distinct_visual_views_separate_from_machine_report":bool(unique),
           "original_test_categories_and_unattested_engine_separated":
               categories_separated},
      189:{"original_critical_finding_present":bool(critical),
           "critical_finding_keeps_controller_delivery_blocked":
                bool(critical and blocked)},
      190:{"internal_qa_report_binds_export_and_six_rasters":bool(internal_bound),
           "internal_report_does_not_self_certify_owner":bool(no_self_approval)},
    }
    # Ten extra ORIGINAL-source semantic predicates, one per canonical P8
    # obligation. These are measured facts, not subjective quality, independent
    # owner approval, MG0 or engine certification. In particular, a historical
    # critical finding cannot establish a current-attempt delivery firewall.
    def unit_normals():
        if native is None:
            return False
        try:
            mesh_doc, blob = _glb_parts(native)
            primitives = [p for mesh in mesh_doc["meshes"]
                          for p in mesh["primitives"]]
            if not primitives:
                return False
            for prim in primitives:
                normals_idx = prim.get("attributes", {}).get("NORMAL")
                if type(normals_idx) is not int:
                    return False
                vectors = _read_accessor(mesh_doc, blob, normals_idx)
                if not vectors or any(
                    len(v) != 3 or not all(finite(x) for x in v) or
                    not 0.99 <= math.sqrt(sum(x*x for x in v)) <= 1.01
                    for v in vectors):
                    return False
            return True
        except (ValueError, TypeError, KeyError, IndexError):
            return False
    def valid_material_binding():
        if native is None:
            return False
        try:
            from c07_p4_texture_semantics import _embedded
            mesh_doc, blob = _glb_parts(native)
            materials = mesh_doc.get("materials", [])
            textures = mesh_doc.get("textures", [])
            images = mesh_doc.get("images", [])
            primitives = [p for mesh in mesh_doc["meshes"]
                          for p in mesh["primitives"]]
            # Referenced texture table entries alone do not prove that the
            # actual exported material image exists or is decodable. Reopen
            # every embedded PNG from original GLB binary bufferViews.
            decoded = _embedded(mesh_doc, blob)
            if not (materials and textures and images and primitives and
                    decoded and len(decoded)==len(images)):
                return False
            used=set()
            for prim in primitives:
                idx=prim.get("material")
                if type(idx) is not int or not 0<=idx<len(materials):
                    return False
                material=materials[idx]
                pbr=material.get("pbrMetallicRoughness")
                if type(pbr) is not dict:
                    return False
                binding=pbr.get("baseColorTexture")
                if type(binding) is not dict or type(binding.get("index")) is not int:
                    return False
                tid=binding["index"]
                if not 0<=tid<len(textures):
                    return False
                source=textures[tid].get("source")
                if type(source) is not int or not 0<=source<len(decoded):
                    return False
                used.add(source)
            return bool(used and all(
                decoded[i]["width"]>=2 and decoded[i]["height"]>=2 and
                decoded[i]["unique_rgba"]>=1
                for i in used))
        except (ValueError, TypeError, KeyError, IndexError):
            return False
    original_open = next((i for i, row in enumerate(audit)
        if row.get("event") == "SUPERVISOR_OPERATION_OPENED" and
           row.get("step") == step), -1)
    current_critical = [row for i,row in enumerate(audit)
        if i > original_open >= 0 and row.get("step") == step and
           row.get("event") == "QUALITY_FINDING" and
           row.get("severity") == "CRITICAL" and
           row.get("status") in ("OPEN", "FAIL", "UNKNOWN") and
           row.get("attempt_id") == work["attempt_id"] and
           row.get("operation_sha256") == work["operation_sha256"]]
    regression_ids = regression.get("checks")
    regression_rechecks = bool(regression_bound and
        type(regression_ids) is list and
        len({x["id"] for x in regression_ids}) == len(regression_ids) and
        any(x["status"] == "RUN" for x in regression_ids))
    deep = {
      181: ("original_six_views_and_machine_test_matrix_same_operation",
            bool(unique and categories_separated)),
      182: ("original_measured_horizontal_extents_nonzero_and_origin_pinned",
            bool(measured and origin_ok and
                 bbox[1][0] > bbox[0][0] and bbox[1][1] > bbox[0][1])),
      183: ("original_non_degenerate_mesh_outside_every_forbidden_region",
            bool(top_ok and forbidden_clear)),
      184: ("original_native_normals_are_unit_vectors_and_report_sha_bound",
            bool(normal_report and normal_ok and unit_normals())),
      185: ("original_export_primitives_bind_real_materials_and_textures",
            bool(material is not None and valid_material_binding())),
      186: ("original_area_context_and_front_have_matching_raster_dimensions",
            bool(context and views["FRONT"] and
                 context["width"] == views["FRONT"]["width"] and
                 context["height"] == views["FRONT"]["height"] and
                 context["pixel_sha256"] != views["FRONT"]["pixel_sha256"])),
      187: ("original_correction_rechecks_have_distinct_ids_and_run_result",
            regression_rechecks),
      188: ("original_machine_visual_engine_categories_and_native_sha_consistent",
            bool(categories_separated and machine_bound)),
      189: ("current_attempt_critical_blocks_original_controller_delivery",
            bool(current_critical and blocked)),
      190: ("independent_no_customer_defect_triage_attestation", False),
    }
    need(set(deep) == set(NUMBERS) and
         len({name for name, _ in deep.values()}) == 10 and
         all(type(v) is bool for _, v in deep.values()),
         "C07_P8_TEN_DISTINCT_ORIGINAL_SEMANTIC_PREDICATES")
    result={}
    for n,rid in zip(NUMBERS,IDS):
        c=checks[n]
        need(len(c)==(3 if n==188 else 2)
             and all(type(v) is bool for v in c.values()),
             "C07_P8_FINAL_EXACT_RULE_CHECKS:"+rid)
        result[rid]={
            "requirement_sha256":inventory["rules"][rid]["requirement_sha256"],
            "source_sha256":catalog,"exact_attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "original_machine_checks":c,
            "original_cross_source_semantic": {deep[n][0]: deep[n][1]},
            "machine_scope":"OBSERVED_SCOPE_PASS" if all(c.values())
                            else "UNKNOWN_OR_DEFECT",
            "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
            "owner_acceptance":"UNKNOWN","advancement_authorized":False,
        }
    return {"schema":SCHEMA,"source_rule_count":10,"rules":result,
            "original_audit_sha256":audit_sha,"original_audit_tail":tail,
            "attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "metrics":{"decoded_views":sum(v is not None for v in views.values()),
                       "triangle_count":sum(m["triangles"] for m in metrics or []),
                       "critical_open_audit_findings":len(critical)},
            "machine_positive_obligations":sum(
                v["machine_scope"]=="OBSERVED_SCOPE_PASS" for v in result.values()),
            "original_cross_source_positive_obligations":sum(
                value for _,value in deep.values()),
            "full_rule_semantic_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False}
