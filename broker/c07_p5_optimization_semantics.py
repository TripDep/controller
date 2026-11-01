"""C07 P5 original-byte optimization oracles for O-143/145/147/149/150.

These are five distinct *scoped* technical observations, never a claim that
hidden geometry, visual LOD transitions, real-world performance, MG0, or owner
acceptance have been certified. In particular, untrusted FPS JSON cannot
become a FiveM runtime PASS.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p3_geometry_semantics import geometry, _read_accessor
from c07_p5_budget_semantics import _glb_parts, _json
from c07_p345_forty_native_evidence import TEXT, PHASE_INDEX

NUMBERS = (143, 145, 147, 149, 150)
IDS = tuple("AAA-200-O-%03d" % n for n in NUMBERS)
SCHEMA = "gg-c07-p5-five-original-optimization-oracles-v1"

class OriginalOptimizationBlocked(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise OriginalOptimizationBlocked(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def finite(x):
    return type(x) in (int, float) and math.isfinite(x)

def _mesh(raw):
    if raw is None:
        return None
    metrics = geometry(raw)
    doc, binary = _glb_parts(raw)
    coords = []
    primitive_materials = []
    for mesh in doc["meshes"]:
        for primitive in mesh["primitives"]:
            vertices = _read_accessor(doc, binary,
                                      primitive["attributes"]["POSITION"])
            coords.extend(vertices)
            primitive_materials.append((
                primitive.get("material"),
                next(row["triangles"] for row in metrics
                     if row["mesh_index"] == doc["meshes"].index(mesh)
                     and row["primitive_index"] == mesh["primitives"].index(primitive))))
    need(bool(coords), "C07_P5_EMPTY_VERTEX_SET")
    bounds = [[min(v[i] for v in coords) for i in range(3)],
              [max(v[i] for v in coords) for i in range(3)]]
    return {"doc": doc, "metrics": metrics, "bounds": bounds,
            "primitive_materials": primitive_materials,
            "triangles": sum(x["triangles"] for x in metrics)}

def _references(doc):
    materials = doc.get("materials", [])
    textures = doc.get("textures", [])
    images = doc.get("images", [])
    if not all(type(x) is list for x in (materials, textures, images)):
        return None
    refs = []
    for m in materials:
        if type(m) is not dict:
            return None
        pbr = m.get("pbrMetallicRoughness", {})
        if type(pbr) is not dict:
            return None
        for field, parent in (("baseColorTexture", pbr),
                              ("metallicRoughnessTexture", pbr),
                              ("normalTexture", m), ("occlusionTexture", m),
                              ("emissiveTexture", m)):
            entry = parent.get(field)
            if entry is None:
                continue
            if type(entry) is not dict or type(entry.get("index")) is not int:
                return None
            idx = entry["index"]
            if not 0 <= idx < len(textures):
                return None
            t = textures[idx]
            if type(t) is not dict or type(t.get("source")) is not int:
                return None
            src = t["source"]
            if not 0 <= src < len(images):
                return None
            refs.append(src)
    return refs

def inspect(inventory, plan, controller, asset, step, work, *, source_loader):
    need(type(inventory) is dict and inventory.get("rule_count") == 763
         and inventory.get("schema") == "gg-effective-family-inventory-v1"
         and type(plan) is dict and type(work) is dict
         and plan.get("phase") in PHASE_INDEX
         and PHASE_INDEX[plan["phase"]] >= 5
         and work.get("phase") == plan["phase"]
         and callable(source_loader), "C07_P5_OPTIMIZATION_CONTEXT")
    catalog = inventory.get("source_digests", {}).get("aaa_catalog")
    need(type(catalog) is str and len(catalog) == 64
         and all(c in "0123456789abcdef" for c in catalog),
         "C07_P5_OPTIMIZATION_CATALOG")
    for n, rid in zip(NUMBERS, IDS):
        literal, phase = TEXT[str(n)]
        row = inventory["rules"].get(rid, {})
        need(phase == "P5" and row.get("family") == "AAA-200"
             and row.get("catalog_number") == n
             and row.get("catalog_section") == "O"
             and row.get("catalog_phase") == phase
             and row.get("requirement") == literal
             and row.get("requirement_sha256") == sha(literal.encode())
             and row.get("source_sha256") == catalog,
             "C07_P5_OPTIMIZATION_LITERAL_CHANGED:" + rid)
    audit, tail, state, audit_sha = _original_attempt(
        inventory, plan, controller, asset, step, work)
    need(state.get("last_audit_hash") == tail
         and sha(controller.master.read_bytes()) == work["master_sha256"]
         and (state.get("active_step") or {}).get("step") == step,
         "C07_P5_OPTIMIZATION_AUDIT_DRIFT")
    artifacts = _registered_artifacts(
        audit, state, step, source_loader, work)
    found = {}
    wanted = {"NATIVE_EXPORT", "LOD_EXPORT", "P5_PERF_BUDGET",
              "P5_RUNTIME_CAPTURE"}
    for role, path, digest, raw in artifacts:
        if role in wanted:
            need(role not in found, "C07_P5_OPTIMIZATION_DUPLICATE:" + role)
            found[role] = (path, digest, raw)
    contract = plan.get("p345_evidence_contract", {})
    pins = contract.get("original_artifact_sha256", {}) if type(contract) is dict else {}
    if type(pins) is not dict:
        pins = {}
    def original(role, ext):
        item = found.get(role)
        if item is None or not item[0].lower().endswith(ext):
            return None
        return item[2] if pins.get(role) == item[1] and sha(item[2]) == item[1] else None

    native = _mesh(original("NATIVE_EXPORT", ".glb"))
    lod = _mesh(original("LOD_EXPORT", ".glb"))
    raw_budget = original("P5_PERF_BUDGET", ".json")
    budget = _json(raw_budget) if raw_budget is not None else {}
    raw_capture = original("P5_RUNTIME_CAPTURE", ".json")
    capture = _json(raw_capture) if raw_capture is not None else {}
    geometry_ok = native is not None
    duplicate = sum(x["duplicate_geometric_faces"] for x in native["metrics"]) if geometry_ok else None
    degenerate = sum(x["degenerate_triangles"] for x in native["metrics"]) if geometry_ok else None
    tolerance = budget.get("lod_bounds_tolerance_m")
    ratio = budget.get("lod_max_triangle_ratio")
    bounds_close = bool(native and lod and finite(tolerance) and
                        0 <= tolerance <= 10 and
                        all(abs(native["bounds"][side][axis] -
                                lod["bounds"][side][axis]) <= tolerance
                            for side in range(2) for axis in range(3)))
    ratio_ok = bool(native and lod and finite(ratio) and 0 < ratio < 1
                    and 0 < lod["triangles"] < native["triangles"]
                    and lod["triangles"] / native["triangles"] <= ratio)
    refs = _references(native["doc"]) if native else None
    min_shared = budget.get("min_shared_texture_bindings")
    shared = (refs is not None and type(min_shared) is int and
              2 <= min_shared <= 100 and len(refs) >= min_shared and
              len(set(refs)) < len(refs))
    alpha_count = None
    alpha_policy_ok = False
    if native:
        materials = native["doc"].get("materials", [])
        alpha_count = 0
        valid = bool(materials)
        for mat_idx, count in native["primitive_materials"]:
            if type(mat_idx) is not int or not 0 <= mat_idx < len(materials):
                valid = False
                break
            material = materials[mat_idx]
            mode = material.get("alphaMode", "OPAQUE")
            if mode not in ("OPAQUE", "MASK", "BLEND"):
                valid = False
                break
            if mode != "OPAQUE":
                alpha_count += count
        alpha_limit = budget.get("max_alpha_triangles")
        alpha_policy_ok = (valid and type(alpha_limit) is int
                           and 0 <= alpha_limit < 10**9
                           and alpha_count <= alpha_limit)
    fps_samples = capture.get("frame_ms_samples")
    capture_samples_valid = (
        type(fps_samples) is list and 10 <= len(fps_samples) <= 2000
        and all(finite(x) and 0 < x < 10000 for x in fps_samples))
    # Even authentic registered JSON is not an independently attested
    # in-game benchmark. Never promote it to a native/runtime verdict.
    checks = {
        143: {
            "actual_original_glb_faces_scanned_for_exact_duplicates":
                geometry_ok and duplicate is not None,
            "no_exact_duplicate_or_zero_area_faces":
                geometry_ok and duplicate == 0 and degenerate == 0,
        },
        145: {
            "original_lod_reduction_measured_against_pre_d_ratio": ratio_ok,
            "original_high_low_geometry_bounds_within_pre_d_tolerance": bounds_close,
        },
        147: {
            "original_glb_material_texture_indices_resolved": refs is not None,
            "actual_shared_texture_bindings_meet_pre_d_reuse_goal": shared,
        },
        149: {
            "original_alpha_draw_triangles_counted": alpha_count is not None,
            "actual_alpha_triangle_cost_within_pre_d_budget": alpha_policy_ok,
        },
        150: {
            "source_runtime_sample_vector_structurally_valid": capture_samples_valid,
            "independent_fivem_runtime_provenance_confirmed": False,
        },
    }
    rules = {}
    for n, rid in zip(NUMBERS, IDS):
        measured = {k: bool(v) for k, v in checks[n].items()}
        rules[rid] = {
            "requirement_sha256": inventory["rules"][rid]["requirement_sha256"],
            "source_sha256": catalog,
            "exact_attempt_id": work["attempt_id"],
            "operation_sha256": work["operation_sha256"],
            "original_machine_checks": measured,
            "machine_scope": "OBSERVED_SCOPE_PASS" if all(measured.values())
                             else "UNKNOWN_OR_DEFECT",
            "full_rule_semantics": "UNKNOWN", "individual_mg0": "UNKNOWN",
            "owner_acceptance": "UNKNOWN", "advancement_authorized": False,
        }
    return {
        "schema": SCHEMA, "source_rule_count": len(IDS), "rules": rules,
        "original_audit_sha256": audit_sha, "original_audit_tail": tail,
        "attempt_id": work["attempt_id"], "operation_sha256": work["operation_sha256"],
        "metrics": {
            "duplicate_faces": duplicate, "degenerate_faces": degenerate,
            "native_triangles": native["triangles"] if native else None,
            "lod_triangles": lod["triangles"] if lod else None,
            "bounds_match": bounds_close,
            "texture_binding_count": len(refs) if refs is not None else None,
            "distinct_referenced_images": len(set(refs)) if refs is not None else None,
            "alpha_triangles": alpha_count,
            "runtime_capture_unattested": bool(raw_capture),
        },
        "machine_positive_obligations": sum(
            v["machine_scope"] == "OBSERVED_SCOPE_PASS" for v in rules.values()),
        "full_rule_semantic_passes": 0, "individual_mg0_passes": 0,
        "advancement_authorized": False,
    }
