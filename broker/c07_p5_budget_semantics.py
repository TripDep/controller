"""C07 P5 O-141/142/144/146/148: measured original-budget/GLB oracles.

Only exact Controller-recorded bytes and pre-D SHA pins count. A quantitative
observation is not artistic fitness, independent MG0, owner or FiveM PASS.
"""
import hashlib
import json
import math
import struct

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p3_geometry_semantics import geometry
from c07_a10_c10_original_evidence import original_image
from c07_p345_forty_native_evidence import TEXT, PHASE_INDEX

NUMBERS = (141, 142, 144, 146, 148)
IDS = tuple("AAA-200-O-%03d" % n for n in NUMBERS)
SCHEMA = "gg-c07-p5-five-original-budget-oracles-v1"

class OriginalBudgetBlocked(ValueError):
    pass

def need(condition, why):
    if not condition:
        raise OriginalBudgetBlocked(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def _json(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 1_000_000,
         "C07_P5_ORIGINAL_BUDGET_BYTES")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "C07_P5_DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def reject(value):
        raise OriginalBudgetBlocked("C07_P5_NONFINITE_JSON")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                       parse_constant=reject)
    need(type(value) is dict, "C07_P5_BUDGET_OBJECT_REQUIRED")
    return value

def _positive(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0

def _glb_parts(raw):
    need(type(raw) is bytes and len(raw) >= 28 and raw[:4] == b"glTF",
         "C07_P5_ORIGINAL_GLB")
    version, length = struct.unpack_from("<II", raw, 4)
    jsz, typ = struct.unpack_from("<I4s", raw, 12)
    need(version == 2 and length == len(raw) and typ == b"JSON"
         and jsz % 4 == 0 and 0 < jsz <= 8_000_000
         and 28 + jsz <= len(raw), "C07_P5_GLB_HEADER")
    size, kind = struct.unpack_from("<I4s", raw, 20 + jsz)
    need(kind == b"BIN\x00" and size % 4 == 0
         and 28 + jsz + size == len(raw), "C07_P5_GLB_BINARY")
    doc = _json(raw[20:20+jsz].rstrip(b" \x00"))
    need(doc.get("asset", {}).get("version") == "2.0"
         and type(doc.get("materials", [])) is list
         and type(doc.get("images", [])) is list
         and type(doc.get("bufferViews", [])) is list,
         "C07_P5_GLB_TABLES")
    return doc, raw[28+jsz:]

def _texture_bytes(doc, binary):
    images = doc.get("images", [])
    views = doc.get("bufferViews", [])
    need(len(images) <= 128, "C07_P5_TOO_MANY_IMAGES")
    decoded = []
    for entry in images:
        if type(entry) is not dict or entry.get("mimeType") != "image/png":
            return None  # External/JPEG/KTX bytes cannot be claimed as measured PNG.
        index = entry.get("bufferView")
        if type(index) is not int or index < 0 or index >= len(views):
            return None
        view = views[index]
        off, length = view.get("byteOffset", 0), view.get("byteLength")
        if (type(off) is not int or type(length) is not int
                or off < 0 or length <= 0 or off+length > len(binary)):
            return None
        actual = original_image(binary[off:off+length])
        if actual is None:
            return None
        decoded.append(actual)
    return decoded if decoded else None

def inspect(inventory, plan, controller, asset, step, work, *, source_loader):
    need(type(inventory) is dict and inventory.get("rule_count") == 763
         and inventory.get("schema") == "gg-effective-family-inventory-v1"
         and type(plan) is dict and type(work) is dict
         and plan.get("phase") in PHASE_INDEX
         and PHASE_INDEX[plan["phase"]] >= 5
         and work.get("phase") == plan["phase"] and callable(source_loader),
         "C07_P5_EXACT_OPERATION_CONTEXT")
    catalog = inventory.get("source_digests", {}).get("aaa_catalog")
    need(type(catalog) is str and len(catalog) == 64
         and all(c in "0123456789abcdef" for c in catalog),
         "C07_P5_ORIGINAL_CATALOG")
    for number, rid in zip(NUMBERS, IDS):
        source, phase = TEXT[str(number)]
        row = inventory["rules"].get(rid, {})
        need(phase == "P5" and row.get("family") == "AAA-200"
             and row.get("catalog_number") == number
             and row.get("catalog_section") == "O"
             and row.get("catalog_phase") == phase
             and row.get("requirement") == source
             and row.get("requirement_sha256") == sha(source.encode())
             and row.get("source_sha256") == catalog,
             "C07_P5_ORIGINAL_LITERAL_CHANGED:" + rid)
    audit, tail, state, audit_sha = _original_attempt(
        inventory, plan, controller, asset, step, work)
    need(state.get("last_audit_hash") == tail
         and sha(controller.master.read_bytes()) == work["master_sha256"]
         and (state.get("active_step") or {}).get("step") == step,
         "C07_P5_ORIGINAL_AUDIT_DRIFT")
    records = _registered_artifacts(audit, state, step, source_loader, work)
    wanted = {"P5_PERF_BUDGET", "NATIVE_EXPORT", "LOD_EXPORT"}
    found = {}
    for role, path, digest, raw in records:
        if role in wanted:
            need(role not in found, "C07_P5_DUPLICATE_ROLE:" + role)
            found[role] = (path, digest, raw)
    contract = plan.get("p345_evidence_contract", {})
    pins = contract.get("original_artifact_sha256", {}) if type(contract) is dict else {}
    if type(pins) is not dict:
        pins = {}
    def original(role, extension):
        entry = found.get(role)
        if entry is None or not entry[0].lower().endswith(extension):
            return None
        return entry[2] if pins.get(role) == entry[1] and sha(entry[2]) == entry[1] else None
    budget_raw = original("P5_PERF_BUDGET", ".json")
    budget = _json(budget_raw) if budget_raw is not None else {}
    glb_raw = original("NATIVE_EXPORT", ".glb")
    native = geometry(glb_raw) if glb_raw is not None else None
    doc, binary = _glb_parts(glb_raw) if native is not None else ({}, b"")
    lod_raw = original("LOD_EXPORT", ".glb")
    lod = geometry(lod_raw) if lod_raw is not None else None
    triangles = sum(x["triangles"] for x in native or [])
    lod_triangles = sum(x["triangles"] for x in lod or [])
    material_count = len(doc.get("materials", []))
    images = _texture_bytes(doc, binary) if native is not None else None
    texture_bytes = (sum(im["width"] * im["height"] * 4 for im in images)
                     if images is not None else None)
    limit_tri = budget.get("max_triangles")
    limit_mat = budget.get("material_count_budget")
    limit_tex = budget.get("max_texture_mb")
    lod_ratio = budget.get("lod_max_triangle_ratio")
    near = budget.get("lod_near_m")
    far = budget.get("lod_far_m")
    checks = {
        141: {
            "original_platform_and_scene_budget_scoped":
                budget.get("platform") == "GTA_V_FIVEM"
                and type(budget.get("scene_class")) is str
                and bool(budget["scene_class"].strip())
                and type(limit_tri) is int and limit_tri > 0
                and type(limit_mat) is int and limit_mat > 0
                and _positive(limit_tex),
            "real_native_scene_fits_declared_triangle_budget":
                triangles > 0 and type(limit_tri) is int
                and triangles <= limit_tri,
            "real_original_material_and_rgba_cost_within_pre_d_budget":
                native is not None and images is not None
                and type(limit_mat) is int and 0 < material_count <= limit_mat
                and _positive(limit_tex)
                and texture_bytes is not None
                and texture_bytes <= limit_tex * 1024 * 1024,
        },
        142: {
            "all_original_glb_triangles_counted":
                native is not None and triangles > 0,
            "measured_count_not_above_original_pre_d_limit":
                triangles > 0 and type(limit_tri) is int
                and 0 < triangles <= limit_tri,
        },
        144: {
            "real_original_lod_reduces_triangle_count":
                lod is not None and 0 < lod_triangles < triangles,
            "lod_ratio_and_distance_contract_measured":
                lod is not None and triangles > 0 and _positive(lod_ratio)
                and lod_ratio < 1 and lod_triangles/triangles <= lod_ratio
                and _positive(near) and _positive(far) and near < far,
        },
        146: {
            "actual_export_material_table_measured":
                native is not None and material_count > 0,
            "material_count_within_original_budget":
                material_count > 0 and type(limit_mat) is int
                and 0 < material_count <= limit_mat,
        },
        148: {
            "all_embedded_original_png_dimensions_decoded":
                images is not None and len(images) == len(doc.get("images", [])),
            "actual_rgba_memory_bound_by_original_budget":
                texture_bytes is not None and _positive(limit_tex)
                and texture_bytes <= limit_tex * 1024 * 1024,
        },
    }
    rules = {}
    for number, rid in zip(NUMBERS, IDS):
        measured = checks[number]
        rules[rid] = {
            "requirement_sha256": inventory["rules"][rid]["requirement_sha256"],
            "source_sha256": catalog,
            "exact_attempt_id": work["attempt_id"],
            "operation_sha256": work["operation_sha256"],
            "original_machine_checks": measured,
            "machine_scope": ("OBSERVED_SCOPE_PASS" if all(measured.values())
                              else "UNKNOWN_OR_DEFECT"),
            "full_rule_semantics": "UNKNOWN",
            "individual_mg0": "UNKNOWN",
            "owner_acceptance": "UNKNOWN",
            "advancement_authorized": False,
        }
    return {
        "schema": SCHEMA, "source_rule_count": 5, "rules": rules,
        "original_audit_sha256": audit_sha, "original_audit_tail": tail,
        "attempt_id": work["attempt_id"],
        "operation_sha256": work["operation_sha256"],
        "metrics": {"triangles": triangles, "lod_triangles": lod_triangles,
                    "materials": material_count, "embedded_png_count":
                    len(images) if images is not None else None,
                    "rgba_uncompressed_bytes": texture_bytes},
        "machine_positive_obligations": sum(
            r["machine_scope"] == "OBSERVED_SCOPE_PASS" for r in rules.values()),
        "full_rule_semantic_passes": 0, "individual_mg0_passes": 0,
        "advancement_authorized": False,
    }
