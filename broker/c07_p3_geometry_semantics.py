"""C07 P3: original-byte geometry oracles for four literal L-111..L-114 rules.

Unlike a GLB-header check or a QA event name, this independently reads every
triangle, tests its edges, detects duplicate/degenerate faces, and checks
declared normal direction. It is scoped to the exact registered Controller
operation. Open boundaries and intentional split vertices are not automatically
defects; a machine observation is NOT full artistic/owner/MG0 approval.
"""
from collections import Counter
import hashlib
import json
import math
import re
import struct

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p345_forty_native_evidence import TEXT, PHASE_INDEX

IDS = tuple("AAA-200-L-%03d" % n for n in range(111, 115))
SCHEMA = "gg-c07-p3-four-original-triangle-oracles-v1"
HEX = re.compile(r"[a-f0-9]{64}\Z")

class OriginalTopologyBlocked(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise OriginalTopologyBlocked(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def _read_accessor(doc, binary, index, *, scalar=False):
    accessors = doc["accessors"]
    views = doc["bufferViews"]
    need(type(index) is int and 0 <= index < len(accessors),
         "C07_P3_ACCESSOR_INDEX")
    a = accessors[index]
    typ = a.get("componentType")
    fmt = {5121: ("B", 1), 5123: ("H", 2), 5125: ("I", 4)}.get(typ) if scalar else (
        ("f", 4) if typ == 5126 else None)
    width = 1 if scalar else 3
    need(fmt is not None and a.get("type") == ("SCALAR" if scalar else "VEC3") and
         type(a.get("count")) is int and 3 <= a["count"] <= 500000 and
         "sparse" not in a and "normalized" not in a,
         "C07_P3_ACCESSOR_FORMAT")
    v = a.get("bufferView")
    need(type(v) is int and 0 <= v < len(views), "C07_P3_ACCESSOR_VIEW")
    view = views[v]
    off = view.get("byteOffset", 0)
    local = a.get("byteOffset", 0)
    stride = view.get("byteStride", width * fmt[1])
    length = view.get("byteLength")
    need(view.get("buffer") == 0 and
         all(type(x) is int for x in (off, local, stride, length)) and
         min(off, local, stride, length) >= 0 and
         stride >= width * fmt[1] and
         off + length <= len(binary) and
         local + (a["count"] - 1) * stride + width * fmt[1] <= length,
         "C07_P3_ACCESSOR_OUT_OF_BOUNDS")
    unpack = struct.Struct("<" + fmt[0] * width)
    result = [unpack.unpack_from(binary, off + local + i * stride)
              for i in range(a["count"])]
    need(scalar or all(math.isfinite(x) for row in result for x in row),
         "C07_P3_NONFINITE_VERTEX_OR_NORMAL")
    return [r[0] for r in result] if scalar else result

def geometry(raw):
    need(type(raw) is bytes and 52 <= len(raw) <= 250_000_000 and
         raw[:4] == b"glTF", "C07_P3_ORIGINAL_GLB_BYTES")
    version, declared = struct.unpack_from("<II", raw, 4)
    need(version == 2 and declared == len(raw), "C07_P3_GLB_VERSION_LENGTH")
    jsz, jtype = struct.unpack_from("<I4s", raw, 12)
    need(jtype == b"JSON" and 2 <= jsz <= 8_000_000 and
         jsz % 4 == 0 and 28 + jsz <= len(raw),
         "C07_P3_GLB_JSON")
    doc = json.loads(raw[20:20 + jsz])
    size, btype = struct.unpack_from("<I4s", raw, 20 + jsz)
    need(btype == b"BIN\x00" and size % 4 == 0 and
         28 + jsz + size == len(raw), "C07_P3_GLB_BIN")
    binary = memoryview(raw)[28 + jsz:]
    need(type(doc) is dict and
         all(type(doc.get(k)) is list for k in
             ("meshes", "buffers", "bufferViews", "accessors")) and
         len(doc["buffers"]) == 1 and
         type(doc["buffers"][0].get("byteLength")) is int and
         0 < doc["buffers"][0]["byteLength"] <= len(binary) and
         doc["meshes"], "C07_P3_GLB_TABLES")
    reports = []
    for mesh_index, mesh in enumerate(doc["meshes"]):
        need(type(mesh) is dict and type(mesh.get("primitives")) is list and
             mesh["primitives"], "C07_P3_MESH_PRIMITIVES")
        for primitive_index, prim in enumerate(mesh["primitives"]):
            need(type(prim) is dict and prim.get("mode", 4) == 4 and
                 type(prim.get("attributes")) is dict,
                 "C07_P3_TRIANGLE_PRIMITIVE_REQUIRED")
            vertices = _read_accessor(doc, binary, prim["attributes"].get("POSITION"))
            normals = None
            if "NORMAL" in prim["attributes"]:
                normals = _read_accessor(doc, binary, prim["attributes"]["NORMAL"])
                need(len(normals) == len(vertices), "C07_P3_NORMAL_COUNT")
            indices = (_read_accessor(doc, binary, prim["indices"], scalar=True)
                       if "indices" in prim else list(range(len(vertices))))
            need(len(indices) % 3 == 0 and len(indices) >= 3 and
                 all(type(i) is int and 0 <= i < len(vertices) for i in indices),
                 "C07_P3_TRIANGLE_INDICES")
            edges = Counter()
            faces = set()
            dup_faces = degenerate = reverse = 0
            for offset in range(0, len(indices), 3):
                a, b, c = indices[offset:offset + 3]
                p, q, r = vertices[a], vertices[b], vertices[c]
                canonical = tuple(sorted((p, q, r)))
                if canonical in faces:
                    dup_faces += 1
                faces.add(canonical)
                for u, v in ((a, b), (b, c), (c, a)):
                    edges[tuple(sorted((u, v)))] += 1
                u = [q[k] - p[k] for k in range(3)]
                v = [r[k] - p[k] for k in range(3)]
                cross = (u[1]*v[2]-u[2]*v[1],
                         u[2]*v[0]-u[0]*v[2],
                         u[0]*v[1]-u[1]*v[0])
                area2 = sum(x*x for x in cross)
                if len({a, b, c}) < 3 or area2 <= 1e-20:
                    degenerate += 1
                    continue
                if normals is not None:
                    avg = [sum(normals[i][k] for i in (a, b, c))
                           for k in range(3)]
                    if sum(cross[k]*avg[k] for k in range(3)) < -1e-10:
                        reverse += 1
            reports.append({
                "mesh_index": mesh_index, "primitive_index": primitive_index,
                "vertices": len(vertices), "triangles": len(indices)//3,
                "duplicate_coordinate_vertices": len(vertices)-len(set(vertices)),
                "duplicate_geometric_faces": dup_faces,
                "degenerate_triangles": degenerate,
                "boundary_edges": sum(v == 1 for v in edges.values()),
                "nonmanifold_edges": sum(v > 2 for v in edges.values()),
                "declared_vertex_normals": normals is not None,
                "opposed_face_normals": reverse,
            })
    need(reports and sum(x["triangles"] for x in reports) > 0,
         "C07_P3_EMPTY_TRIANGLE_SET")
    return reports

def inspect(inventory, plan, controller, asset, step, work, *, source_loader):
    need(type(inventory) is dict and inventory.get("rule_count") == 763 and
         type(plan) is dict and plan.get("phase") in PHASE_INDEX and
         PHASE_INDEX[plan["phase"]] >= PHASE_INDEX["P3"] and
         type(work) is dict and work.get("phase") == plan["phase"] and
         callable(source_loader), "C07_P3_ORIGINAL_WORK_SCOPE")
    catalog = inventory.get("source_digests", {}).get("aaa_catalog")
    need(type(catalog) is str and HEX.fullmatch(catalog),
         "C07_P3_CATALOG_ORIGIN")
    for n, rid in zip(range(111, 115), IDS):
        row = inventory["rules"].get(rid, {})
        requirement, phase = TEXT[str(n)]
        need(row.get("requirement") == requirement and
             row.get("requirement_sha256") ==
             sha(requirement.encode("utf-8")) and
             row.get("source_sha256") == catalog and
             row.get("catalog_number") == n and
             row.get("catalog_section") == "L" and
             phase == "P3", "C07_P3_LITERAL_SOURCE_CHANGED:" + rid)
    rows, tail, state, audit_sha = _original_attempt(
        inventory, plan, controller, asset, step, work)
    need(state.get("last_audit_hash") == tail and
         sha(controller.master.read_bytes()) == work["master_sha256"] and
         (state.get("active_step") or {}).get("step") == step,
         "C07_P3_ORIGINAL_AUDIT_STATE_DRIFT")
    artifacts = _registered_artifacts(
        rows, state, step, source_loader, work)
    exports = [a for a in artifacts if a[0] == "NATIVE_EXPORT"]
    need(len(exports) <= 1, "C07_P3_MULTIPLE_NATIVE_EXPORTS")
    parsed = None
    if exports:
        need(exports[0][1].lower().endswith(".glb"),
             "C07_P3_NATIVE_EXPORT_FORMAT")
        parsed = geometry(exports[0][3])
    totals = {name: sum(row[name] for row in parsed or [])
              for name in ("triangles", "duplicate_coordinate_vertices",
                           "duplicate_geometric_faces", "degenerate_triangles",
                           "boundary_edges", "nonmanifold_edges",
                           "opposed_face_normals")}
    normal_ok = bool(parsed and
                     all(row["declared_vertex_normals"] for row in parsed))
    checks = {
        IDS[0]: {"all_original_mesh_primitives_scanned": parsed is not None,
                 "nonmanifold_edge_count_zero": bool(parsed and
                                                    totals["nonmanifold_edges"] == 0)},
        IDS[1]: {"no_duplicate_geometric_faces": bool(parsed and
                                                      totals["duplicate_geometric_faces"] == 0),
                 "no_exact_duplicate_coordinate_vertices": bool(parsed and
                                                      totals["duplicate_coordinate_vertices"] == 0)},
        IDS[2]: {"all_triangle_areas_recomputed": parsed is not None,
                 "no_degenerate_original_triangles": bool(parsed and
                                                      totals["degenerate_triangles"] == 0)},
        IDS[3]: {"all_primitives_have_vertex_normals": normal_ok,
                 "no_face_normal_opposition": bool(normal_ok and
                                                   totals["opposed_face_normals"] == 0)},
    }
    result = {}
    for rid, measured in checks.items():
        result[rid] = {
            "requirement_sha256": inventory["rules"][rid]["requirement_sha256"],
            "source_sha256": inventory["rules"][rid]["source_sha256"],
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
        "schema": SCHEMA, "source_rule_count": 4, "rules": result,
        "original_mesh_metrics": parsed, "totals": totals,
        "original_audit_sha256": audit_sha, "original_audit_tail": tail,
        "attempt_id": work["attempt_id"],
        "operation_sha256": work["operation_sha256"],
        "machine_positive_obligations": sum(
            v["machine_scope"] == "OBSERVED_SCOPE_PASS" for v in result.values()),
        "full_rule_semantic_passes": 0, "individual_mg0_passes": 0,
        "advancement_authorized": False,
    }
