"""C07 P7 Q-161..170: original CodeWalker/Sollumz source-specific oracles.

Read exact Controller-registered XML/GLB/PNG/source bytes and pre-D SHA pins.
XML previews, a tool-labelled JSON trace, and screenshots are NOT native RAGE
validation, authenticated CodeWalker execution, FiveM gameplay, MG0 or owner
approval. In-game rule 170 deliberately cannot pass on self-reported logs.
"""
import hashlib
import math
import re
import struct
from pathlib import PurePosixPath
import xml.etree.ElementTree as ET

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p5_budget_semantics import _json, _glb_parts
from c07_p3_geometry_semantics import _read_accessor
from c07_a10_c10_original_evidence import original_image
from c07_p678_forty_native_domain import TEXT, PHASES

NUMBERS = tuple(range(161, 171))
IDS = tuple("AAA-200-Q-%03d" % n for n in NUMBERS)
SCHEMA = "gg-c07-p7-ten-original-rage-preflight-oracles-v1"
HEX = re.compile(r"[a-f0-9]{64}\Z")

class OriginalRageBlocked(ValueError):
    pass

def need(ok, why):
    if not ok:
        raise OriginalRageBlocked(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def finite(x):
    return type(x) in (int, float) and math.isfinite(x)

def local(tag):
    return tag.rsplit("}", 1)[-1].lower() if type(tag) is str else ""

def nodes(root, tag):
    return [e for e in root.iter() if local(e.tag) == tag.lower()] if root is not None else []

def value(elem, tag):
    for x in elem.iter():
        if local(x.tag) == tag.lower():
            v = x.attrib.get("value", x.text)
            if type(v) is str and v.strip():
                return v.strip()
    return ""

def _xml(raw, root_name):
    if raw is None:
        return None
    need(type(raw) is bytes and len(raw) <= 4_000_000 and
         b"<!DOCTYPE" not in raw.upper() and
         b"<!ENTITY" not in raw.upper(),
         "C07_P7_UNSAFE_XML")
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError, UnicodeError):
        return None
    need(sum(1 for _ in root.iter()) <= 30000, "C07_P7_XML_TOO_MANY_NODES")
    return root if local(root.tag) == root_name.lower() else None

def _vec(element):
    if element is None:
        return None
    try:
        v = [float(element.attrib[k]) for k in ("x", "y", "z")]
    except (KeyError, ValueError, TypeError, OverflowError):
        return None
    return v if all(math.isfinite(x) and abs(x) <= 1_000_000 for x in v) else None

def _archetypes(root):
    out = {}
    for node in nodes(root, "Item"):
        if node.attrib.get("type") not in ("CBaseArchetypeDef",
                                           "CMloArchetypeDef"):
            continue
        name = value(node, "name")
        asset = value(node, "assetName")
        if not name or not asset or name.casefold() in out:
            return {}
        out[name.casefold()] = asset.casefold()
    return out

def _entities(root):
    out = []
    for node in nodes(root, "Item"):
        if node.attrib.get("type") != "CEntityDef":
            continue
        archetype = value(node, "archetypeName")
        positions = [e for e in node.iter() if local(e.tag) == "position"]
        xyz = _vec(positions[0]) if len(positions) == 1 else None
        if not archetype or xyz is None:
            return []
        out.append((archetype.casefold(), xyz))
    return out if len(out) == len(set((n, tuple(v)) for n,v in out)) else []

def _texture_names(root):
    out = []
    if root is None:
        return out
    for node in nodes(root, "Item"):
        name = value(node, "Name")
        if name:
            out.append(name.casefold())
    return out if len(out) == len(set(out)) else []

def native_collision_envelope(glb, binary, children):
    """Measure original GLB vertices against original CodeWalker YBN box bounds.

    A declared collision child alone is not proof of usable coverage. Require
    the union of actual original YBN Box bounds to enclose the native GLB local
    bounds. This remains static geometry preflight, not FiveM physics.
    """
    if not (type(glb) is dict and type(binary) is bytes and children):
        return False
    vertices = []
    try:
        for mesh in glb.get("meshes", []):
            for prim in mesh.get("primitives", []):
                positions = _read_accessor(
                    glb, binary, prim["attributes"]["POSITION"])
                if not positions or len(vertices)+len(positions) > 1_000_000:
                    return False
                vertices.extend(positions)
    except (KeyError, ValueError, TypeError, IndexError):
        return False
    if not vertices or any(len(v) != 3 or not all(finite(x) for x in v)
                           for v in vertices):
        return False
    lower = [min(v[k] for v in vertices) for k in range(3)]
    upper = [max(v[k] for v in vertices) for k in range(3)]
    boxes = []
    for child in children:
        if child.attrib.get("type") != "Box":
            continue
        mins = nodes(child, "Min")
        maxs = nodes(child, "Max")
        if len(mins) != 1 or len(maxs) != 1:
            return False
        low, high = _vec(mins[0]), _vec(maxs[0])
        if low is None or high is None or any(a >= b for a,b in zip(low,high)):
            return False
        boxes.append((low,high))
    if not boxes:
        return False
    # Every extreme point must lie within a real original collision bound.
    # Union-AABB alone would allow two disconnected boxes to claim coverage.
    for v in vertices:
        if not any(all(lo[k]-0.001 <= v[k] <= hi[k]+0.001 for k in range(3))
                   for lo,hi in boxes):
            return False
    return True


def inspect(inventory, plan, controller, asset, step, work, *, source_loader):
    need(type(inventory) is dict and inventory.get("rule_count") == 763
         and inventory.get("schema") == "gg-effective-family-inventory-v1"
         and type(plan) is dict and type(work) is dict
         and plan.get("phase") in PHASES and PHASES[plan["phase"]] >= 7
         and plan["phase"] == work.get("phase") and callable(source_loader),
         "C07_P7_ORIGINAL_CONTEXT")
    catalog = inventory.get("source_digests", {}).get("aaa_catalog")
    need(type(catalog) is str and HEX.fullmatch(catalog),
         "C07_P7_CATALOG_SOURCE")
    for n, rid in zip(NUMBERS, IDS):
        literal, phase = TEXT[str(n)]
        row = inventory["rules"].get(rid, {})
        need(phase == "P7" and row.get("family") == "AAA-200"
             and row.get("catalog_number") == n
             and row.get("catalog_section") == "Q"
             and row.get("catalog_phase") == phase
             and row.get("requirement") == literal
             and row.get("requirement_sha256") == sha(literal.encode())
             and row.get("source_sha256") == catalog,
             "C07_P7_LITERAL_SOURCE_CHANGED:" + rid)
    audit, tail, state, audit_sha = _original_attempt(
        inventory, plan, controller, asset, step, work)
    need(state.get("last_audit_hash") == tail
         and sha(controller.master.read_bytes()) == work["master_sha256"]
         and (state.get("active_step") or {}).get("step") == step,
         "C07_P7_ORIGINAL_AUDIT_DRIFT")
    records = _registered_artifacts(audit, state, step, source_loader, work)
    roles = {"P7_FXMANIFEST", "P7_YDR_XML", "P7_YTD_XML", "P7_YTYP_XML",
             "P7_YMAP_XML", "P7_YBN_XML", "P7_EXPORT_TRACE",
             "P7_CODEWALKER_REPORT", "P7_SHADER_POLICY", "P7_FIVEM_LOG",
             "P7_VIEW_FRONT", "P7_VIEW_SIDE", "P7_VIEW_TOP",
             "SOURCE_EDITABLE", "NATIVE_EXPORT"}
    found = {}
    for role, path, digest, raw in records:
        if role in roles:
            need(role not in found, "C07_P7_DUPLICATE_ORIGINAL_ROLE:" + role)
            found[role] = (path, digest, raw)
    contract = plan.get("p678_evidence_contract", {})
    pins = contract.get("original_artifact_sha256", {}) if type(contract) is dict else {}
    if type(pins) is not dict:
        pins = {}
    def original(role, extension):
        row = found.get(role)
        return (row[2] if row and row[0].lower().endswith(extension)
                and pins.get(role) == row[1] and sha(row[2]) == row[1]
                else None)
    manifest = original("P7_FXMANIFEST", ".lua")
    drawable = _xml(original("P7_YDR_XML", ".xml"), "Drawable")
    dictionary = _xml(original("P7_YTD_XML", ".xml"), "TextureDictionary")
    ytyp = _xml(original("P7_YTYP_XML", ".xml"), "CMapTypes")
    ymap = _xml(original("P7_YMAP_XML", ".xml"), "CMapData")
    ybn = _xml(original("P7_YBN_XML", ".xml"), "BoundsFile")
    trace_raw = original("P7_EXPORT_TRACE", ".json")
    trace = _json(trace_raw) if trace_raw is not None else {}
    cw_raw = original("P7_CODEWALKER_REPORT", ".json")
    cw = _json(cw_raw) if cw_raw is not None else {}
    policy_raw = original("P7_SHADER_POLICY", ".json")
    policy = _json(policy_raw) if policy_raw is not None else {}
    game_raw = original("P7_FIVEM_LOG", ".json")
    game = _json(game_raw) if game_raw is not None else {}
    editable = original("SOURCE_EDITABLE", ".blend")
    native_raw = original("NATIVE_EXPORT", ".glb")
    glb, glb_binary = _glb_parts(native_raw) if native_raw is not None else ({}, b"")
    pngs = [original("P7_VIEW_" + name, ".png")
            for name in ("FRONT", "SIDE", "TOP")]
    views = [original_image(raw) if raw is not None else None for raw in pngs]

    # A quoted .ytyp in a comment or unrelated Lua string is not a
    # loadable FiveM resource. Verify active files{} AND data_file declarations
    # from the exact SHA-pinned original manifest bytes.
    from c07_p7_manifest_source_semantics import parse as parse_fxmanifest
    parsed_manifest = parse_fxmanifest(manifest)
    manifest_ok = parsed_manifest["valid"]
    manifest_ytyp = parsed_manifest["valid"]
    ytyp_paths = list(parsed_manifest["ytyp_paths"])
    drawable_name = value(drawable, "Name").casefold() if drawable is not None else ""
    # Explicit shader nodes under ShaderGroup/Shaders, never generic mesh names.
    shaders = []
    for group in nodes(drawable, "Shaders"):
        shaders.extend(value(x, "Name").casefold() for x in list(group)
                       if local(x.tag) == "item")
    shaders = [s for s in shaders if s]
    texture_names = _texture_names(dictionary)
    referenced_textures = [e.text.strip().casefold()
                           for e in nodes(drawable, "TextureName")
                           if type(e.text) is str and e.text.strip()]
    archetypes = _archetypes(ytyp)
    entities = _entities(ymap)
    collision_children = [
        x for group in nodes(ybn, "Children") for x in list(group)
        if local(x.tag) == "item"]
    source_matches_archetype = bool(drawable_name and archetypes and
                                   drawable_name in set(archetypes.values()))
    mapped = bool(entities and archetypes and
                  all(name in archetypes for name, _ in entities))
    collision_declared = bool(collision_children and
                              all(x.attrib.get("type") for x in collision_children))
    addon_version = trace.get("addon_version")
    addon_claim = (trace.get("addon") == "Sollumz"
                   and type(addon_version) is str
                   and re.fullmatch(r"[0-9]+\.[0-9]+(\.[0-9]+)?", addon_version))
    export_trace_bound = bool(addon_claim and editable and native_raw and
                              trace.get("source_sha256") == sha(editable)
                              and trace.get("export_sha256") == sha(native_raw)
                              and trace.get("asset") == asset)
    def uv_valid(attributes):
        if type(attributes) is not dict or not (
                {"POSITION", "NORMAL", "TEXCOORD_0"} <= set(attributes)):
            return False
        try:
            positions = _read_accessor(glb, glb_binary, attributes["POSITION"])
            normals = _read_accessor(glb, glb_binary, attributes["NORMAL"])
            idx = attributes["TEXCOORD_0"]
            accessors, views = glb["accessors"], glb["bufferViews"]
            if (type(idx) is not int or not 0 <= idx < len(accessors)
                    or len(positions) != len(normals)):
                return False
            accessor = accessors[idx]
            if (accessor.get("type") != "VEC2"
                    or accessor.get("componentType") != 5126
                    or accessor.get("count") != len(positions)
                    or "sparse" in accessor):
                return False
            view_idx = accessor.get("bufferView")
            if type(view_idx) is not int or not 0 <= view_idx < len(views):
                return False
            view = views[view_idx]
            off = view.get("byteOffset", 0)
            local_off = accessor.get("byteOffset", 0)
            stride = view.get("byteStride", 8)
            size = view.get("byteLength")
            bounds_ok = (view.get("buffer") == 0
                         and all(type(x) is int and x >= 0
                                 for x in (off, local_off, stride, size))
                         and stride >= 8
                         and off + size <= len(glb_binary)
                         and local_off + (len(positions)-1)*stride + 8 <= size)
            if not bounds_ok:
                return False
            for i in range(len(positions)):
                u,v = struct.unpack_from("<ff", glb_binary,
                                         off+local_off+i*stride)
                if not (math.isfinite(u) and math.isfinite(v)):
                    return False
            return True
        except (ValueError, KeyError, IndexError, TypeError):
            return False
    glb_attrs = [p.get("attributes", {}) for mesh in glb.get("meshes", [])
                 for p in mesh.get("primitives", [])] if type(glb) is dict else []
    attrs_valid = bool(glb_attrs and all(uv_valid(a) for a in glb_attrs))
    allowed = policy.get("allowed_shader_names")
    shader_policy = (type(allowed) is list and bool(allowed)
                     and len(allowed) <= 128
                     and all(type(s) is str and s.strip() for s in allowed)
                     and len(allowed) == len(set(allowed)))
    shaders_declared = bool(shaders and shader_policy and
                            set(shaders) <= {s.casefold() for s in allowed})
    reported = cw.get("entity_positions")
    report_matches = bool(
        mapped and type(reported) is list and len(reported) == len(entities)
        and all(type(x) is dict and type(x.get("archetype")) is str
                and type(x.get("xyz")) is list and len(x["xyz"]) == 3
                and all(finite(v) for v in x["xyz"]) for x in reported)
        and sorted((x["archetype"].casefold(), tuple(x["xyz"]))
                   for x in reported) == sorted((n, tuple(xyz)) for n,xyz in entities))
    near, far = cw.get("lod_near_m"), cw.get("lod_far_m")
    lod_report = bool(finite(near) and finite(far) and 0 <= near < far <= 100000)
    game_samples = game.get("frame_ms_samples")
    game_structural = bool(
        game.get("engine") == "FiveM" and game.get("asset") == asset
        and type(game_samples) is list and len(game_samples) >= 10
        and len(game_samples) <= 2000
        and all(finite(x) and 0 < x < 10000 for x in game_samples))
    checks = {
        161: {"actual_resource_manifest_declares_gta5_map": manifest_ok,
              "source_manifest_references_archetype_dictionary": manifest_ytyp},
        162: {"original_codewalker_drawable_name_parsed": bool(drawable_name),
              "drawable_is_cross_referenced_by_original_archetype": source_matches_archetype},
        163: {"original_texture_dictionary_has_distinct_named_entries":
              bool(texture_names),
              "drawable_referenced_texture_names_resolve_in_dictionary":
              bool(referenced_textures and texture_names and
                   set(referenced_textures) <= set(texture_names))},
        164: {"original_archetype_names_and_asset_names_parsed": bool(archetypes),
              "archetype_asset_matches_actual_drawable_source": source_matches_archetype},
        165: {"original_ymap_entity_positions_parsed": bool(entities),
              "all_placed_archetypes_resolve_in_original_ytyp": mapped},
        166: {"original_ybn_bound_children_structurally_parsed": collision_declared,
              "original_ytyp_and_ybn_source_both_present":
              bool(archetypes and collision_children)},
        167: {"registered_blend_and_glb_bytes_match_original_sollumz_trace":
              export_trace_bound,
              "independent_sollumz_execution_provenance_confirmed": False},
        168: {"original_export_vertex_attributes_have_position_normal_uv":
              attrs_valid,
              "original_drawable_shader_names_match_pre_d_allowlist":
              shaders_declared},
        169: {"codewalker_report_entity_positions_match_original_ymap":
              report_matches,
              "source_lod_distances_and_three_original_views_recorded":
              lod_report and all(views) and
              len({v["sha256"] for v in views if v}) == 3},
        170: {"source_fivem_log_contains_numeric_samples": game_structural,
              "independent_in_game_execution_and_owner_provenance": False},
    }
    # Independent *additional* semantic obligations, not a third name for
    # either existing presence check. Each reads cross-file original data;
    # no source-labelled Sollumz/FiveM log can attest external execution.
    # Original bytes and pre-D hashes have already been re-opened above.
    from visual_content_metrics import decode_grid, VisualContentBlocked
    def pixel_digest(raw):
        if raw is None:
            return None
        try:
            width, height, pixels = decode_grid(raw, step=1)
            if width < 2 or height < 2 or not pixels:
                return None
            return sha(bytes(c for pixel in pixels for c in pixel))
        except (ValueError, TypeError, VisualContentBlocked):
            return None
    pixel_digests = [pixel_digest(raw) for raw in pngs]
    def normalized_normals():
        if not glb_attrs:
            return False
        try:
            for attrs in glb_attrs:
                if not uv_valid(attrs):
                    return False
                normal = _read_accessor(glb, glb_binary, attrs["NORMAL"])
                if not normal or any(
                    len(v) != 3 or not all(finite(x) for x in v) or
                    not (0.99 <= math.sqrt(sum(x*x for x in v)) <= 1.01)
                    for v in normal
                ):
                    return False
            return True
        except (KeyError, IndexError, TypeError, ValueError):
            return False
    semantic = {
        161: ("manifest_ytyp_entries_unique_and_confined_to_stream",
              bool(manifest_ok and manifest_ytyp and
                   len(ytyp_paths) == len(set(ytyp_paths)) and
                   all(path.startswith("stream/") for path in ytyp_paths))),
        162: ("drawable_bound_to_exactly_one_original_archetype",
              bool(manifest_ok and drawable_name and sum(
                  v == drawable_name for v in archetypes.values()) == 1)),
        163: ("every_original_drawable_texture_resolves_once",
              bool(manifest_ok and referenced_textures and texture_names and
                   len(referenced_textures) == len(set(referenced_textures)) and
                   set(referenced_textures) <= set(texture_names))),
        164: ("all_placed_original_archetypes_have_drawable_binding",
              bool(manifest_ok and mapped and all(archetypes.get(name) == drawable_name
                                  for name, _ in entities))),
        165: ("all_original_map_positions_match_current_codewalker_source",
              bool(manifest_ok and report_matches and entities and
                   all(all(finite(c) for c in xyz) for _, xyz in entities))),
        166: ("original_collision_children_have_supported_bound_types_and_native_coverage",
              bool(manifest_ok and collision_declared and all(
                  x.attrib.get("type") in (
                      "Box", "Sphere", "Capsule", "Geometry",
                      "GeometryBVH", "Composite")
                  for x in collision_children)
                  and native_collision_envelope(glb, glb_binary,
                                                collision_children))),
        167: ("independent_sollumz_execution_provenance", False),
        168: ("actual_native_vertex_normals_normalized_and_uv_finite",
              bool(attrs_valid and shaders_declared and normalized_normals())),
        169: ("three_original_views_have_distinct_decoded_pixels",
              bool(manifest_ok and report_matches and lod_report and
                   all(pixel_digests) and
                   len(set(pixel_digests)) == len(pixel_digests))),
        170: ("independent_fivem_engine_execution_provenance", False),
    }
    need(set(semantic) == set(NUMBERS) and
         len({k for k, _ in semantic.values()}) == 10 and
         all(type(v) is bool for _, v in semantic.values()),
         "C07_P7_TEN_DISTINCT_CROSS_SOURCE_SEMANTICS")
    rules = {}
    for n, rid in zip(NUMBERS, IDS):
        measured = {k: bool(v) for k,v in checks[n].items()}
        rules[rid] = {
            "requirement_sha256": inventory["rules"][rid]["requirement_sha256"],
            "source_sha256": catalog,
            "exact_attempt_id": work["attempt_id"],
            "operation_sha256": work["operation_sha256"],
            "original_machine_checks": measured,
            "original_cross_source_semantic": {
                semantic[n][0]: semantic[n][1]},
            "machine_scope": "OBSERVED_SCOPE_PASS" if all(measured.values())
                             else "UNKNOWN_OR_DEFECT",
            "full_rule_semantics": "UNKNOWN", "individual_mg0": "UNKNOWN",
            "owner_acceptance": "UNKNOWN", "advancement_authorized": False,
        }
    return {
        "schema": SCHEMA, "source_rule_count": len(IDS), "rules": rules,
        "original_audit_sha256": audit_sha, "original_audit_tail": tail,
        "attempt_id": work["attempt_id"], "operation_sha256": work["operation_sha256"],
        "metrics": {"archetypes": len(archetypes), "entities": len(entities),
                    "drawable_name": drawable_name or None,
                    "texture_names": len(texture_names),
                    "collision_children": len(collision_children),
                    "shader_names": len(shaders),
                    "original_views": sum(bool(v) for v in views),
                    "unattested_sollumz_trace": bool(trace_raw),
                    "unattested_fivem_log": bool(game_raw)},
        "machine_positive_obligations": sum(
            v["machine_scope"] == "OBSERVED_SCOPE_PASS" for v in rules.values()),
        "original_cross_source_positive_obligations": sum(
            value for _, value in semantic.values()),
        "full_rule_semantic_passes": 0, "individual_mg0_passes": 0,
        "advancement_authorized": False,
    }
