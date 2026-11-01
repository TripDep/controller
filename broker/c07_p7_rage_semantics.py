"""C07 P7 Q-161..170: original CodeWalker/Sollumz source-specific oracles.

Read exact Controller-registered XML/GLB/PNG/source bytes and pre-D SHA pins.
XML previews, a tool-labelled JSON trace, and screenshots are NOT native RAGE
validation, authenticated CodeWalker execution, FiveM gameplay, MG0 or owner
approval. In-game rule 170 deliberately cannot pass on self-reported logs.
"""
import hashlib
import math
import re
import xml.etree.ElementTree as ET

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p5_budget_semantics import _json, _glb_parts
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
    glb = _glb_parts(native_raw)[0] if native_raw is not None else {}
    pngs = [original("P7_VIEW_" + name, ".png")
            for name in ("FRONT", "SIDE", "TOP")]
    views = [original_image(raw) if raw is not None else None for raw in pngs]

    manifest_text = manifest.decode("utf-8", "replace") if manifest is not None else ""
    manifest_ok = bool(
        manifest is not None and len(manifest) < 200_000
        and re.search(r"(?m)^\s*fx_version\s*['\"][a-zA-Z0-9_-]+['\"]",
                      manifest_text)
        and re.search(r"(?m)^\s*game\s*['\"]gta5['\"]", manifest_text)
        and re.search(r"(?m)^\s*this_is_a_map\s*['\"]yes['\"]", manifest_text))
    manifest_ytyp = bool(re.search(r"['\"][^'\"]+\.ytyp['\"]", manifest_text))
    drawable_name = value(drawable, "Name").casefold() if drawable is not None else ""
    shader_items = [value(x, "Name").casefold()
                    for x in nodes(drawable, "Item")
                    if x in nodes(drawable, "Item") and
                    any(local(y.tag) == "shaders" for y in drawable.iter())]
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
    glb_attrs = [p.get("attributes", {}) for mesh in glb.get("meshes", [])
                 for p in mesh.get("primitives", [])] if type(glb) is dict else []
    attrs_valid = bool(glb_attrs and all(type(a) is dict and
                        {"POSITION", "NORMAL", "TEXCOORD_0"} <= set(a)
                        for a in glb_attrs))
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
    rules = {}
    for n, rid in zip(NUMBERS, IDS):
        measured = {k: bool(v) for k,v in checks[n].items()}
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
        "full_rule_semantic_passes": 0, "individual_mg0_passes": 0,
        "advancement_authorized": False,
    }
