"""C07 P4 M-124/125/127/128/129/130: real original PNG pixel oracles.

Decodes registered embedded RGBA PNG pixels (not a filename, QA label or
producer PASS) and compares them with SHA-pinned pre-D limits. Pixel variation
and lighting response are machine facts, not aesthetic realism, RAGE shader
compatibility, individual MG0 or owner acceptance.
"""
import hashlib
import math
import struct
import zlib

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p5_budget_semantics import _glb_parts, _json
from c07_a10_c10_original_evidence import original_image
from c07_p345_forty_native_evidence import TEXT, PHASE_INDEX

NUMBERS = (124,125,127,128,129,130)
IDS = tuple("AAA-200-M-%03d" % n for n in NUMBERS)
SCHEMA = "gg-c07-p4-six-original-pixel-oracles-v1"

class OriginalPixelBlocked(ValueError):
    pass

def need(ok, why):
    if not ok:
        raise OriginalPixelBlocked(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def finite(x):
    return type(x) in (int,float) and math.isfinite(x)

def _paeth(a,b,c):
    p = a+b-c
    da,db,dc = abs(p-a),abs(p-b),abs(p-c)
    return a if da <= db and da <= dc else b if db <= dc else c

def rgba(raw):
    """Reconstruct real PNG filter bytes; strict RGBA8 only, bounded size."""
    if original_image(raw) is None:
        return None
    w,h,depth,color,compression,filter_,interlace = struct.unpack_from(
        ">IIBBBBB", raw, 16)
    if (depth,color,compression,filter_,interlace) != (8,6,0,0,0):
        return None
    if w*h > 4_000_000:
        return None
    chunks = []
    off = 8
    while off+12 <= len(raw):
        size = struct.unpack_from(">I",raw,off)[0]
        typ = raw[off+4:off+8]
        if typ == b"IDAT":
            chunks.append(raw[off+8:off+8+size])
        off += size+12
        if typ == b"IEND":
            break
    expected = h*(1+4*w)
    try:
        dec = zlib.decompressobj()
        stream = dec.decompress(b"".join(chunks), expected+1)
        stream += dec.flush()
    except (ValueError, zlib.error, OverflowError):
        return None
    if len(stream) != expected or not dec.eof or dec.unused_data:
        return None
    stride = 4*w
    rows = []
    prev = bytearray(stride)
    off = 0
    for _ in range(h):
        mode = stream[off]
        cur = bytearray(stream[off+1:off+1+stride])
        off += 1+stride
        for j in range(stride):
            a = cur[j-4] if j >= 4 else 0
            b = prev[j]
            c = prev[j-4] if j >= 4 else 0
            predictor = (0 if mode == 0 else a if mode == 1 else b
                         if mode == 2 else (a+b)//2 if mode == 3
                         else _paeth(a,b,c))
            cur[j] = (cur[j]+predictor) & 255
        rows.append(bytes(cur))
        prev = cur
    colors = [tuple(row[j:j+4]) for row in rows for j in range(0,stride,4)]
    lumas = [(54*r+183*g+19*b)/256 for r,g,b,_ in colors]
    mean = sum(lumas)/len(lumas)
    variance = sum((x-mean)**2 for x in lumas)/len(lumas)
    quadrants = []
    for y0,y1 in ((0,h//2),(h//2,h)):
        for x0,x1 in ((0,w//2),(w//2,w)):
            samples = [lumas[y*w+x] for y in range(y0,y1)
                       for x in range(x0,x1)]
            quadrants.append(sum(samples)/len(samples) if samples else None)
    return {"width":w,"height":h,"mean":mean,"variance":variance,
            "unique_rgb":len(set(x[:3] for x in colors)),
            "unique_rgba":len(set(colors)),
            "quadrants":quadrants,"sha256":sha(raw),
            "pixel_sha256":sha(b"".join(rows)),
            "compressed_bytes":len(raw)}

def _embedded(doc, binary):
    out = []
    views = doc.get("bufferViews", [])
    for img in doc.get("images", []):
        if type(img) is not dict or img.get("mimeType") != "image/png":
            return None
        idx = img.get("bufferView")
        if type(idx) is not int or not 0 <= idx < len(views):
            return None
        view = views[idx]
        off, length = view.get("byteOffset",0), view.get("byteLength")
        if (type(off) is not int or type(length) is not int or
                off < 0 or length <= 0 or off+length > len(binary)):
            return None
        result = rgba(binary[off:off+length])
        if result is None:
            return None
        out.append(result)
    return out if out else None

def inspect(inventory, plan, controller, asset, step, work, *, source_loader):
    need(type(inventory) is dict and inventory.get("rule_count") == 763
         and inventory.get("schema") == "gg-effective-family-inventory-v1"
         and type(plan) is dict and type(work) is dict
         and plan.get("phase") in PHASE_INDEX
         and PHASE_INDEX[plan["phase"]] >= 4
         and work.get("phase") == plan["phase"] and callable(source_loader),
         "C07_P4_PIXEL_CONTEXT")
    catalog = inventory.get("source_digests", {}).get("aaa_catalog")
    need(type(catalog) is str and len(catalog) == 64
         and all(c in "0123456789abcdef" for c in catalog),
         "C07_P4_PIXEL_CATALOG")
    for n, rid in zip(NUMBERS, IDS):
        literal, phase = TEXT[str(n)]
        row = inventory["rules"].get(rid, {})
        need(phase == "P4" and row.get("family") == "AAA-200"
             and row.get("catalog_number") == n
             and row.get("catalog_section") == "M"
             and row.get("catalog_phase") == phase
             and row.get("requirement") == literal
             and row.get("requirement_sha256") == sha(literal.encode())
             and row.get("source_sha256") == catalog,
             "C07_P4_PIXEL_LITERAL_CHANGED:" + rid)
    audit,tail,state,audit_sha = _original_attempt(
        inventory, plan, controller, asset, step, work)
    need(state.get("last_audit_hash") == tail
         and sha(controller.master.read_bytes()) == work["master_sha256"]
         and (state.get("active_step") or {}).get("step") == step,
         "C07_P4_PIXEL_AUDIT_DRIFT")
    artifacts = _registered_artifacts(
        audit, state, step, source_loader, work)
    roles = {"NATIVE_EXPORT", "P4_TEXTURE_POLICY",
             "P4_VIEW_NEUTRAL", "P4_VIEW_DIRECT", "P4_VIEW_SHADOW"}
    found = {}
    for role,path,digest,raw in artifacts:
        if role in roles:
            need(role not in found, "C07_P4_DUPLICATE_ROLE:" + role)
            found[role] = (path,digest,raw)
    contract = plan.get("p345_evidence_contract", {})
    pins = contract.get("original_artifact_sha256", {}) if type(contract) is dict else {}
    if type(pins) is not dict:
        pins = {}
    def original(role,ext):
        row = found.get(role)
        return (row[2] if row and row[0].lower().endswith(ext)
                and pins.get(role) == row[1] and sha(row[2]) == row[1]
                else None)
    policy_raw = original("P4_TEXTURE_POLICY",".json")
    policy = _json(policy_raw) if policy_raw is not None else {}
    native_raw = original("NATIVE_EXPORT",".glb")
    doc,binary = _glb_parts(native_raw) if native_raw is not None else ({},b"")
    images = _embedded(doc,binary) if native_raw is not None else None
    view_roles = ("P4_VIEW_NEUTRAL","P4_VIEW_DIRECT","P4_VIEW_SHADOW")
    views = [rgba(original(role,".png")) if original(role,".png") is not None
             else None for role in view_roles]
    distinct_min = policy.get("min_distinct_rgb")
    variance_min = policy.get("min_luminance_variance")
    variance_max = policy.get("max_luminance_variance")
    min_size = policy.get("min_texture_side_px")
    max_size = policy.get("max_texture_side_px")
    max_bytes = policy.get("max_png_bytes")
    min_quadrant_delta = policy.get("min_quadrant_luma_delta")
    valid_variance = (finite(variance_min) and finite(variance_max)
                      and 0 <= variance_min < variance_max <= 65025)
    size_policy = (type(min_size) is int and type(max_size) is int
                   and 2 <= min_size <= max_size <= 8192
                   and type(max_bytes) is int and 64 <= max_bytes <= 32_000_000)
    variance_ok = bool(images and valid_variance and all(
        variance_min <= img["variance"] <= variance_max for img in images))
    distinct_ok = bool(images and type(distinct_min) is int
                       and 2 <= distinct_min <= 1000000 and
                       all(img["unique_rgb"] >= distinct_min for img in images))
    quadrant_ok = bool(images and finite(min_quadrant_delta)
                       and 0 < min_quadrant_delta <= 255
                       and all(all(x is not None for x in img["quadrants"])
                               and max(img["quadrants"])-min(img["quadrants"])
                               >= min_quadrant_delta for img in images))
    size_ok = bool(images and size_policy and all(
        min_size <= img["width"] <= max_size and
        min_size <= img["height"] <= max_size and
        img["compressed_bytes"] <= max_bytes for img in images))
    materials = doc.get("materials", [])
    allowed = policy.get("allowed_material_names")
    material_names = [m.get("name") for m in materials if type(m) is dict]
    material_ok = bool(
        materials and len(material_names) == len(materials)
        and all(type(name) is str and name.strip() for name in material_names)
        and type(allowed) is list and bool(allowed)
        and all(type(name) is str for name in allowed)
        and set(material_names) <= set(allowed))
    pbr_ok = bool(material_ok and all(
        type(m.get("pbrMetallicRoughness")) is dict
        and finite(m["pbrMetallicRoughness"].get("roughnessFactor"))
        and finite(m["pbrMetallicRoughness"].get("metallicFactor"))
        and 0 <= m["pbrMetallicRoughness"]["roughnessFactor"] <= 1
        and 0 <= m["pbrMetallicRoughness"]["metallicFactor"] <= 1
        for m in materials))
    light_views = bool(
        all(views) and len({v["sha256"] for v in views if v}) == 3
        and len({(v["width"],v["height"]) for v in views if v}) == 1)
    light_order = bool(light_views and
                       views[1]["mean"] > views[0]["mean"] > views[2]["mean"])
    checks = {
        124: {"actual_embedded_original_pixels_have_distinct_colors":
              distinct_ok,
              "original_pixel_luminance_variance_not_flat": variance_ok},
        125: {"actual_original_texture_quadrants_differ":
              quadrant_ok,
              "all_original_texture_variance_within_pre_d_range": variance_ok},
        127: {"actual_original_pixel_variation_not_outside_pre_d_range":
              variance_ok,
              "actual_original_color_diversity_measured": distinct_ok},
        128: {"original_embedded_png_bytes_and_dimensions_within_budget":
              size_ok,
              "all_original_embedded_images_independently_decoded":
              images is not None and len(images) == len(doc.get("images",[]))},
        129: {"original_exported_material_names_in_pre_d_shader_policy":
              material_ok,
              "actual_exported_pbr_factors_in_numeric_range": pbr_ok},
        130: {"three_original_lighting_views_decoded_at_equal_resolution":
              light_views,
              "original_direct_neutral_shadow_luminance_order_measured":
              light_order},
    }
    rules = {}
    for n,rid in zip(NUMBERS,IDS):
        measured = {k:bool(v) for k,v in checks[n].items()}
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
        "metrics": {"decoded_original_textures": len(images) if images else 0,
                    "mean_texture_variance":
                    (sum(im["variance"] for im in images)/len(images)
                     if images else None),
                    "neutral_direct_shadow_means":
                    [v["mean"] if v else None for v in views],
                    "material_names": material_names},
        "machine_positive_obligations": sum(
            v["machine_scope"] == "OBSERVED_SCOPE_PASS" for v in rules.values()),
        "full_rule_semantic_passes": 0, "individual_mg0_passes": 0,
        "advancement_authorized": False,
    }
