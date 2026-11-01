"""C07 P4 macro: seven literal material rules on original registered asset bytes.

One shared immutable read of the original Controller operation, GLB embedded
images, and pre-D SHA-pinned material contract. Each rule has its own source
predicates; undecidable RAGE/renderer claims remain candidate UNKNOWN.
Positive scoped evidence never implies independent MG0, owner or FiveM PASS.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p345_forty_native_evidence import inspect as inspect_p345, binary_json
from c07_p5_budget_semantics import _glb_parts
from c07_p4_texture_semantics import rgba, _embedded

SECTION = 'M'
NEW = (121, 122, 125, 126, 127, 129, 130)
RULES = frozenset('AAA-200-M-%03d' % n for n in NEW)
# Only the five byte-decidable source-scoped materials predicates can be
# positively enrolled. Shader acceptance and rendered-light provenance cannot.
DECIDABLE = frozenset('AAA-200-M-%03d' % n
                      for n in (121, 122, 125, 126, 127))
CRITERIA = {
121: ('pre_d_original_physical_material_classification_sha_pinned',
      'every_actual_exported_primitive_material_has_canonical_class',
      'all_actual_original_roughness_and_metallic_values_in_physical_class_ranges'),
122: ('pre_d_light_response_and_pbr_factor_contract_sha_pinned',
      'all_original_exported_material_roughness_and_reflectance_measured',
      'real_original_direct_neutral_shadow_pixels_follow_source_bounds'),
125: ('pre_d_original_surface_variation_limits_sha_pinned',
      'actual_original_embedded_texture_quadrants_recomputed',
      'all_real_texture_variation_exceeds_original_local_contrast_limit'),
126: ('pre_d_original_weathering_reference_and_limits_sha_pinned',
      'original_texture_and_reference_pixel_distributions_independently_reopened',
      'real_original_texture_weathering_mean_and_local_spread_within_limits'),
127: ('pre_d_original_pixel_diversity_and_variance_limits_sha_pinned',
      'all_original_embedded_rgba_channels_recomputed_from_png_bytes',
      'real_original_colors_and_variance_within_pre_d_material_ranges'),
129: ('original_pre_d_target_rage_shader_and_native_export_source_sha_pinned',
      'original_native_rage_shader_descriptors_independently_parsed',
      'original_shaders_vertex_attributes_and_texture_channels_compatible'),
130: ('pre_d_original_multi_light_material_response_policy_sha_pinned',
      'actual_registered_neutral_direct_shadow_pixel_buffers_recomputed',
      'trusted_independent_renderer_provenance_and_real_material_response_verified'),
}

class MaterialMacroBlocked(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise MaterialMacroBlocked(reason)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def numeric(v):
    return type(v) in (int, float) and math.isfinite(v)

def bound(v, low, high):
    return numeric(v) and low <= v <= high

def band(v):
    return (type(v) is list and len(v)==2 and all(numeric(x) for x in v)
            and 0 <= v[0] <= v[1] <= 1)

def rgb_mean(p):
    return p['mean'] if type(p) is dict else None

def quartile(p):
    if not p or any(x is None for x in p['quadrants']):
        return None
    return max(p['quadrants'])-min(p['quadrants'])

def inspect(source_context, rule_id):
    require(rule_id in RULES and type(source_context) is dict and
            set(source_context) == {'inventory', 'plan', 'controller',
                                    'asset', 'step', 'work', 'source_loader'},
            'C07_P4_MACRO_ORIGINAL_CONTEXT_REQUIRED')
    inv, plan, controller, asset, step, work, loader = (
        source_context[k] for k in ('inventory', 'plan', 'controller',
                                   'asset', 'step', 'work', 'source_loader'))
    require(plan.get('phase') in ('P4', 'P5', 'P6', 'P7', 'P8',
                                 'VERIFY', 'G2', 'G3', 'G4', 'DELIVERY'),
            'C07_P4_MACRO_PHASE_REQUIRED')
    inspect_p345(inv, plan, controller, asset, step, work, source_loader=loader)
    rows, tail, state, audit_sha = _original_attempt(
        inv, plan, controller, asset, step, work)
    require(sha(controller.master.read_bytes()) == work['master_sha256']
            and state.get('last_audit_hash') == tail
            and (state.get('active_step') or {}).get('step') == step,
            'C07_P4_MACRO_CURRENT_AUDIT_DRIFT')
    contract = plan.get('p345_evidence_contract', {})
    pins = contract.get('original_artifact_sha256', {}) if type(contract) is dict else {}
    require(type(pins) is dict, 'C07_P4_MACRO_PRE_D_ORIGINAL_PINS')
    found = {}
    for role, path, digest, raw in _registered_artifacts(
            rows, state, step, loader, work):
        require(role not in found, 'C07_P4_MACRO_DUPLICATE_ROLE')
        found[role] = (path, digest, raw)
    def original(role, ext):
        row = found.get(role)
        return (row[2] if (row and row[0].lower().endswith(ext)
                          and pins.get(role) == row[1]
                          and sha(row[2]) == row[1]) else None)
    raw_contract = original('P4_MATERIAL_CONFORMANCE', '.json')
    raw_glb = original('NATIVE_EXPORT', '.glb')
    policy = binary_json(raw_contract) if raw_contract is not None else {}
    doc, binary = _glb_parts(raw_glb) if raw_glb is not None else ({}, b'')
    actual_images = _embedded(doc, binary) if raw_glb is not None else None
    materials = doc.get('materials', [])
    meshes = doc.get('meshes', [])
    primitive_mats = []
    for mesh in meshes if type(meshes) is list else ():
        if type(mesh) is not dict:
            continue
        for prim in mesh.get('primitives', []):
            if type(prim) is dict:
                primitive_mats.append(prim.get('material'))
    mapped = bool(type(materials) is list and materials and
                  primitive_mats and
                  all(type(x) is int and 0<=x<len(materials)
                      for x in primitive_mats) and
                  all(type(mat) is dict and
                      type(mat.get('name')) is str and mat['name'].strip()
                      for mat in materials))
    classes = policy.get('physical_material_classes')
    classes_valid = bool(type(classes) is dict and classes and all(
        type(name) is str and type(rule) is dict and
        band(rule.get('roughness')) and band(rule.get('metallic'))
        for name,rule in classes.items()))
    name_classes = policy.get('material_to_class')
    classification = bool(classes_valid and mapped and type(name_classes) is dict
                          and set(m['name'] for m in materials) == set(name_classes)
                          and all(name_classes[n] in classes for n in name_classes))
    pbr = bool(mapped and all(
        type(m.get('pbrMetallicRoughness')) is dict and
        bound(m['pbrMetallicRoughness'].get('roughnessFactor'),0,1) and
        bound(m['pbrMetallicRoughness'].get('metallicFactor'),0,1)
        for m in materials))
    pbr_match = bool(classification and pbr and all(
        classes[name_classes[m['name']]]['roughness'][0] <=
            m['pbrMetallicRoughness']['roughnessFactor'] <=
            classes[name_classes[m['name']]]['roughness'][1] and
        classes[name_classes[m['name']]]['metallic'][0] <=
            m['pbrMetallicRoughness']['metallicFactor'] <=
            classes[name_classes[m['name']]]['metallic'][1]
        for m in materials))

    variation = policy.get('surface_variation', {})
    var_policy = bool(type(variation) is dict and
        type(variation.get('min_distinct_rgb')) is int and
        2<=variation['min_distinct_rgb']<=1000000 and
        bound(variation.get('min_quadrant_luma_delta'),1,255) and
        numeric(variation.get('min_variance')) and
        numeric(variation.get('max_variance')) and
        0<=variation['min_variance']<variation['max_variance']<=65025)
    pixels = bool(actual_images and
                  len(actual_images)==len(doc.get('images', [])) and
                  all(im['width']>=4 and im['height']>=4 for im in actual_images))
    local = bool(pixels and all(quartile(im) is not None for im in actual_images))
    contrast = bool(var_policy and local and all(
        quartile(im)>=variation['min_quadrant_luma_delta']
        for im in actual_images))
    variance = bool(var_policy and pixels and all(
        variation['min_variance'] <= im['variance'] <=
            variation['max_variance'] and
        im['unique_rgb'] >= variation['min_distinct_rgb']
        for im in actual_images))

    light_policy = policy.get('light_response', {})
    lp = bool(type(light_policy) is dict and
        bound(light_policy.get('min_direct_neutral_delta'),1,254) and
        bound(light_policy.get('min_neutral_shadow_delta'),1,254))
    raw_views = [original(r,'.png') for r in
                 ('P4_VIEW_NEUTRAL','P4_VIEW_DIRECT','P4_VIEW_SHADOW')]
    views = [rgba(v) if v is not None else None for v in raw_views]
    visual = bool(all(views) and len({v['sha256'] for v in views})==3 and
                  len({(v['width'],v['height']) for v in views})==1)
    luminance = bool(lp and visual and
        views[1]['mean']-views[0]['mean'] >=
            light_policy['min_direct_neutral_delta'] and
        views[0]['mean']-views[2]['mean'] >=
            light_policy['min_neutral_shadow_delta'])

    weather = policy.get('weathering', {})
    wp = bool(type(weather) is dict and
        bound(weather.get('max_reference_mean_delta'),0,255) and
        bound(weather.get('min_texture_local_delta'),1,255))
    raw_ref = original('P4_WEATHERING_REFERENCE','.png')
    reference = rgba(raw_ref) if raw_ref is not None else None
    comparable = bool(reference and pixels and
        all((x['width'],x['height']) ==
            (reference['width'],reference['height']) for x in actual_images))
    spread = bool(wp and comparable and all(
        abs(im['mean']-reference['mean'])<=
            weather['max_reference_mean_delta'] and
        quartile(im)>=weather['min_texture_local_delta'] and
        im['pixel_sha256']!=reference['pixel_sha256']
        for im in actual_images))

    names = {
        121: (bool(raw_contract and raw_glb and classification),
              classification, pbr_match),
        122: (bool(raw_contract and raw_glb and lp and all(raw_views)),
              pbr and classification, luminance),
        125: (bool(raw_contract and raw_glb and var_policy),
              local, contrast),
        126: (bool(raw_contract and raw_glb and raw_ref and wp),
              comparable, spread),
        127: (bool(raw_contract and raw_glb and var_policy),
              pixels, variance),
        # This source reader deliberately cannot certify RAGE shader support
        # from glTF PBR material labels or producer-generated QA JSON.
        129: (bool(raw_contract and raw_glb and
                   type(policy.get('rage_shader_target')) is str),
              False, False),
        # Source PNGs show luminance differences, not trusted evidence of
        # the renderer/light rig used. Independent provenance is required.
        130: (bool(raw_contract and raw_glb and lp),
              visual, False),
    }
    num=int(rule_id.rsplit('-',1)[1])
    checks=dict(zip(CRITERIA[num],(bool(v) for v in names[num])))
    require(len(checks)==3 and all(type(v) is bool for v in checks.values()),
            'C07_P4_MACRO_DISTINCT_RULE_CHECKS')
    complete=bool(raw_contract and raw_glb and doc and mapped and
                  num in (121,122,125,126,127))
    return {
        'rule_id':rule_id,
        'checks':checks, 'evidence_complete':complete,
        'original_audit_sha256':audit_sha,
        'original_audit_tail':tail,
        'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'individual_mg0':'UNKNOWN','owner_acceptance':'UNKNOWN',
        'runtime_fivem':'UNKNOWN','advancement_authorized':False,
    }
