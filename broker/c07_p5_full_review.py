"""Original-byte positive P5 reviews for distance/importance LOD and material cost.

These are conservative source-decidable contracts, not engine profiling or
owner signoff. All originals are reloaded from the current Controller attempt.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p5_budget_semantics import inspect as budget_inspect, _json, _glb_parts
from c07_p6_collision_semantics import _triangles

RULES = frozenset(('AAA-200-O-144', 'AAA-200-O-146'))
CRITERIA = {
    'AAA-200-O-144': (
        'pre_d_importance_specific_lod_distance_policy_authenticated',
        'original_native_and_lod_meshes_measured_and_spatially_coherent',
        'real_lod_reduction_and_switch_distances_match_importance_policy'),
    'AAA-200-O-146': (
        'original_baseline_and_material_reduction_policy_sha_pinned',
        'original_before_after_material_bindings_independently_counted',
        'measured_material_binding_reduction_meets_pre_d_target'),
}
IMPORTANCE = ('hero', 'primary', 'secondary', 'background')

class P5FullReviewBlocked(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise P5FullReviewBlocked(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def positive(v):
    return type(v) in (int, float) and math.isfinite(v) and v > 0

def bounds(triangles):
    points = [p for tri in triangles for p in tri]
    require(bool(points), 'C07_P5_FULL_EMPTY_TRIANGLES')
    return tuple((min(p[k] for p in points), max(p[k] for p in points))
                 for k in range(3))

def material_bindings(raw):
    """Count actual material slots used by original triangle primitives."""
    doc, _ = _glb_parts(raw)
    materials = doc.get('materials')
    require(type(materials) is list and bool(materials),
            'C07_P5_FULL_MATERIAL_TABLE_REQUIRED')
    used = []
    for mesh in doc.get('meshes', ()):
        require(type(mesh) is dict and type(mesh.get('primitives')) is list,
                'C07_P5_FULL_MESH_SCHEMA')
        for primitive in mesh['primitives']:
            require(type(primitive) is dict and
                    type(primitive.get('material')) is int and
                    0 <= primitive['material'] < len(materials),
                    'C07_P5_FULL_MATERIAL_BINDING_REQUIRED')
            used.append(primitive['material'])
    require(bool(used), 'C07_P5_FULL_MATERIAL_PRIMITIVES_REQUIRED')
    return len(set(used))

def inspect(source_context, rule_id):
    require(rule_id in RULES and type(source_context) is dict,
            'C07_P5_FULL_RULE_NOT_REVIEWED')
    inv = source_context['inventory']
    plan = source_context['plan']
    controller = source_context['controller']
    asset = source_context['asset']
    step = source_context['step']
    work = source_context['work']
    loader = source_context['source_loader']
    # Existing source-domain reader independently authenticates all P5
    # canonical literals, the active Controller hash-chain and current work.
    report = budget_inspect(inv, plan, controller, asset, step, work,
                            source_loader=loader)
    rows, tail, state, audit_sha = _original_attempt(
        inv, plan, controller, asset, step, work)
    require(report['original_audit_tail'] == tail and
            report['original_audit_sha256'] == audit_sha and
            sha(controller.master.read_bytes()) == work['master_sha256'] and
            state['last_audit_hash'] == tail,
            'C07_P5_FULL_ORIGINAL_AUDIT_DRIFT')
    registered = _registered_artifacts(rows, state, step, loader, work)
    pins = plan.get('p345_evidence_contract', {}).get(
        'original_artifact_sha256', {})
    require(type(pins) is dict, 'C07_P5_FULL_PRE_D_PIN_SCHEMA')
    sources = {}
    for role, path, digest, raw in registered:
        if role in ('P5_PERF_BUDGET', 'NATIVE_EXPORT',
                    'LOD_EXPORT', 'BASELINE_SNAPSHOT'):
            require(role not in sources, 'C07_P5_FULL_DUPLICATE_ROLE')
            sources[role] = (path, digest, raw)
    def original(role, extension):
        item = sources.get(role)
        if (item is None or not item[0].lower().endswith(extension)
                or pins.get(role) != item[1]
                or sha(item[2]) != item[1]):
            return None
        return item[2]
    budget_raw = original('P5_PERF_BUDGET', '.json')
    budget = _json(budget_raw) if budget_raw is not None else {}
    native_raw = original('NATIVE_EXPORT', '.glb')
    lod_raw = original('LOD_EXPORT', '.glb')
    baseline_raw = original('BASELINE_SNAPSHOT', '.glb')
    if rule_id == 'AAA-200-O-144':
        importance = budget.get('asset_importance')
        profiles = budget.get('importance_lod_profiles')
        policy_ok = (importance in IMPORTANCE and type(profiles) is dict
                     and set(profiles) == set(IMPORTANCE))
        if policy_ok:
            previous = float('inf')
            for label in IMPORTANCE:
                row = profiles[label]
                policy_ok = (type(row) is dict and
                             set(row) == {'min_far_m', 'max_lod_triangle_ratio'}
                             and positive(row['min_far_m'])
                             and positive(row['max_lod_triangle_ratio'])
                             and row['max_lod_triangle_ratio'] < 1
                             and row['min_far_m'] < previous)
                if not policy_ok:
                    break
                previous = row['min_far_m']
        native = _triangles(native_raw) if native_raw is not None else None
        lod = _triangles(lod_raw) if lod_raw is not None else None
        coherent = bool(native and lod and all(
            abs(a-b) <= 0.01 for pair, other in zip(bounds(native), bounds(lod))
            for a, b in zip(pair, other)))
        near, far = budget.get('lod_near_m'), budget.get('lod_far_m')
        ratio = len(lod)/len(native) if native and lod else None
        fit = bool(policy_ok and coherent and positive(near) and
                   positive(far) and near < far and
                   far >= profiles[importance]['min_far_m'] and
                   0 < ratio <= profiles[importance]['max_lod_triangle_ratio']
                   and positive(budget.get('lod_max_triangle_ratio')) and
                   ratio <= budget['lod_max_triangle_ratio'])
        checks = dict(zip(CRITERIA[rule_id],
                          (bool(policy_ok), bool(coherent), bool(fit))))
        complete = bool(budget_raw and native_raw and lod_raw)
    else:
        baseline_sha = budget.get('material_cost_baseline_sha256')
        target = budget.get('min_material_binding_reduction_pct')
        policy_ok = (type(baseline_sha) is str and len(baseline_sha) == 64
                     and baseline_raw is not None and
                     baseline_sha == sha(baseline_raw) and
                     positive(target) and target <= 100)
        before = (material_bindings(baseline_raw)
                  if baseline_raw is not None else None)
        after = (material_bindings(native_raw)
                 if native_raw is not None else None)
        measured = before is not None and after is not None and before > after > 0
        fit = bool(policy_ok and measured and
                   100 * (before-after)/before >= target)
        checks = dict(zip(CRITERIA[rule_id],
                          (bool(policy_ok), bool(measured), bool(fit))))
        complete = bool(budget_raw and baseline_raw and native_raw)
    require(set(checks) == set(CRITERIA[rule_id]) and
            all(type(v) is bool for v in checks.values()),
            'C07_P5_FULL_CRITERIA_SCHEMA')
    return {'rule_id': rule_id, 'checks': checks,
            'evidence_complete': complete,
            'source_sha256': inv['rules'][rule_id]['source_sha256'],
            'attempt_id': work['attempt_id'],
            'operation_sha256': work['operation_sha256'],
            'original_audit_sha256': audit_sha,
            'original_audit_tail': tail,
            'individual_mg0': 'UNKNOWN',
            'advancement_authorized': False}
