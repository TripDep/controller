"""E049/E050/F053: original-byte, source-specific P1 spatial and lock review.

The accepted *code* predicate is limited to the exact pre-D recorded scope:
all declared existing assets, whole-native-export lock, and named native
orientation anchors. Missing independent sources remain UNKNOWN. No owner,
world runtime, MG0 or asset approval is inferred.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p1_thirty_native_domain import inspect as p1_inspect, jbytes
from c07_p6_collision_semantics import _triangles

OVERLAP = 'AAA-200-E-049'
LOCK = 'AAA-200-E-050'
ORIENTATION = 'AAA-200-F-053'
RULES = frozenset((OVERLAP, LOCK, ORIENTATION))
CRITERIA = {
    OVERLAP: (
        'pre_d_complete_existing_asset_placement_and_clearance_policy_sha_pinned',
        'original_native_and_every_existing_asset_world_bounds_independently_recomputed',
        'all_actual_world_aabbs_separated_by_source_required_clearance'),
    LOCK: (
        'pre_d_entire_asset_lock_and_original_baseline_sha_pinned',
        'current_native_and_baseline_original_export_bytes_identical',
        'current_and_baseline_original_world_placements_identical'),
    ORIENTATION: (
        'pre_d_world_forward_and_original_native_anchor_contract_sha_pinned',
        'both_original_forward_anchor_points_present_in_actual_native_mesh',
        'measured_native_world_forward_and_up_match_source_target'),
}

class P1EnvironmentBlocked(ValueError):
    pass

def need(value, code):
    if not value:
        raise P1EnvironmentBlocked(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def finite(value):
    return type(value) in (int, float) and math.isfinite(value)

def vec(value, n=3):
    return type(value) is list and len(value) == n and all(finite(x) for x in value)

def pose(value):
    return (type(value) is dict and
            set(value) == {'translation_xyz', 'yaw_deg', 'scale_xyz'} and
            vec(value['translation_xyz']) and vec(value['scale_xyz']) and
            finite(value['yaw_deg']) and
            all(0 < s < 1e6 for s in value['scale_xyz']))

def world(point, placement):
    x, y, z = (point[k] * placement['scale_xyz'][k] for k in range(3))
    angle = math.radians(placement['yaw_deg'])
    return (x * math.cos(angle) - y * math.sin(angle) +
            placement['translation_xyz'][0],
            x * math.sin(angle) + y * math.cos(angle) +
            placement['translation_xyz'][1],
            z + placement['translation_xyz'][2])

def bounds(triangles, placement):
    points = [world(p, placement) for tri in triangles for p in tri]
    return tuple((min(p[k] for p in points), max(p[k] for p in points))
                 for k in range(3)) if points else None

def separation(a, b):
    # AABB separation is a conservative proof of *no* triangle intersection.
    # An intersecting AABB cannot be treated as proof of mesh intersection.
    return math.sqrt(sum(max(0., a[k][0] - b[k][1],
                             b[k][0] - a[k][1]) ** 2 for k in range(3)))

def inspect(source_context, rule_id):
    need(rule_id in RULES and type(source_context) is dict and
         set(source_context) == {'inventory', 'plan', 'controller',
                                 'asset', 'step', 'work', 'source_loader'},
         'C07_P1_ENV_UNREVIEWED_LITERAL_OR_CONTEXT')
    inv, plan, controller = (source_context[k] for k in
                             ('inventory', 'plan', 'controller'))
    asset, step, work, loader = (source_context[k] for k in
                                 ('asset', 'step', 'work', 'source_loader'))
    # Validate all thirty exact canonical P1 literals, current operation,
    # hash chain and source identity before accepting any geometry.
    p1_inspect(inv, plan, controller, asset, step, work,
               source_loader=loader)
    rows, tail, state, audit_sha = _original_attempt(
        inv, plan, controller, asset, step, work)
    need(state.get('last_audit_hash') == tail and
         sha(controller.master.read_bytes()) == work['master_sha256'] and
         (state.get('active_step') or {}).get('step') == step,
         'C07_P1_ENV_ORIGINAL_OPERATION_DRIFT')
    contract = plan.get('p1_evidence_contract', {})
    pins = contract.get('original_artifact_sha256', {}) if type(contract) is dict else {}
    need(type(pins) is dict, 'C07_P1_ENV_PRE_D_PIN_SCHEMA')
    registered = {}
    for role, path, digest, raw in _registered_artifacts(
            rows, state, step, loader, work):
        need(role not in registered, 'C07_P1_ENV_DUPLICATE_ORIGINAL_ROLE')
        registered[role] = (path, digest, raw)
    def original(role, suffix):
        item = registered.get(role)
        if not item or not item[0].lower().endswith(suffix):
            return None
        return item[2] if pins.get(role) == item[1] and sha(item[2]) == item[1] else None
    scene_raw = original('P1_SCENE_CONTRACT', '.json')
    native_raw = original('NATIVE_EXPORT', '.glb')
    scene = jbytes(scene_raw) if scene_raw is not None else {}
    native = _triangles(native_raw) if native_raw is not None else []
    checks = {}
    complete = False
    if rule_id == OVERLAP:
        placement_raw = original('P1_WORLD_PLACEMENTS', '.json')
        placement_doc = jbytes(placement_raw) if placement_raw is not None else {}
        actual_placements = placement_doc.get('placements')
        expected_placements = scene.get('expected_world_placements')
        existing_roles = scene.get('existing_asset_roles')
        clearance = scene.get('existing_asset_clearance_m')
        declared = bool(type(existing_roles) is list and
                        1 <= len(existing_roles) <= 128 and
                        len(set(existing_roles)) == len(existing_roles) and
                        all(type(role) is str and role not in
                            ('NATIVE_EXPORT', 'P1_SCENE_CONTRACT')
                            for role in existing_roles) and
                        type(expected_placements) is dict and
                        set(expected_placements) == set(existing_roles) | {'NATIVE_EXPORT'} and
                        all(pose(p) for p in expected_placements.values()) and
                        finite(clearance) and 0 < clearance < 10000)
        measured = bool(declared and native and
                        type(actual_placements) is dict and
                        actual_placements == expected_placements)
        world_boxes = {}
        if measured:
            world_boxes['NATIVE_EXPORT'] = bounds(
                native, actual_placements['NATIVE_EXPORT'])
            for role in existing_roles:
                raw = original(role, '.glb')
                if raw is None:
                    measured = False
                    break
                triangles = _triangles(raw)
                if not triangles:
                    measured = False
                    break
                world_boxes[role] = bounds(triangles, actual_placements[role])
            measured = bool(measured and len(world_boxes) == len(existing_roles) + 1
                            and all(world_boxes.values()))
        separated = bool(measured and all(
            separation(world_boxes['NATIVE_EXPORT'], world_boxes[role]) >= clearance
            for role in existing_roles))
        checks = dict(zip(CRITERIA[rule_id], (
            bool(declared and scene_raw is not None and placement_raw is not None),
            measured, separated)))
        complete = bool(declared and native_raw is not None and
                        placement_raw is not None and
                        all(original(role, '.glb') is not None
                            for role in existing_roles))
    elif rule_id == LOCK:
        baseline_raw = original('BASELINE_SNAPSHOT', '.glb')
        placement_raw = original('P1_WORLD_PLACEMENTS', '.json')
        baseline_placement = original('BASELINE_WORLD_PLACEMENTS', '.json')
        source_raw = original('SOURCE_EDITABLE', '.blend')
        declared = bool(scene.get('locked_scope') == 'entire_asset' and
                        type(scene.get('locked_native_export_sha256')) is str and
                        scene['locked_native_export_sha256'] ==
                        (sha(baseline_raw) if baseline_raw is not None else None) and
                        source_raw is not None and
                        scene.get('locked_original_sha256') == sha(source_raw))
        # Byte identity is intentionally strict: geometric similarity, a
        # producer assertion, or a hash-only match never proves lock retention.
        same_mesh = bool(declared and native_raw is not None and
                         baseline_raw is not None and native_raw == baseline_raw)
        same_placement = bool(declared and placement_raw is not None and
                              baseline_placement is not None and
                              jbytes(placement_raw) and
                              jbytes(placement_raw) == jbytes(baseline_placement) and
                              placement_raw == baseline_placement)
        checks = dict(zip(CRITERIA[rule_id], (declared, same_mesh, same_placement)))
        complete = bool(declared and native_raw is not None and
                        baseline_raw is not None and placement_raw is not None and
                        baseline_placement is not None)
    else:
        placement_raw = original('P1_WORLD_PLACEMENTS', '.json')
        placement_doc = jbytes(placement_raw) if placement_raw is not None else {}
        placements = placement_doc.get('placements')
        anchors = scene.get('orientation_anchor_local')
        forward = scene.get('expected_forward_world')
        up = scene.get('expected_up_world')
        declared = bool(type(anchors) is list and len(anchors) == 2 and
                        all(vec(p) for p in anchors) and
                        anchors[0] != anchors[1] and
                        vec(forward) and vec(up) and
                        type(placements) is dict and
                        'NATIVE_EXPORT' in placements and
                        pose(placements['NATIVE_EXPORT']) and
                        scene.get('expected_world_placements', {}).get('NATIVE_EXPORT') ==
                        placements['NATIVE_EXPORT'] and
                        abs(math.sqrt(sum(x*x for x in forward)) - 1) < 1e-5 and
                        abs(math.sqrt(sum(x*x for x in up)) - 1) < 1e-5)
        vertices = set(tuple(p) for tri in native for p in tri)
        original_anchors = bool(declared and native and
                                all(tuple(p) in vertices for p in anchors))
        correct = False
        if original_anchors:
            placement = placements['NATIVE_EXPORT']
            a, b = (world(p, placement) for p in anchors)
            direction = [b[k] - a[k] for k in range(3)]
            length = math.sqrt(sum(x*x for x in direction))
            # Require actual measured native orientation, not a declared
            # rotation value or the name of a camera image.
            correct = bool(length > 1e-9 and
                sum(direction[k] * forward[k] for k in range(3)) / length > 0.99999
                and sum(up[k] * (1 if k == 2 else 0) for k in range(3)) > 0.99999)
        checks = dict(zip(CRITERIA[rule_id], (
            bool(declared and scene_raw is not None and placement_raw is not None),
            original_anchors, correct)))
        complete = bool(declared and native_raw is not None and
                        placement_raw is not None and original_anchors)
    need(set(checks) == set(CRITERIA[rule_id]) and
         all(type(v) is bool for v in checks.values()),
         'C07_P1_ENV_EXACT_RULE_CHECKS_CHANGED')
    return {'rule_id': rule_id, 'checks': checks,
            'evidence_complete': complete,
            'source_sha256': inv['rules'][rule_id]['source_sha256'],
            'attempt_id': work['attempt_id'],
            'operation_sha256': work['operation_sha256'],
            'original_audit_sha256': audit_sha, 'original_audit_tail': tail,
            'individual_mg0': 'UNKNOWN', 'advancement_authorized': False}
