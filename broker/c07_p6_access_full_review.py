"""P-154: original-byte door/passage/stair/railing geometry review.

Source-pinned P6 policy and both GLB exports are independently reopened from
the current hash-chained Controller attempt. Geometric QA is not an in-game
collision test, MG0, or owner approval.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p6_collision_semantics import inspect as collision_inspect, _triangles, _box, _aabb_intersects
from c07_p5_budget_semantics import _json

RULE = 'AAA-200-P-154'
CRITERIA = (
    'pre_d_four_access_kinds_and_clearance_limits_original_sha_pinned',
    'original_door_and_passage_free_and_stair_tread_rises_measured',
    'original_stair_and_side_rail_collision_and_visual_geometry_verified',
)

class AccessReviewBlocked(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise AccessReviewBlocked(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def positive(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0

def centroid(tri):
    return tuple(sum(v[k] for v in tri)/3 for k in range(3))

def inside(point, box):
    low, high = box
    return all(low[k] <= point[k] <= high[k] for k in range(3))

def xy_gap(a, b):
    return math.hypot(*(
        max(a[0][k]-b[1][k], b[0][k]-a[1][k], 0)
        for k in (0, 1)))

def inspect(source_context, rule_id):
    require(rule_id == RULE and type(source_context) is dict,
            'C07_P154_UNREVIEWED_LITERAL')
    inv, plan, controller = (source_context[k] for k in
                             ('inventory', 'plan', 'controller'))
    asset, step, work, loader = (source_context[k] for k in
                                 ('asset', 'step', 'work', 'source_loader'))
    # The existing P6 reader verifies the canonical literal, phase,
    # source catalog, original operation, and its immutable audit.
    collision_inspect(inv, plan, controller, asset, step, work,
                      source_loader=loader)
    rows, tail, state, audit_sha = _original_attempt(
        inv, plan, controller, asset, step, work)
    require(state.get('last_audit_hash') == tail and
            sha(controller.master.read_bytes()) == work['master_sha256'] and
            (state.get('active_step') or {}).get('step') == step,
            'C07_P154_ORIGINAL_AUDIT_DRIFT')
    artifacts = _registered_artifacts(rows, state, step, loader, work)
    sources = {}
    for role, path, digest, raw in artifacts:
        if role in ('P6_COLLISION_POLICY', 'NATIVE_EXPORT', 'COLLISION_EXPORT'):
            require(role not in sources, 'C07_P154_DUPLICATE_ROLE')
            sources[role] = (path, digest, raw)
    contract = plan.get('p678_evidence_contract', {})
    pins = contract.get('original_artifact_sha256', {}) if type(contract) is dict else {}
    require(type(pins) is dict, 'C07_P154_PRE_D_PIN_SCHEMA')
    def original(role, ext):
        item = sources.get(role)
        return (item[2] if item and item[0].lower().endswith(ext)
                and pins.get(role) == item[1] and sha(item[2]) == item[1]
                else None)
    policy_raw = original('P6_COLLISION_POLICY', '.json')
    visual_raw = original('NATIVE_EXPORT', '.glb')
    collision_raw = original('COLLISION_EXPORT', '.glb')
    complete = all(x is not None for x in (policy_raw, visual_raw, collision_raw))
    checks = dict.fromkeys(CRITERIA, False)
    if complete:
        policy = _json(policy_raw)
        visual, collision = _triangles(visual_raw), _triangles(collision_raw)
        openings = policy.get('openings')
        widths = (policy.get('player_clear_width_m'),
                  policy.get('player_clear_height_m'),
                  policy.get('max_stair_riser_m'),
                  policy.get('min_rail_height_m'),
                  policy.get('max_stair_rail_gap_m'))
        kinds = ('door', 'passage', 'stair', 'railing')
        valid = (type(openings) is list and 4 <= len(openings) <= 128 and
                 all(positive(x) for x in widths) and
                 0.1 <= widths[0] <= 3 and 1 <= widths[1] <= 4 and
                 0.05 <= widths[2] <= 0.5 and
                 0.5 <= widths[3] <= 2 and
                 0 < widths[4] <= 2)
        grouped = {k: [] for k in kinds}
        names = set()
        if valid:
            for row in openings:
                if (type(row) is not dict or row.get('kind') not in grouped or
                        type(row.get('name')) is not str or
                        not row['name'].strip() or row['name'] in names or
                        _box(row) is None):
                    valid = False
                    break
                names.add(row['name'])
                grouped[row['kind']].append(_box(row))
            valid = valid and all(grouped.values())
        checks[CRITERIA[0]] = bool(valid)
        if valid:
            clear = all(
                max(box[1][0]-box[0][0], box[1][1]-box[0][1]) >= widths[0]
                and box[1][2]-box[0][2] >= widths[1]
                and not any(_aabb_intersects(tri, box) for tri in collision)
                for kind in ('door', 'passage') for box in grouped[kind])
            stair_ok = True
            for box in grouped['stair']:
                treads = [tri for tri in collision
                          if inside(centroid(tri), box) and
                          max(v[2] for v in tri)-min(v[2] for v in tri) <= 0.02]
                levels = sorted(set(round(centroid(tri)[2], 4) for tri in treads))
                stair_ok = stair_ok and (
                    len(levels) >= 2 and
                    all(0 < b-a <= widths[2] for a, b in zip(levels, levels[1:])))
            checks[CRITERIA[1]] = bool(clear and stair_ok)
            rail_ok = True
            for box in grouped['railing']:
                vertical = [tri for tri in collision
                            if inside(centroid(tri), box) and
                            max(v[2] for v in tri)-min(v[2] for v in tri)
                            >= widths[3]]
                adjacent = any(0 < xy_gap(box, stair) <= widths[4]
                               for stair in grouped['stair'])
                rail_ok = rail_ok and bool(vertical and adjacent and
                    any(_aabb_intersects(tri, box) for tri in visual))
            stair_visual = all(any(_aabb_intersects(tri, box) for tri in visual)
                               for box in grouped['stair'])
            checks[CRITERIA[2]] = bool(rail_ok and stair_visual)
    return {'rule_id': RULE, 'checks': {k: bool(v) for k, v in checks.items()},
            'evidence_complete': bool(complete),
            'source_sha256': inv['rules'][RULE]['source_sha256'],
            'attempt_id': work['attempt_id'],
            'operation_sha256': work['operation_sha256'],
            'original_audit_sha256': audit_sha, 'original_audit_tail': tail,
            'individual_mg0': 'UNKNOWN', 'advancement_authorized': False}
