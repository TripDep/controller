"""Native E-043 spatial review: independently measure two original GLB buildings.

The source-pinned P1 scene contract supplies *pre-D* placements and minimum
clearances; exported GLB vertices supply the dimensions. This does not assert
owner aesthetic approval or engine runtime acceptance.
"""
import hashlib
import json
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p1_thirty_native_domain import inspect as p1_inspect, jbytes
from c07_native_output_oracle import read_mesh_geometry
from c07_p6_collision_semantics import _triangles

RULE = 'AAA-200-E-043'
ALIGNMENT_RULE = 'AAA-200-F-054'
RULES = frozenset((RULE, ALIGNMENT_RULE))
CRITERIA = (
    'pre_d_two_building_world_placements_and_ratio_targets_sha_pinned',
    'actual_original_world_space_building_extents_independently_measured',
    'real_building_clearance_footprint_and_height_ratios_meet_pre_d_limits',
)

ALIGNMENT_CRITERIA = (
    'pre_d_complete_module_alignment_pair_contract_sha_pinned',
    'every_alignment_anchor_recomputed_from_actual_original_mesh_vertices',
    'all_actual_world_space_module_anchor_gaps_within_original_tolerance',
)

class P1SpatialReviewBlocked(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise P1SpatialReviewBlocked(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def numeric(v):
    return type(v) in (int, float) and math.isfinite(v)

def positive(v):
    return numeric(v) and v > 0

def ratio_range(v):
    return (type(v) is list and len(v) == 2 and
            positive(v[0]) and positive(v[1]) and v[0] <= v[1])

def placement(v):
    return (type(v) is dict and set(v) == {
        'translation_xyz', 'yaw_deg', 'scale_xyz'} and
        type(v['translation_xyz']) is list and
        type(v['scale_xyz']) is list and
        len(v['translation_xyz']) == len(v['scale_xyz']) == 3 and
        all(numeric(x) for x in v['translation_xyz']) and
        all(positive(x) for x in v['scale_xyz']) and
        numeric(v['yaw_deg']))

def world_bounds(local, pose):
    lo, hi = local['bbox_min'], local['bbox_max']
    theta = math.radians(pose['yaw_deg'])
    co, si = math.cos(theta), math.sin(theta)
    xyz = []
    for x in (lo[0], hi[0]):
        for y in (lo[1], hi[1]):
            for z in (lo[2], hi[2]):
                sx, sy, sz = (x * pose['scale_xyz'][0],
                              y * pose['scale_xyz'][1],
                              z * pose['scale_xyz'][2])
                xyz.append((
                    sx*co - sy*si + pose['translation_xyz'][0],
                    sx*si + sy*co + pose['translation_xyz'][1],
                    sz + pose['translation_xyz'][2]))
    return tuple((min(p[k] for p in xyz), max(p[k] for p in xyz))
                 for k in range(3))

def inspect(source_context, rule_id):
    require(rule_id in RULES and type(source_context) is dict,
            'C07_E043_UNREVIEWED_RULE')
    inv = source_context['inventory']
    plan = source_context['plan']
    controller = source_context['controller']
    asset = source_context['asset']
    step = source_context['step']
    work = source_context['work']
    loader = source_context['source_loader']
    report = p1_inspect(inv, plan, controller, asset, step, work,
                        source_loader=loader)
    rows, tail, state, audit_sha = _original_attempt(
        inv, plan, controller, asset, step, work)
    require(report['original_audit_tail'] == tail and
            report['original_audit_sha256'] == audit_sha and
            sha(controller.master.read_bytes()) == work['master_sha256'],
            'C07_E043_ORIGINAL_AUDIT_CHANGED')
    artifacts = _registered_artifacts(rows, state, step, loader, work)
    pins = plan.get('p1_evidence_contract', {}).get('original_artifact_sha256', {})
    require(type(pins) is dict, 'C07_E043_PRE_D_PIN_SCHEMA')
    found = {}
    for role, path, digest, raw in artifacts:
        if role in ('P1_SCENE_CONTRACT', 'NATIVE_EXPORT', 'SECONDARY_EXPORT'):
            require(role not in found, 'C07_E043_DUPLICATE_ROLE')
            found[role] = (path, digest, raw)
    def original(role, ext):
        row = found.get(role)
        if (row is None or not row[0].lower().endswith(ext) or
                pins.get(role) != row[1] or sha(row[2]) != row[1]):
            return None
        return row[2]
    scene_raw = original('P1_SCENE_CONTRACT', '.json')
    scene = jbytes(scene_raw) if scene_raw is not None else {}
    raw_a = original('NATIVE_EXPORT', '.glb')
    raw_b = original('SECONDARY_EXPORT', '.glb')
    poses = scene.get('building_world_placements')
    clearance = scene.get('building_clearance_m')
    area_range = scene.get('building_footprint_area_ratio_range')
    height_range = scene.get('building_height_ratio_range')
    policy = bool(type(poses) is dict and set(poses) == {'primary', 'secondary'}
                  and all(placement(v) for v in poses.values())
                  and positive(clearance) and ratio_range(area_range)
                  and ratio_range(height_range))
    if rule_id == ALIGNMENT_RULE:
        pairs = scene.get('module_alignment_pairs')
        alignment_policy = bool(
            type(poses) is dict and set(poses) == {'primary', 'secondary'}
            and all(placement(v) for v in poses.values())
            and type(pairs) is list and 0 < len(pairs) <= 128
            and all(type(row) is dict and set(row) == {
                'primary_vertex_xyz', 'secondary_vertex_xyz', 'max_gap_m'}
                and all(type(row[key]) is list and len(row[key]) == 3
                        and all(numeric(x) for x in row[key])
                        for key in ('primary_vertex_xyz', 'secondary_vertex_xyz'))
                and positive(row['max_gap_m']) and row['max_gap_m'] <= 0.25
                for row in pairs))
        tris_a = _triangles(raw_a) if raw_a is not None else None
        tris_b = _triangles(raw_b) if raw_b is not None else None
        verts_a = set(tuple(p) for tri in tris_a for p in tri) if tris_a else set()
        verts_b = set(tuple(p) for tri in tris_b for p in tri) if tris_b else set()
        anchors = bool(alignment_policy and verts_a and verts_b and all(
            tuple(row['primary_vertex_xyz']) in verts_a and
            tuple(row['secondary_vertex_xyz']) in verts_b for row in pairs))
        def world_point(point, pose):
            theta = math.radians(pose['yaw_deg'])
            co, si = math.cos(theta), math.sin(theta)
            x, y, z = [point[k]*pose['scale_xyz'][k] for k in range(3)]
            return (x*co-y*si+pose['translation_xyz'][0],
                    x*si+y*co+pose['translation_xyz'][1],
                    z+pose['translation_xyz'][2])
        aligned = bool(anchors and all(
            math.dist(world_point(row['primary_vertex_xyz'], poses['primary']),
                      world_point(row['secondary_vertex_xyz'], poses['secondary']))
            <= row['max_gap_m'] for row in pairs))
        checks = dict(zip(ALIGNMENT_CRITERIA,
                          (bool(alignment_policy), bool(anchors), bool(aligned))))
        return {'rule_id': rule_id, 'checks': checks,
                'evidence_complete': bool(scene_raw and raw_a and raw_b),
                'original_audit_sha256': audit_sha,
                'original_audit_tail': tail,
                'attempt_id': work['attempt_id'],
                'operation_sha256': work['operation_sha256'],
                'individual_mg0': 'UNKNOWN', 'advancement_authorized': False}
    a = read_mesh_geometry(raw_a) if raw_a is not None else None
    b = read_mesh_geometry(raw_b) if raw_b is not None else None
    measured = bool(policy and a and b and a['triangles'] > 0
                    and b['triangles'] > 0)
    if measured:
        wa = world_bounds(a, poses['primary'])
        wb = world_bounds(b, poses['secondary'])
        dx = max(wa[0][0]-wb[0][1], wb[0][0]-wa[0][1], 0)
        dy = max(wa[1][0]-wb[1][1], wb[1][0]-wa[1][1], 0)
        gap = math.hypot(dx, dy)
        area_a = (wa[0][1]-wa[0][0])*(wa[1][1]-wa[1][0])
        area_b = (wb[0][1]-wb[0][0])*(wb[1][1]-wb[1][0])
        height_a, height_b = wa[2][1]-wa[2][0], wb[2][1]-wb[2][0]
        measured = all(positive(x) for x in (area_a, area_b, height_a, height_b))
        fit = bool(measured and gap >= clearance and
                   area_range[0] <= area_a/area_b <= area_range[1] and
                   height_range[0] <= height_a/height_b <= height_range[1])
    else:
        fit = False
    checks = dict(zip(CRITERIA, (bool(policy), bool(measured), bool(fit))))
    return {'rule_id': rule_id, 'checks': checks,
            'evidence_complete': bool(scene_raw and raw_a and raw_b),
            'original_audit_sha256': audit_sha,
            'original_audit_tail': tail,
            'attempt_id': work['attempt_id'],
            'operation_sha256': work['operation_sha256'],
            'individual_mg0': 'UNKNOWN', 'advancement_authorized': False}
