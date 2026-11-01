"""P1 E048/F055: independently measured planar terrain contact and player corridor.

Only a single-planar-support-triangle pre-D contract is decidable here. Other
terrain, unspecified obstacles, unpinned paths and engine physics remain
UNKNOWN; source geometry cannot confer FiveM/owner/MG0 acceptance.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p1_thirty_native_domain import inspect as inspect_p1, jbytes
from c07_p6_collision_semantics import _triangles
from c07_p1_environment_full_review import pose, world

TERRAIN = 'AAA-200-E-048'
WALK = 'AAA-200-F-055'
RULES = frozenset((TERRAIN, WALK))
CRITERIA = {
    TERRAIN: (
        'pre_d_planar_terrain_contact_contract_and_both_original_meshes_sha_pinned',
        'entire_native_projected_footprint_inside_original_support_triangle',
        'all_original_native_vertices_above_ground_and_measured_contacts_within_tolerance'),
    WALK: (
        'pre_d_player_capsule_path_and_all_obstacle_roles_original_sha_pinned',
        'all_original_walkable_segments_inside_measured_support_terrain',
        'all_measured_player_swept_corridors_clear_of_original_blocking_triangles'),
}

class P1TerrainBlocked(ValueError):
    pass

def need(value, code):
    if not value:
        raise P1TerrainBlocked(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def finite(x):
    return type(x) in (int, float) and math.isfinite(x)

def point2(p):
    return type(p) is list and len(p) == 2 and all(finite(v) for v in p)

def inside(p, tri, eps=1e-9):
    a, b, c = tri
    den = (b[1]-c[1])*(a[0]-c[0]) + (c[0]-b[0])*(a[1]-c[1])
    if abs(den) < eps:
        return False
    u = ((b[1]-c[1])*(p[0]-c[0]) + (c[0]-b[0])*(p[1]-c[1]))/den
    v = ((c[1]-a[1])*(p[0]-c[0]) + (a[0]-c[0])*(p[1]-c[1]))/den
    return u >= -eps and v >= -eps and u+v <= 1+eps

def aabb(tri):
    return tuple((min(p[k] for p in tri), max(p[k] for p in tri))
                 for k in range(3))

def intersects(a, b):
    return all(a[k][1] >= b[k][0] and b[k][1] >= a[k][0]
               for k in range(3))

def inspect(source_context, rule_id):
    need(rule_id in RULES and type(source_context) is dict and
         set(source_context) == {'inventory', 'plan', 'controller',
                                 'asset', 'step', 'work', 'source_loader'},
         'C07_P1_TERRAIN_RULE_OR_CONTEXT')
    inv, plan, controller = (source_context[k] for k in
                             ('inventory', 'plan', 'controller'))
    asset, step, work, loader = (source_context[k] for k in
                                 ('asset', 'step', 'work', 'source_loader'))
    inspect_p1(inv, plan, controller, asset, step, work,
               source_loader=loader)
    rows, tail, state, audit_sha = _original_attempt(
        inv, plan, controller, asset, step, work)
    need(state.get('last_audit_hash') == tail and
         sha(controller.master.read_bytes()) == work['master_sha256'] and
         (state.get('active_step') or {}).get('step') == step,
         'C07_P1_TERRAIN_CURRENT_AUDIT_DRIFT')
    contract = plan.get('p1_evidence_contract', {})
    pins = contract.get('original_artifact_sha256', {}) if type(contract) is dict else {}
    need(type(pins) is dict, 'C07_P1_TERRAIN_PRE_D_PINS')
    found = {}
    for role, path, digest, raw in _registered_artifacts(
            rows, state, step, loader, work):
        need(role not in found, 'C07_P1_TERRAIN_DUPLICATE_ROLE')
        found[role] = (path, digest, raw)
    def original(role, ext):
        item = found.get(role)
        return item[2] if (item and item[0].lower().endswith(ext) and
            pins.get(role) == item[1] and sha(item[2]) == item[1]) else None
    scene_raw = original('P1_SCENE_CONTRACT', '.json')
    terrain_raw = original('P1_TERRAIN_EXPORT', '.glb')
    native_raw = original('NATIVE_EXPORT', '.glb')
    placement_raw = original('P1_WORLD_PLACEMENTS', '.json')
    scene = jbytes(scene_raw) if scene_raw is not None else {}
    placement_doc = jbytes(placement_raw) if placement_raw is not None else {}
    current_placements = placement_doc.get('placements')
    expected_placements = scene.get('expected_world_placements')
    identity = {'translation_xyz': [0, 0, 0], 'yaw_deg': 0,
                'scale_xyz': [1, 1, 1]}
    shared_reference = bool(type(current_placements) is dict and
        current_placements == expected_placements and
        current_placements.get('NATIVE_EXPORT') == identity and
        current_placements.get('P1_TERRAIN_EXPORT') == identity)
    tolerance = scene.get('terrain_support_contact_tolerance_m')
    minimum = scene.get('terrain_min_support_vertices')
    height = scene.get('terrain_reference_z_m')
    policy = bool(scene.get('terrain_scope') ==
                  'single_planar_support_triangle' and
                  scene.get('terrain_reference_frame') == 'shared_local' and
                  shared_reference and placement_raw is not None and
                  finite(height) and finite(tolerance) and
                  0 < tolerance <= 0.05 and
                  type(minimum) is int and 3 <= minimum <= 10000)
    terrain = _triangles(terrain_raw) if terrain_raw is not None else []
    native = _triangles(native_raw) if native_raw is not None else []
    planar = bool(policy and terrain and
                  all(abs(p[2] - height) <= 1e-8
                      for tri in terrain for p in tri))
    # A single original planar triangle must cover the *entire* native XY
    # footprint. A handful of arbitrary terrain samples cannot prove contact.
    native_points = {tuple(p) for tri in native for p in tri}
    cover = next((tri for tri in terrain if
                  all(inside(p, tri) for p in native_points)), None) if planar and native else None
    covered = bool(cover is not None)
    contact = {p for p in native_points
               if abs(p[2] - height) <= tolerance} if covered else set()
    stable = bool(covered and
                  all(p[2] >= height - tolerance for p in native_points) and
                  len(contact) >= minimum)
    if rule_id == TERRAIN:
        checks = dict(zip(CRITERIA[rule_id], (
            bool(policy and scene_raw is not None and terrain_raw is not None
                 and native_raw is not None and placement_raw is not None),
            covered, stable)))
        complete = bool(policy and terrain_raw is not None and
                        native_raw is not None and planar)
    else:
        paths_raw = original('P1_PATHS_GEOJSON', '.json')
        paths = jbytes(paths_raw) if paths_raw is not None else {}
        placements = current_placements
        expected = expected_placements
        roles = scene.get('existing_asset_roles')
        wanted = scene.get('walkable_path_ids')
        width = scene.get('player_width_m')
        player_height = scene.get('player_height_m')
        features = paths.get('features')
        declared = bool(policy and planar and
            finite(width) and 0 < width <= 4 and
            finite(player_height) and 0 < player_height <= 4 and
            type(roles) is list and 1 <= len(roles) <= 128 and
            len(set(roles)) == len(roles) and
            all(type(role) is str for role in roles) and
            type(expected) is dict and
            set(expected) == set(roles) | {'NATIVE_EXPORT', 'P1_TERRAIN_EXPORT'} and
            all(pose(p) for p in expected.values()) and
            type(placements) is dict and placements == expected and
            type(wanted) is list and 1 <= len(wanted) <= 128 and
            len(set(wanted)) == len(wanted) and
            all(type(x) is str and x for x in wanted) and
            type(features) is list and len(features) == len(wanted) and
            {f.get('id') for f in features if type(f) is dict} == set(wanted) and
            all(type(f) is dict and f.get('class') == 'walkable' and
                type(f.get('geometry')) is dict and
                f['geometry'].get('type') == 'LineString' and
                type(f['geometry'].get('coordinates')) is list and
                len(f['geometry']['coordinates']) >= 2 and
                all(point2(p) for p in f['geometry']['coordinates'])
                for f in features))
        segments = []
        if declared:
            for feature in features:
                points = feature['geometry']['coordinates']
                segments += list(zip(points, points[1:]))
        path_covered = bool(declared and covered and segments and
            all(math.dist(a, b) > 1e-6 and
                inside(a, cover) and inside(b, cover) and
                inside(((a[0]+b[0])/2, (a[1]+b[1])/2), cover)
                for a, b in segments))
        blockers = []
        all_originals = True
        if path_covered:
            for role in roles:
                raw = original(role, '.glb')
                if raw is None:
                    all_originals = False
                    break
                tri = _triangles(raw)
                if not tri:
                    all_originals = False
                    break
                blockers.extend([[world(p, placements[role]) for p in t]
                                 for t in tri])
            # All native triangles above the original floor are blockers too.
            blockers.extend([[world(p, placements['NATIVE_EXPORT']) for p in t]
                             for t in native if max(p[2] for p in t) >
                             height + tolerance])
        corridor_clear = bool(path_covered and all_originals and
            all(not intersects(
                ((min(a[0], b[0])-width/2, max(a[0], b[0])+width/2),
                 (min(a[1], b[1])-width/2, max(a[1], b[1])+width/2),
                 (height+tolerance, height+player_height)),
                aabb(tri)) for a, b in segments for tri in blockers))
        checks = dict(zip(CRITERIA[rule_id], (
            bool(declared and scene_raw is not None and paths_raw is not None
                 and placement_raw is not None and terrain_raw is not None
                 and native_raw is not None),
            path_covered, corridor_clear)))
        complete = bool(declared and covered and all_originals and
                        paths_raw is not None and placement_raw is not None)
    need(set(checks) == set(CRITERIA[rule_id]) and
         all(type(v) is bool for v in checks.values()),
         'C07_P1_TERRAIN_CRITERIA_CHANGED')
    return {'rule_id': rule_id, 'checks': checks,
            'evidence_complete': complete,
            'source_sha256': inv['rules'][rule_id]['source_sha256'],
            'attempt_id': work['attempt_id'],
            'operation_sha256': work['operation_sha256'],
            'original_audit_sha256': audit_sha, 'original_audit_tail': tail,
            'individual_mg0': 'UNKNOWN', 'advancement_authorized': False}
