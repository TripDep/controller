"""C07 read-only source GLB adjacency/winding evidence, never asset acceptance.

Uses the existing strictly parsed glTF 2.0 embedded-buffer accessors. Tests
index topology of each triangle primitive, not appearance, collision, final
water level, game world coordinates or Blender/FiveM behavior.

A triangle edge shared by two faces must be traversed in opposite directions
for coherent winding. Open edges are reported separately from orientation
conflicts. Distinct but coincident (unwelded) vertices are NOT identified as
adjacent by this conservative index-only audit.
"""
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

from glb_machine_qa import parse, read_accessor, GLBError

HEX = re.compile(r'[a-f0-9]{64}\Z')


class WindingBlocked(ValueError):
    pass


def need(value, reason):
    if not value:
        raise WindingBlocked(reason)


def scan_bytes(raw, expected_sha256):
    need(type(raw) is bytes and 0 < len(raw) <= 250_000_000,
         'C07_WINDING_INVALID_INPUT_SIZE')
    need(type(expected_sha256) is str and HEX.fullmatch(expected_sha256)
         and hashlib.sha256(raw).hexdigest() == expected_sha256,
         'C07_WINDING_SOURCE_SHA256_DRIFT')
    g, binary = parse(raw)
    meshes = g.get('meshes', [])
    need(type(meshes) is list and meshes, 'C07_WINDING_NO_MESHES')
    need(len(meshes) <= 100_000, 'C07_WINDING_MESH_LIMIT')
    issues = []
    closed = 0
    consistent = 0
    total_triangles = 0
    total_conflicts = 0
    total_boundary = 0
    total_nonmanifold = 0
    for mid, mesh in enumerate(meshes):
        name = mesh.get('name') or 'MESH_%06d' % mid
        need(type(name) is str and len(name) <= 2048,
             'C07_WINDING_MESH_NAME')
        edges = defaultdict(list)
        face_count = 0
        primitives = mesh.get('primitives', [])
        need(type(primitives) is list and primitives,
             'C07_WINDING_NO_PRIMITIVES')
        for pid, prim in enumerate(primitives):
            need(prim.get('mode', 4) == 4 and not prim.get('targets'),
                 'C07_WINDING_TRIANGLES_ONLY:' + str(mid))
            attrs = prim.get('attributes', {})
            need(type(attrs) is dict and 'POSITION' in attrs,
                 'C07_WINDING_POSITION_REQUIRED:' + str(mid))
            vertices = read_accessor(g, binary, attrs['POSITION'], 'VEC3', (5126,))
            if 'indices' in prim:
                indices = [v[0] for v in read_accessor(
                    g, binary, prim['indices'], 'SCALAR', (5121, 5123, 5125))]
            else:
                indices = list(range(len(vertices)))
            need(len(indices) % 3 == 0
                 and all(type(i) is int and 0 <= i < len(vertices)
                         for i in indices),
                 'C07_WINDING_INVALID_TRIANGLE_INDICES:' + str(mid))
            face_count += len(indices) // 3
            total_triangles += len(indices) // 3
            need(total_triangles <= 12_000_000,
                 'C07_WINDING_TRIANGLE_LIMIT')
            # Different primitives must NOT be welded just because their index
            # numbers coincide; the primitive ID is part of the edge key.
            for pos in range(0, len(indices), 3):
                a, b, c = indices[pos:pos + 3]
                need(len({a, b, c}) == 3,
                     'C07_WINDING_DEGENERATE_INDEX_TRIANGLE:' + str(mid))
                for u, v in ((a, b), (b, c), (c, a)):
                    key = (pid, min(u, v), max(u, v))
                    edges[key].append(1 if u < v else -1)
        boundary = sum(len(v) == 1 for v in edges.values())
        nonmanifold = sum(len(v) > 2 for v in edges.values())
        conflicts = sum(len(v) == 2 and v[0] == v[1]
                        for v in edges.values())
        if not boundary and not nonmanifold:
            closed += 1
        if not conflicts and not nonmanifold:
            consistent += 1
        total_boundary += boundary
        total_conflicts += conflicts
        total_nonmanifold += nonmanifold
        if boundary or nonmanifold or conflicts:
            issues.append({
                'mesh_index': mid, 'name': name, 'triangle_count': face_count,
                'boundary_edges': boundary, 'nonmanifold_edges': nonmanifold,
                'same_direction_shared_edges': conflicts,
            })
    bad = [x for x in issues if x['same_direction_shared_edges']
           or x['nonmanifold_edges']]
    return {
        'schema': 'gg-c07-glb-winding-index-evidence-v1',
        'source_sha256': expected_sha256,
        'mesh_count': len(meshes),
        'triangles_examined': total_triangles,
        'index_topology_closed_meshes': closed,
        'consistent_meshes': consistent,
        'orientation_conflict_meshes': len(bad),
        'same_direction_shared_edges': total_conflicts,
        'boundary_edges': total_boundary,
        'nonmanifold_edges': total_nonmanifold,
        'flagged_meshes': bad,
        'flagged_meshes_sha256': hashlib.sha256(json.dumps(
            bad, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        'topology_observation': ('SOURCE_EDGE_ORIENTATION_CONFLICT_OBSERVED'
                                 if bad else 'NO_INDEX_WINDING_CONFLICT_OBSERVED'),
        'unwelded_coincident_edges_checked': False,
        'artistic_qa': 'UNKNOWN',
        'collision_qa': 'UNKNOWN',
        'blender_roundtrip': 'UNKNOWN',
        'game_world_scale_and_position': 'UNKNOWN',
        'individual_mg0': 'UNKNOWN',
        'asset_approved': False,
        'advancement_authorized': False,
    }


def scan_file(path, expected_sha256):
    file = Path(path)
    need(file.is_file() and file.suffix.lower() == '.glb' and
         not file.is_symlink(), 'C07_WINDING_LOCAL_GLB_REQUIRED')
    need(file.stat().st_size <= 250_000_000, 'C07_WINDING_SIZE_LIMIT')
    return scan_bytes(file.read_bytes(), expected_sha256)
