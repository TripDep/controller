"""Independent P3 topology literal replay from immutable original GLB bytes.

Only the three source-decidable L-111/L-113/L-114 technical predicates are
covered. A pinned reference is a comparison target, not evidence of owner
approval; individual MG0, artistic approval and FiveM remain UNKNOWN.
"""
from collections import Counter
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p3_geometry_semantics import geometry, _read_accessor
from c07_p5_budget_semantics import _glb_parts
from c07_p6_collision_semantics import _triangles

RULES = frozenset(('AAA-200-L-111', 'AAA-200-L-113', 'AAA-200-L-114'))
CRITERIA = {
    'AAA-200-L-111': (
        'all_original_mesh_primitives_topologically_inspected',
        'original_mesh_edges_no_nonmanifold_or_degenerate',
        'original_mesh_faces_unique'),
    'AAA-200-L-113': (
        'all_original_triangle_areas_independently_recomputed',
        'no_original_degenerate_or_duplicate_faces',
        'original_geometry_matches_source_pinned_reference'),
    'AAA-200-L-114': (
        'all_original_vertex_normals_finite_and_unit_length',
        'every_original_vertex_normal_matches_face_orientation',
        'original_face_orientation_matches_source_pinned_reference'),
}

class TopologyReviewBlocked(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise TopologyReviewBlocked(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def _faces(raw, *, oriented=False):
    """Read every indexed triangle, not a GLB header or a producer QA row."""
    triangles = _triangles(raw)
    def signature(tri):
        vertices = tuple(sorted(tuple(v) for v in tri))
        if not oriented:
            return vertices
        p, q, r = tri
        u = [q[k]-p[k] for k in range(3)]
        v = [r[k]-p[k] for k in range(3)]
        n = (u[1]*v[2]-u[2]*v[1],
             u[2]*v[0]-u[0]*v[2],
             u[0]*v[1]-u[1]*v[0])
        norm = math.sqrt(sum(x*x for x in n))
        return vertices, (tuple(round(x/norm, 7) for x in n)
                          if norm > 1e-10 else None)
    return Counter(signature(tri) for tri in triangles)

def _geometric_topology(raw):
    """Reconstruct welded geometric edges, including split-index UV seams."""
    triangles = _triangles(raw)
    edges = Counter()
    faces = Counter()
    degenerate = 0
    for tri in triangles:
        vertices = [tuple(v) for v in tri]
        faces[tuple(sorted(vertices))] += 1
        p, q, r = vertices
        u = [q[k]-p[k] for k in range(3)]
        v = [r[k]-p[k] for k in range(3)]
        cross = (u[1]*v[2]-u[2]*v[1],
                 u[2]*v[0]-u[0]*v[2],
                 u[0]*v[1]-u[1]*v[0])
        if len(set(vertices)) != 3 or sum(x*x for x in cross) <= 1e-20:
            degenerate += 1
        for a, b in ((p, q), (q, r), (r, p)):
            edges[tuple(sorted((a, b)))] += 1
    return {'triangles': len(triangles),
            'nonmanifold_edges': sum(v > 2 for v in edges.values()),
            'duplicate_faces': sum(v-1 for v in faces.values() if v > 1),
            'degenerate_faces': degenerate}


def _normal_consistency(raw):
    doc, binary = _glb_parts(raw)
    complete = True
    aligned = True
    for mesh in doc['meshes']:
        for primitive in mesh['primitives']:
            attrs = primitive['attributes']
            points = _read_accessor(doc, binary, attrs['POSITION'])
            if 'NORMAL' not in attrs:
                complete = False
                aligned = False
                continue
            normals = _read_accessor(doc, binary, attrs['NORMAL'])
            require(len(points) == len(normals),
                    'C07_TOPOLOGY_VERTEX_NORMAL_LENGTH')
            indices = (_read_accessor(doc, binary, primitive['indices'],
                                      scalar=True)
                       if 'indices' in primitive else list(range(len(points))))
            for offset in range(0, len(indices), 3):
                a, b, c = indices[offset:offset+3]
                p, q, r = (points[i] for i in (a, b, c))
                u = [q[k]-p[k] for k in range(3)]
                v = [r[k]-p[k] for k in range(3)]
                cross = (u[1]*v[2]-u[2]*v[1],
                         u[2]*v[0]-u[0]*v[2],
                         u[0]*v[1]-u[1]*v[0])
                area = math.sqrt(sum(x*x for x in cross))
                if area <= 1e-10:
                    aligned = False
                    continue
                for index in (a, b, c):
                    normal = normals[index]
                    length = math.sqrt(sum(x*x for x in normal))
                    if not 0.95 <= length <= 1.05:
                        complete = False
                        aligned = False
                    elif sum(cross[k]*normal[k] for k in range(3)) / (
                            area * length) < 1e-5:
                        aligned = False
    return complete, aligned

def inspect(source_context, rule_id):
    """Return independent per-literal checks and completeness of original proof.

    Missing original or missing pre-D pin is UNKNOWN, not a defect PASS/FAIL.
    Contradictory measured originals are a source-specific FAIL. No source
    data comes from the signed producer packet.
    """
    require(rule_id in RULES and type(source_context) is dict,
            'C07_TOPOLOGY_REVIEW_UNREGISTERED_RULE')
    inv = source_context['inventory']
    plan = source_context['plan']
    controller = source_context['controller']
    asset = source_context['asset']
    step = source_context['step']
    work = source_context['work']
    loader = source_context['source_loader']
    require(callable(loader) and plan.get('phase') == work.get('phase')
            and plan['phase'] in ('P3', 'P4', 'P5', 'P6', 'P7', 'P8',
                                 'VERIFY', 'G2', 'G3', 'G4', 'DELIVERY'),
            'C07_TOPOLOGY_REVIEW_PHASE_OR_LOADER')
    rows, tail, state, audit_sha = _original_attempt(
        inv, plan, controller, asset, step, work)
    require(state.get('last_audit_hash') == tail
            and sha(controller.master.read_bytes()) == work['master_sha256']
            and (state.get('active_step') or {}).get('step') == step,
            'C07_TOPOLOGY_REVIEW_ORIGINAL_AUDIT_CHANGED')
    registered = _registered_artifacts(rows, state, step, loader, work)
    found = {}
    for role, path, digest, raw in registered:
        if role in ('NATIVE_EXPORT', 'P3_APPROVED_REFERENCE'):
            require(role not in found, 'C07_TOPOLOGY_REVIEW_DUPLICATE_ORIGINAL')
            found[role] = (path, digest, raw)
    contract = plan.get('p345_evidence_contract', {})
    pins = contract.get('original_artifact_sha256', {}) if type(contract) is dict else {}
    if type(pins) is not dict:
        pins = {}
    def original(role):
        item = found.get(role)
        return (item[2] if item and item[0].lower().endswith('.glb')
                and pins.get(role) == item[1] and sha(item[2]) == item[1]
                else None)
    native = original('NATIVE_EXPORT')
    reference = original('P3_APPROVED_REFERENCE')
    reference_required = rule_id != 'AAA-200-L-111'
    complete = native is not None and (not reference_required or reference is not None)
    metrics = geometry(native) if native is not None else []
    total = lambda field: sum(row[field] for row in metrics)
    original_reference = geometry(reference) if reference is not None else []
    welded = _geometric_topology(native) if native is not None else None
    # Compare complete original face multisets. Geometry with different
    # winding is intentionally distinct for the surface-orientation rule.
    reference_matches = bool(native and reference and
        _faces(native) == _faces(reference))
    oriented_matches = bool(reference_matches and
        _faces(native, oriented=True) == _faces(reference, oriented=True))
    normal_complete, normal_aligned = (
        _normal_consistency(native) if native is not None else (False, False))
    checks = {
        'AAA-200-L-111': {
            'all_original_mesh_primitives_topologically_inspected': bool(metrics),
            'original_mesh_edges_no_nonmanifold_or_degenerate': bool(metrics)
                and welded['nonmanifold_edges'] == 0
                and welded['degenerate_faces'] == 0
                and total('nonmanifold_edges') == 0,
            'original_mesh_faces_unique': bool(metrics)
                and welded['duplicate_faces'] == 0,
        },
        'AAA-200-L-113': {
            'all_original_triangle_areas_independently_recomputed': bool(metrics),
            'no_original_degenerate_or_duplicate_faces': bool(metrics)
                and welded['degenerate_faces'] == 0
                and welded['duplicate_faces'] == 0,
            'original_geometry_matches_source_pinned_reference': reference_matches,
        },
        'AAA-200-L-114': {
            'all_original_vertex_normals_finite_and_unit_length': normal_complete,
            'every_original_vertex_normal_matches_face_orientation': normal_aligned,
            'original_face_orientation_matches_source_pinned_reference':
                oriented_matches,
        },
    }[rule_id]
    require(set(checks) == set(CRITERIA[rule_id])
            and all(type(value) is bool for value in checks.values()),
            'C07_TOPOLOGY_REVIEW_PER_LITERAL_CRITERIA_CHANGED')
    return {'checks': checks, 'evidence_complete': bool(complete),
            'native_sha256': sha(native) if native is not None else None,
            'reference_sha256': sha(reference) if reference is not None else None,
            'geometric_topology': welded,
            'original_audit_sha256': audit_sha, 'original_audit_tail': tail,
            'attempt_id': work['attempt_id'],
            'operation_sha256': work['operation_sha256'],
            'mg0': 'UNKNOWN', 'advancement_authorized': False}
