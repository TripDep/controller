"""P6 P-156: source-specific invisible-collision geometry replay.

Every collision triangle is measured against original visible triangles, not
a producer's 'no invisible collision' label. Engine physics remains UNKNOWN.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p6_collision_semantics import inspect as collision_inspect, _triangles
from c07_p5_budget_semantics import _json

RULE = 'AAA-200-P-156'
CRITERIA = (
    'pre_d_invisible_collision_tolerance_and_original_exports_sha_pinned',
    'every_original_collision_triangle_normal_matches_a_visual_surface',
    'every_original_collision_triangle_vertex_and_centroid_on_visible_original_geometry',
)

class InvisibleCollisionBlocked(ValueError):
    pass

def need(ok,reason):
    if not ok:
        raise InvisibleCollisionBlocked(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def sub(a,b):
    return tuple(a[i]-b[i] for i in range(3))

def dot(a,b):
    return sum(a[i]*b[i] for i in range(3))

def cross(a,b):
    return (a[1]*b[2]-a[2]*b[1],
            a[2]*b[0]-a[0]*b[2],
            a[0]*b[1]-a[1]*b[0])

def norm(a):
    return math.sqrt(dot(a,a))

def unit_normal(tri):
    n = cross(sub(tri[1],tri[0]),sub(tri[2],tri[0]))
    m = norm(n)
    return tuple(x/m for x in n) if m>1e-12 else None

def segment_distance(p,a,b):
    d=sub(b,a)
    dd=dot(d,d)
    if dd<=1e-20:
        return norm(sub(p,a))
    t=max(0,min(1,dot(sub(p,a),d)/dd))
    return norm(sub(p,tuple(a[i]+t*d[i] for i in range(3))))

def surface_distance(p,tri):
    a,b,c=tri
    ab,ac=sub(b,a),sub(c,a)
    n=cross(ab,ac)
    n2=dot(n,n)
    if n2<=1e-20:
        return min(segment_distance(p,a,b),segment_distance(p,b,c),
                   segment_distance(p,c,a))
    signed=dot(sub(p,a),n)/n2
    projected=tuple(p[i]-signed*n[i] for i in range(3))
    v=sub(projected,a)
    d00,d01,d11=dot(ab,ab),dot(ab,ac),dot(ac,ac)
    d20,d21=dot(v,ab),dot(v,ac)
    den=d00*d11-d01*d01
    if den>1e-20:
        u=(d11*d20-d01*d21)/den
        w=(d00*d21-d01*d20)/den
        if u>=-1e-9 and w>=-1e-9 and u+w<=1+1e-9:
            return abs(dot(sub(p,a),n))/math.sqrt(n2)
    return min(segment_distance(p,a,b),segment_distance(p,b,c),
               segment_distance(p,c,a))

def inspect(source_context,rule_id):
    need(type(source_context) is dict and rule_id==RULE,
         'C07_P156_RULE_OR_CONTEXT')
    inv,plan,controller,asset,step,work,loader=(
        source_context[k] for k in
        ('inventory','plan','controller','asset','step','work','source_loader'))
    collision_inspect(inv,plan,controller,asset,step,work,
                      source_loader=loader)
    rows,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    records=_registered_artifacts(rows,state,step,loader,work)
    found={}
    for role,path,digest,raw in records:
        need(role not in found,'C07_P156_DUPLICATE_SOURCE_ROLE')
        found[role]=(path,digest,raw)
    pins=plan.get('p678_evidence_contract',{}).get(
        'original_artifact_sha256',{})
    need(type(pins) is dict,'C07_P156_PRE_D_PIN_SCHEMA')
    def original(role,extension):
        row=found.get(role)
        if (row is None or not row[0].lower().endswith(extension) or
                pins.get(role)!=row[1] or sha(row[2])!=row[1]):
            return None
        return row[2]
    c_raw=original('COLLISION_EXPORT','.glb')
    v_raw=original('NATIVE_EXPORT','.glb')
    p_raw=original('P6_COLLISION_POLICY','.json')
    policy=_json(p_raw) if p_raw is not None else {}
    tol=policy.get('max_invisible_collision_distance_m')
    pre_d=bool(c_raw and v_raw and p_raw and
               type(tol) in (int,float) and math.isfinite(tol)
               and 0<tol<=0.05 and
               policy.get('invisible_collision_exemptions')==[])
    complete=bool(c_raw and v_raw and p_raw)
    normals_ok=False
    surfaces_ok=False
    triangle_count=0
    if pre_d:
        collision=_triangles(c_raw)
        visible=_triangles(v_raw)
        triangle_count=len(collision)
        visible_normals=[unit_normal(tri) for tri in visible]
        collision_normals=[unit_normal(tri) for tri in collision]
        normals_ok=bool(collision and visible and
            all(n is not None for n in collision_normals) and
            all(n is not None for n in visible_normals) and
            all(any(abs(dot(n,m))>=0.95 for m in visible_normals)
                for n in collision_normals))
        surfaces_ok=bool(normals_ok and all(
            all(min(surface_distance(p,tri) for tri,nv in
                    zip(visible,visible_normals)
                    if abs(dot(collision_normals[i],nv))>=0.95) <= tol
                for p in list(c_tri)+[
                    tuple(sum(vertex[k] for vertex in c_tri)/3
                          for k in range(3))])
            for i,c_tri in enumerate(collision)))
    checks=dict(zip(CRITERIA,(pre_d,normals_ok,surfaces_ok)))
    return {'rule_id':rule_id,'checks':checks,
            'evidence_complete':complete,
            'original_collision_triangle_count':triangle_count,
            'original_collision_sha256':sha(c_raw) if c_raw else None,
            'original_visible_sha256':sha(v_raw) if v_raw else None,
            'original_policy_sha256':sha(p_raw) if p_raw else None,
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256']}
