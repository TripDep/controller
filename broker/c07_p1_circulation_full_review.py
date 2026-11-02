"""E-046: original-source sightlines, entrances and exits as one P1 semantic.

Three independent proof dimensions: pre-D access/view contract, actual original
path/access topology, and real GLB triangle ray occlusion. No producer labels,
PNG names or signed PASS can certify geometry, owner, MG0 or FiveM runtime.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p1_thirty_native_domain import inspect as inspect_p1, jbytes
from c07_p1_paths_access_full_review import (
    inspect as inspect_access, polygon, on_segment)
from c07_p6_collision_semantics import _triangles
from c07_native_output_oracle import read_mesh_geometry

RULE = 'AAA-200-E-046'
CRITERIA = (
    'original_pre_d_entrance_exit_view_policy_and_native_source_sha_pinned',
    'both_real_path_endpoints_connected_and_inside_original_accessible_zone',
    'original_camera_faces_both_access_points_with_unobstructed_native_triangle_sightlines',
)
EPS=1e-8

class OriginalCirculationBlocked(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise OriginalCirculationBlocked(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def number(v):
    return type(v) in (int, float) and math.isfinite(v)

def vec(v, n):
    return type(v) is list and len(v)==n and all(number(x) for x in v)

def dot(a,b):
    return sum(x*y for x,y in zip(a,b))

def sub(a,b):
    return [x-y for x,y in zip(a,b)]

def cross(a,b):
    return [a[1]*b[2]-a[2]*b[1],
            a[2]*b[0]-a[0]*b[2], a[0]*b[1]-a[1]*b[0]]

def _blocked(origin,target,tri):
    """Moller-Trumbore interior segment/triangle intersection, double sided."""
    a,b,c=tri
    d=sub(target,origin)
    edge1=sub(b,a);edge2=sub(c,a)
    p=cross(d,edge2);det=dot(edge1,p)
    if abs(det)<=EPS:
        return False
    inv=1/det;from_origin=sub(origin,a)
    u=dot(from_origin,p)*inv
    if u < -EPS or u > 1+EPS:return False
    q=cross(from_origin,edge1)
    v=dot(d,q)*inv
    if v < -EPS or u+v > 1+EPS:return False
    t=dot(edge2,q)*inv
    return EPS < t < 1-EPS

def _in_zone(p, vertices):
    """Boundary-inclusive planar polygon point containment."""
    if not vec(p,2) or vertices is None:
        return False
    x,y=p;inside=False
    for a,b in zip(vertices,vertices[1:]+vertices[:1]):
        if on_segment(a,b,p):return True
        if (a[1]>y)!=(b[1]>y):
            at=a[0]+(y-a[1])*(b[0]-a[0])/(b[1]-a[1])
            if at > x:inside=not inside
    return inside

def inspect(source_context, rule_id):
    need(rule_id==RULE and type(source_context) is dict and
         set(source_context)=={
             'inventory','plan','controller','asset',
             'step','work','source_loader'},
         'C07_E046_EXACT_RULE_CONTEXT_REQUIRED')
    inv,plan,controller,asset,step,work,loader=(
        source_context[k] for k in ('inventory','plan','controller',
                                     'asset','step','work','source_loader'))
    need(type(plan) is dict and type(work) is dict and
         callable(loader) and plan.get('phase')==work.get('phase') and
         plan['phase'] in ('P1','P2','P3','P4','P5','P6','P7','P8'),
         'C07_E046_P1_OR_LATER_PHASE_REQUIRED')
    inspect_p1(inv,plan,controller,asset,step,work,source_loader=loader)
    rows,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'C07_E046_CURRENT_MASTER_AUDIT_UNTRUSTED')
    found={}
    for role,path,digest,raw in _registered_artifacts(
            rows,state,step,loader,work):
        need(role not in found,'C07_E046_DUPLICATE_SOURCE_ROLE')
        found[role]=(path,digest,raw)
    pins=plan.get('p1_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_E046_PRE_D_SOURCE_SHA_MAP_REQUIRED')
    def original(role,extension):
        item=found.get(role)
        if (item is None or not item[0].lower().endswith(extension) or
                pins.get(role)!=item[1] or sha(item[2])!=item[1]):
            return None
        return item[2]
    scene_raw=original('P1_SCENE_CONTRACT','.json')
    path_raw=original('P1_PATHS_GEOJSON','.json')
    policy_raw=original('P1_VISUAL_METRICS_POLICY','.json')
    native_raw=original('NATIVE_EXPORT','.glb')
    complete=all(x is not None for x in
                 (scene_raw,path_raw,policy_raw,native_raw))
    checks={key:False for key in CRITERIA}
    if not complete:
        return dict(rule_id=RULE,checks=checks,evidence_complete=False,
                    original_audit_sha256=audit_sha,
                    original_audit_tail=tail,
                    attempt_id=work['attempt_id'],
                    operation_sha256=work['operation_sha256'])
    scene=jbytes(scene_raw)
    paths=jbytes(path_raw)
    policy=jbytes(policy_raw)
    native=read_mesh_geometry(native_raw)
    triangles=_triangles(native_raw)
    footprint=scene.get('footprint_m')
    endpoints=policy.get('entry_exit_xy')
    camera=policy.get('player_camera')
    eye=policy.get('player_eye_height_m')
    aperture=policy.get('max_entry_exit_view_angle_deg')
    contract=bool(
        policy.get('schema')=='c07-p1-visual-metrics-pre-d-v1' and
        vec(footprint,2) and all(x>0 for x in footprint) and
        type(endpoints) is dict and set(endpoints)=={'entrance','exit'} and
        vec(endpoints['entrance'],2) and vec(endpoints['exit'],2) and
        endpoints['entrance']!=endpoints['exit'] and
        all(0<=p[i]<=footprint[i] for p in endpoints.values()
            for i in range(2)) and
        type(camera) is dict and
        vec(camera.get('position_xyz'),3) and
        vec(camera.get('target_xyz'),3) and
        number(eye) and 1.2<=eye<=2.2 and
        number(aperture) and 5<=aperture<=85 and
        native['triangles']==len(triangles) and len(triangles)>0)
    checks[CRITERIA[0]]=contract
    if contract:
        features=paths.get('features')
        zones=paths.get('zones')
        line_ends=[]
        if type(features) is list and features:
            for feature in features:
                geometry=feature.get('geometry') if type(feature) is dict else None
                vertices=geometry.get('coordinates') if type(geometry) is dict else None
                if (type(geometry) is not dict or
                        geometry.get('type')!='LineString' or
                        type(vertices) is not list or len(vertices)<2 or
                        not all(vec(p,2) for p in vertices)):
                    line_ends=[];break
                line_ends.extend((vertices[0],vertices[-1]))
        valid_zones=[]
        if type(zones) is list:
            for zone in zones:
                if type(zone) is dict and zone.get('access')=='ACCESSIBLE':
                    poly=polygon(zone.get('polygon'))
                    if poly is not None and 'pedestrian' in zone.get('allowed_actors',[]):
                        valid_zones.append(poly)
        try:
            topology=inspect_access(source_context,'AAA-200-E-044')
            access=inspect_access(source_context,'AAA-200-E-045')
            topology_ok=all(topology['checks'].values()) and all(
                access['checks'].values())
        except (ValueError,TypeError,KeyError,IndexError,AssertionError):
            topology_ok=False
        connected=bool(topology_ok and len(line_ends)>1 and valid_zones and
             all(any(math.dist(p,q)<=1e-5 for q in line_ends)
                 and any(_in_zone(p,zone) for zone in valid_zones)
                 for p in endpoints.values()))
        checks[CRITERIA[1]]=connected
        if connected:
            origin=camera['position_xyz']
            aim=sub(camera['target_xyz'],origin)
            norm=math.sqrt(dot(aim,aim))
            eye_z=native['bbox_min'][2]+eye
            view_ok=bool(norm>EPS and
                abs(origin[2]-eye_z)<=0.05 and
                not any(not all(number(v) for v in vertex)
                        for tri in triangles for vertex in tri))
            if view_ok:
                for point in endpoints.values():
                    target=[point[0],point[1],eye_z]
                    direction=sub(target,origin)
                    dist=math.sqrt(dot(direction,direction))
                    if (dist<EPS or dot(aim,direction)/(norm*dist) <
                            math.cos(math.radians(aperture)) or
                            any(_blocked(origin,target,t) for t in triangles)):
                        view_ok=False
                        break
            checks[CRITERIA[2]]=view_ok
    return dict(rule_id=RULE,checks=checks,evidence_complete=True,
                original_audit_sha256=audit_sha,original_audit_tail=tail,
                original_source_sha256={role:sha(raw) for role,raw in (
                    ('P1_SCENE_CONTRACT',scene_raw),
                    ('P1_PATHS_GEOJSON',path_raw),
                    ('P1_VISUAL_METRICS_POLICY',policy_raw),
                    ('NATIVE_EXPORT',native_raw))},
                attempt_id=work['attempt_id'],
                operation_sha256=work['operation_sha256'])
