"""F056 original-source multi-view GLB camera replay: five cardinal perspectives.

Actual native triangles are projected and occlusion-tested independently;
original capture rasters are separately decoded. This proves a geometric
inspection, NOT trusted render provenance, artistic quality, MG0, or FiveM.
"""
import hashlib
import math
from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p1_thirty_native_domain import inspect as inspect_p1,jbytes
from c07_p6_collision_semantics import _triangles
from visual_content_metrics import decode_grid, VisualContentBlocked

RULE='AAA-200-F-056'
VIEWS=('FRONT','REAR','LEFT','RIGHT','TOP')
CRITERIA=('five_pre_d_camera_poses_and_original_sha_sources_authenticated',
 'five_distinct_original_triangle_visibility_projections_measured',
 'five_cardinal_including_top_views_have_decoded_distinct_original_rasters')
AXES=((0,-1,0),(0,1,0),(-1,0,0),(1,0,0),(0,0,1))
class FiveViewsBlocked(ValueError):pass
def need(v,why):
    if not v:raise FiveViewsBlocked(why)
def sha(b):return hashlib.sha256(b).hexdigest()
def finite(x):return type(x) in (int,float) and math.isfinite(x)
def vec(x):return type(x) is list and len(x)==3 and all(finite(v) for v in x)
def sub(a,b):return [a[k]-b[k] for k in range(3)]
def dot(a,b):return sum(a[k]*b[k] for k in range(3))
def cross(a,b):
    return (a[1]*b[2]-a[2]*b[1],a[2]*b[0]-a[0]*b[2],
            a[0]*b[1]-a[1]*b[0])
def size(a):return math.sqrt(dot(a,a))
def unit(a):
    n=size(a)
    return [x/n for x in a] if n>1e-7 else None
def hit(a,b,t):
    """Moller-Trumbore source triangle occlusion, excluding endpoints."""
    d=sub(b,a);e1=sub(t[1],t[0]);e2=sub(t[2],t[0])
    h=cross(d,e2);det=dot(e1,h)
    if abs(det)<1e-9:return False
    inv=1/det;s=sub(a,t[0]);u=dot(s,h)*inv
    if not -1e-8<=u<=1+1e-8:return False
    q=cross(s,e1);v=dot(d,q)*inv
    if v < -1e-8 or u+v > 1+1e-8:return False
    distance=dot(e2,q)*inv
    return 1e-5<distance<1-1e-5

def inspect(ctx,rid):
    need(rid==RULE and type(ctx) is dict and set(ctx)=={
      'inventory','plan','controller','asset','step','work','source_loader'},
      'C07_F056_TRUSTED_ORIGINAL_CONTEXT')
    inv,plan,controller,asset,step,work,loader=(
      ctx[k] for k in ('inventory','plan','controller','asset',
                       'step','work','source_loader'))
    need(plan.get('phase')==work.get('phase') and
         plan.get('phase') in ('P1','P2','P3','P4','P5','P6','P7','P8')
         and callable(loader),'C07_F056_ORIGINAL_PHASE')
    inspect_p1(inv,plan,controller,asset,step,work,source_loader=loader)
    audit,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256']
         and state.get('last_audit_hash')==tail
         and (state.get('active_step') or {}).get('step')==step,
         'C07_F056_CURRENT_MASTER_OR_AUDIT')
    found={}
    for role,path,digest,raw in _registered_artifacts(
        audit,state,step,loader,work):
        need(role not in found,'C07_F056_DUPLICATE_ROLE')
        found[role]=(path,digest,raw)
    pins=plan.get('p1_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_F056_PRE_D_SOURCE_PINS')
    def original(role,ext):
        a=found.get(role)
        return a[2] if a and a[0].lower().endswith(ext) and (
           pins.get(role)==a[1] and sha(a[2])==a[1]) else None
    mesh=original('NATIVE_EXPORT','.glb')
    policy_bytes=original('P1_FIVE_VIEW_INSPECTION_POLICY','.json')
    images={v:original('VISUAL_VIEW_'+v,'.png') for v in VIEWS}
    checks={c:False for c in CRITERIA}
    evidence=bool(mesh and policy_bytes and all(images.values()))
    if not evidence:
        return {'rule_id':RULE,'checks':checks,'evidence_complete':False,
            'original_audit_sha256':audit_sha,
            'attempt_id':work['attempt_id'],'operation_sha256':work['operation_sha256']}
    policy=jbytes(policy_bytes);cameras=policy.get('cameras')
    angle=policy.get('max_axis_deviation_deg')
    minimum=policy.get('min_visible_projected_area_m2')
    valid=bool(policy.get('schema')=='c07-p1-five-native-views-pre-d-v1'
         and type(cameras) is dict and set(cameras)==set(VIEWS)
         and finite(angle) and 0<angle<=30
         and finite(minimum) and 0<minimum<=10
         and all(type(cameras[v]) is dict and
           set(cameras[v])=={'position_xyz','target_xyz'} and
           vec(cameras[v]['position_xyz']) and
           vec(cameras[v]['target_xyz']) for v in VIEWS))
    checks[CRITERIA[0]]=valid
    report={}
    if valid:
        triangles=_triangles(mesh)
        need(bool(triangles),'C07_F056_EMPTY_ORIGINAL_MESH')
        vertices=[p for t in triangles for p in t]
        low=[min(p[k] for p in vertices) for k in range(3)]
        high=[max(p[k] for p in vertices) for k in range(3)]
        center=[(low[k]+high[k])*0.5 for k in range(3)]
        camera_dirs=[]
        for name,expected in zip(VIEWS,AXES):
            cam=cameras[name];position=cam['position_xyz']
            target=cam['target_xyz'];from_mesh=unit(sub(position,center))
            forward=unit(sub(target,position))
            aligned=bool(from_mesh and forward and
                dot(from_mesh,expected)>=math.cos(math.radians(angle)) and
                dot(forward,[-x for x in expected])>=
                  math.cos(math.radians(angle)) and
                all(low[k]-1e-5<=target[k]<=high[k]+1e-5 for k in range(3))
                and size(sub(position,center))>max(.25,.6*size(sub(high,low))))
            camera_dirs.append(from_mesh)
            visible=0;area=0.0
            if aligned:
                for i,t in enumerate(triangles):
                    centroid=[sum(p[k] for p in t)/3 for k in range(3)]
                    ray=unit(sub(position,centroid))
                    normal=cross(sub(t[1],t[0]),sub(t[2],t[0]))
                    projected=.5*abs(dot(normal,ray)) if ray else 0
                    if projected<=1e-8:continue
                    if any(hit(centroid,position,other)
                           for j,other in enumerate(triangles) if i!=j):
                        continue
                    visible+=1;area+=projected
            report[name]={'axis_aligned':aligned,'visible_faces':visible,
                          'projected_area_m2':area}
        unique=bool(all(camera_dirs) and
            all(dot(camera_dirs[i],camera_dirs[j])<.95
                for i in range(5) for j in range(i+1,5)))
        checks[CRITERIA[1]]=bool(unique and all(
            r['axis_aligned'] and r['visible_faces']>0
            and r['projected_area_m2']>=minimum for r in report.values()))
        if checks[CRITERIA[1]]:
            decoded=[]
            for raw in images.values():
                try:decoded.append(decode_grid(raw,step=1))
                except (VisualContentBlocked,ValueError,TypeError,KeyError,IndexError,OverflowError):
                    decoded.append(None)
            checks[CRITERIA[2]]=bool(all(decoded) and
                 len({tuple(x[2]) for x in decoded})==5)
    return {'rule_id':RULE,'checks':checks,'evidence_complete':True,
            'native_camera_projection_report':report,
            'original_audit_sha256':audit_sha,
            'original_source_sha256':{
                 'NATIVE_EXPORT':sha(mesh),
                 'P1_FIVE_VIEW_INSPECTION_POLICY':sha(policy_bytes),
                 **{'VISUAL_VIEW_'+v:sha(raw) for v,raw in images.items()}},
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'renderer_provenance':'UNVERIFIED','fivem_runtime':'UNVERIFIED',
            'advancement_authorized':False}
