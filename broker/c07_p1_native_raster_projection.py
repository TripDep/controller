"""P1 eleven residual rules: original GLB triangle projection against PNG pixels.

The machine independently rasterizes native geometry; it never trusts a
producer's screenshot QA flag. Source-scoped only: artistic acceptance, actual
renderer provenance, MG0 and FiveM remain UNKNOWN.
"""
import hashlib
import math
from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p1_thirty_native_domain import inspect as p1_inspect,jbytes
from c07_p6_collision_semantics import _triangles
from c07_native_output_oracle import read_mesh_geometry
from c07_camera_views_full_review import direction_ok
from visual_content_metrics import decode_grid,VisualContentBlocked

NUMBERS=tuple(range(31,41))+(56,)
IDS=tuple('AAA-200-'+('D' if n<=40 else 'F')+'-%03d'%n for n in NUMBERS)
VIEWS=('FRONT','LEFT','RIGHT','TOP')
class RasterReplayBlocked(ValueError):pass
def need(x,msg):
    if not x:raise RasterReplayBlocked(msg)
def sha(x):return hashlib.sha256(x).hexdigest()
def finite(x):return type(x) in (int,float) and math.isfinite(x)
def xyz(x):return type(x) is list and len(x)==3 and all(finite(v) for v in x)
def band(x,a,b):return finite(x) and a<=x<=b
def uv(role,p):
    return ((p[0],p[2]) if role=='FRONT' else
            (p[1],p[2]) if role=='LEFT' else
            (-p[1],p[2]) if role=='RIGHT' else (p[0],p[1]))
def mask_from_triangles(tris,role,w,h):
    """Project and rasterize the ORIGINAL triangle coordinates."""
    need(type(tris) is list and bool(tris) and
         type(w) is int and type(h) is int and
         8<=w<=256 and 8<=h<=256,'C07_P1_RASTER_SOURCE_OR_RESOLUTION')
    triangles=[[uv(role,p) for p in tri] for tri in tris]
    pts=[p for tri in triangles for p in tri]
    lo=[min(p[i] for p in pts) for i in (0,1)]
    hi=[max(p[i] for p in pts) for i in (0,1)]
    def px(p):
        return tuple((p[i]-lo[i])/max(hi[i]-lo[i],1e-9)*
                     ((w,h)[i]-1)*.8+((w,h)[i]-1)*.1 for i in (0,1))
    out=[False]*(w*h)
    for tri in triangles:
        a,b,c=[px(p) for p in tri]
        den=(b[1]-c[1])*(a[0]-c[0])+(c[0]-b[0])*(a[1]-c[1])
        if abs(den)<1e-8:continue
        for y in range(max(0,int(min(a[1],b[1],c[1]))),
                       min(h-1,int(max(a[1],b[1],c[1]))+1)):
            for x in range(max(0,int(min(a[0],b[0],c[0]))),
                           min(w-1,int(max(a[0],b[0],c[0]))+1)):
                u=((b[1]-c[1])*(x+.5-c[0])+(c[0]-b[0])*(y+.5-c[1]))/den
                v=((c[1]-a[1])*(x+.5-c[0])+(a[0]-c[0])*(y+.5-c[1]))/den
                if u>=-1e-7 and v>=-1e-7 and u+v<=1+1e-7:
                    out[y*w+x]=True
    return out
def iou(a,b):
    if not a or not b or len(a)!=len(b):return 0.
    union=sum(x or y for x,y in zip(a,b))
    return sum(x and y for x,y in zip(a,b))/union if union else 0.
def decoded(raw,w,h,bg):
    if raw is None:return None
    try:rw,rh,pixels=decode_grid(raw,step=1)
    except (VisualContentBlocked,ValueError,TypeError):return None
    if (rw,rh)!=(w,h):return None
    return {'pixels':pixels,'mask':[max(abs(p[k]-bg[k])
            for k in range(3))>24 for p in pixels],'sha':sha(raw)}
def mean(p):
    return tuple(sum(x[i] for x in p)/len(p) for i in range(3))
def inspect_family(ctx):
    need(type(ctx) is dict and set(ctx)=={'inventory','plan','controller',
        'asset','step','work','source_loader'},'C07_P1_RASTER_TRUSTED_CONTEXT')
    inv,plan,controller,asset,step,work,loader=(
        ctx[k] for k in ('inventory','plan','controller','asset','step',
                         'work','source_loader'))
    p1_inspect(inv,plan,controller,asset,step,work,source_loader=loader)
    audit,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'C07_P1_RASTER_CURRENT_MASTER_OR_AUDIT')
    records={}
    for role,path,digest,raw in _registered_artifacts(
            audit,state,step,loader,work):
        need(role not in records,'C07_P1_RASTER_DUPLICATE_ROLE')
        records[role]=(path,digest,raw)
    pins=plan.get('p1_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_P1_RASTER_PRE_D_SHA')
    def original(role,ext):
        row=records.get(role)
        return row[2] if row and row[0].lower().endswith(ext) and (
            pins.get(role)==row[1] and sha(row[2])==row[1]) else None
    policy_raw=original('P1_NATIVE_RASTER_POLICY','.json')
    policy=jbytes(policy_raw) if policy_raw is not None else {}
    scene_raw=original('P1_SCENE_CONTRACT','.json')
    scene=jbytes(scene_raw) if scene_raw is not None else {}
    native=original('NATIVE_EXPORT','.glb')
    tris=_triangles(native) if native is not None else []
    bounds=read_mesh_geometry(native) if native is not None else None
    w,h=policy.get('width'),policy.get('height')
    bg=policy.get('background_rgb')
    valid=bool(policy_raw and scene_raw and native and bounds and
        policy.get('schema')=='c07-p1-native-raster-pre-d-v1' and
        type(w) is int and type(h) is int and 8<=w<=256 and 8<=h<=256 and
        xyz(bg) and all(band(v,0,255) for v in bg))
    pictures={}
    projected={}
    if valid:
        for role in VIEWS:
            pictures[role]=decoded(original('VISUAL_VIEW_'+role,'.png'),w,h,bg)
            projected[role]=mask_from_triangles(tris,role,w,h)
    ref=decoded(original('REFERENCE_IMAGE','.png'),w,h,bg) if valid else None
    peer=decoded(original('SCENE_PEER_REFERENCE','.png'),w,h,bg) if valid else None
    front=pictures.get('FRONT')
    fmask=front['mask'] if front else []
    threshold=policy.get('min_projection_iou')
    limit_ok=band(threshold,.5,1)
    match={r:bool(limit_ok and pictures.get(r) and
          iou(pictures[r]['mask'],projected[r])>=threshold)
          for r in VIEWS} if valid else {r:False for r in VIEWS}
    def compare(a,b,key):
        lim=policy.get(key)
        return bool(a and b and band(lim,0,441.7) and
            math.dist(mean(a['pixels']),mean(b['pixels']))<=lim)
    fore=[p for p,m in zip(front['pixels'],fmask) if m] if front else []
    swatches=policy.get('palette_rgb')
    pal=bool(fore and type(swatches) is list and swatches and
        all(xyz(x) and all(band(v,0,255) for v in x) for x in swatches)
        and band(policy.get('max_palette_distance'),0,441.7) and
        all(min(math.dist(p,x) for x in swatches)<=
            policy['max_palette_distance'] for p in fore))
    fill=sum(fmask)/len(fmask) if fmask else 0.
    fill_range=policy.get('solid_fraction_range')
    solid=bool(type(fill_range) is list and len(fill_range)==2 and
        all(band(x,0,1) for x in fill_range) and
        fill_range[0]<=fill<=fill_range[1] and match['FRONT'])
    focal=policy.get('focal_xyz')
    focal_ok=False
    if valid and xyz(focal) and front:
        pts=[uv('FRONT',p) for tri in tris for p in tri]
        lo=[min(p[i] for p in pts) for i in (0,1)]
        hi=[max(p[i] for p in pts) for i in (0,1)]
        q=uv('FRONT',focal)
        x=round((q[0]-lo[0])/max(hi[0]-lo[0],1e-9)*(w-1)*.8+(w-1)*.1)
        y=round((q[1]-lo[1])/max(hi[1]-lo[1],1e-9)*(h-1)*.8+(h-1)*.1)
        focal_ok=bool(0<=x<w and 0<=y<h and fmask[y*w+x])
    sig=[tuple(sorted(tuple(round(v,6) for v in p) for p in tri))
         for tri in tris]
    repeat=bool(sig and band(policy.get('max_duplicate_triangle_ratio'),0,1)
        and 1-len(set(sig))/len(sig)<=policy['max_duplicate_triangle_ratio'])
    diverse=bool(fore and type(policy.get('min_foreground_colors')) is int
        and len(set(fore))>=policy['min_foreground_colors']>=2)
    eye=policy.get('player_eye_xyz')
    eye_ok=bool(xyz(eye) and bounds and
        band(policy.get('player_eye_tolerance_m'),0,1) and
        finite(scene.get('player_height_m')) and
        abs(eye[2]-scene['player_height_m'])<=policy['player_eye_tolerance_m']
        and eye[1]<bounds['bbox_min'][1]-.5 and match['FRONT'])
    mesh_roles=policy.get('component_mesh_roles')
    mesh_ok=bool(type(mesh_roles) is dict and mesh_roles and bounds and
        len(mesh_roles)==bounds['mesh_definitions'] and
        len(set(mesh_roles.values()))==len(mesh_roles) and
        all(type(k) is str and k.strip() and type(v) is int and
            0<=v<bounds['mesh_definitions'] for k,v in mesh_roles.items())
        and match['FRONT'])
    cams=policy.get('cameras')
    cams_ok=bool(bounds and type(cams) is dict and set(cams)==set(VIEWS)
        and all(type(cams[r]) is dict and
            direction_ok('VISUAL_VIEW_'+r,cams[r],bounds) for r in VIEWS))
    four=bool(cams_ok and all(match.values()) and
        all(pictures.get(r) for r in VIEWS) and
        len({pictures[r]['sha'] for r in VIEWS})==4)
    predicates={
       31:(ref is not None,compare(ref,front,'max_reference_rgb_delta'),
           bool(ref and match['FRONT'] and limit_ok and
                iou(ref['mask'],fmask)>=threshold)),
       32:(peer is not None,compare(peer,front,'max_peer_rgb_delta'),
           bool(peer and match['FRONT'] and limit_ok and
                iou(peer['mask'],fmask)>=threshold)),
       33:(bool(swatches),pal,bool(pal and match['FRONT'])),
       34:(bool(tris),solid,bool(solid and sum(projected['FRONT'])>0) if valid else False),
       35:(front is not None,match['FRONT'],bool(match['FRONT'] and sum(fmask)>0)),
       36:(xyz(focal),focal_ok,bool(focal_ok and match['FRONT'])),
       37:(bool(tris),repeat,bool(repeat and match['FRONT'])),
       38:(front is not None,diverse,bool(diverse and pal and match['FRONT'])),
       39:(xyz(eye),eye_ok,bool(eye_ok and cams_ok)),
       40:(bool(mesh_roles),mesh_ok,bool(mesh_ok and match['FRONT'])),
       56:(bool(cams),cams_ok,four),
    }
    out={}
    for n,vals in predicates.items():
        rid='AAA-200-'+('D' if n<=40 else 'F')+'-%03d'%n
        checks={rid+'_pre_d_original':bool(valid and vals[0]),
                rid+'_native_projection':bool(valid and vals[1]),
                rid+'_cross_source':bool(valid and vals[2])}
        out[rid]={'rule_id':rid,'source_sha256':inv['rules'][rid]['source_sha256'],
            'requirement_sha256':inv['rules'][rid]['requirement_sha256'],
            'checks':checks,'source_observed':all(checks.values()),
            'full_rule_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
            'independent_renderer':'UNKNOWN','owner_acceptance':'UNKNOWN',
            'advancement_authorized':False}
    need(set(out)==set(IDS),'C07_P1_RASTER_EXACT_RESIDUAL_FAMILY')
    return {'schema':'c07-p1-eleven-original-raster-v1',
        'family_rule_count':30,'rule_count':11,'rules':out,
        'attempt_id':work['attempt_id'],'operation_sha256':work['operation_sha256'],
        'original_audit_sha256':audit_sha,'original_audit_tail':tail,
        'full_semantic_passes':0,'individual_mg0_passes':0,
        'advancement_authorized':False}
