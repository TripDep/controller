"""C07 P1 residual family: original-byte visual, spatial and QA measurements.

Thirteen distinct P1 literals are replayed on the *same* Controller operation.
Pixels, triangles and original pre-D policies are independently re-opened.
These measurable predicates are NOT aesthetic judgement, authenticated renderer
provenance, owner approval, MG0, or complete positive semantic acceptance.
"""
import hashlib
import math
from pathlib import Path

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p1_thirty_native_domain import inspect as p1_inspect, jbytes
from c07_p6_collision_semantics import _triangles
from c07_p5_budget_semantics import _glb_parts
from visual_content_metrics import decode_grid, VisualContentBlocked

NUMBERS=tuple(range(31,41))+(46,56,57)
IDS=tuple('AAA-200-'+('D' if n<=40 else 'E' if n==46 else 'F')+'-%03d'%n
          for n in NUMBERS)
SCHEMA='c07-p1-thirteen-residual-source-specific-v1'
class ResidualP1Blocked(ValueError):pass
def need(ok,why):
    if not ok:raise ResidualP1Blocked(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def number(x):return type(x) in (int,float) and math.isfinite(x)
def xy(x):return type(x) is list and len(x)==2 and all(number(v) for v in x)
def rgb(x):return type(x) is list and len(x)==3 and all(
    type(v) is int and 0<=v<=255 for v in x)
def distance(a,b):return math.sqrt(sum((a[i]-b[i])**2 for i in range(3)))
def average(pixels):
    return tuple(sum(p[i] for p in pixels)/len(pixels) for i in range(3)) if pixels else None
def luma(p):return (p[0]*299+p[1]*587+p[2]*114)/1000
def inside(pt,poly):
    if not xy(pt) or type(poly) is not list or len(poly)<3 or not all(xy(p) for p in poly):return False
    hit=False;j=len(poly)-1
    for i in range(len(poly)):
        a,b=poly[i],poly[j]
        if (a[1]>pt[1])!=(b[1]>pt[1]):
            at=a[0]+(pt[1]-a[1])*(b[0]-a[0])/(b[1]-a[1])
            if pt[0]<at:hit=not hit
        j=i
    return hit
def mask_overlap(a,b):
    if a is None or b is None or a[:2]!=b[:2]:return None
    aa,bb=a[2],b[2]
    if not aa or len(aa)!=len(bb):return None
    base_a,base_b=aa[0],bb[0]
    ia=[distance(p,base_a)>18 for p in aa]
    ib=[distance(p,base_b)>18 for p in bb]
    union=sum(x or y for x,y in zip(ia,ib))
    return sum(x and y for x,y in zip(ia,ib))/union if union else None

def inspect_family(source_context):
    need(type(source_context) is dict and
         set(source_context)=={'inventory','plan','controller','asset','step','work','source_loader'},
         'C07_P1_RESIDUAL_TRUSTED_RULE_CONTEXT')
    inv,plan,controller,asset,step,work,loader=(source_context[k] for k in
        ('inventory','plan','controller','asset','step','work','source_loader'))
    need(callable(loader) and plan.get('phase')==work.get('phase'),
         'C07_P1_RESIDUAL_PHASE')
    # Re-check all 30 exact original canonical clauses before any rule verdict.
    p1_inspect(inv,plan,controller,asset,step,work,source_loader=loader)
    rows,tail,state,audit_sha=_original_attempt(inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'C07_P1_RESIDUAL_MASTER_AUDIT_MISMATCH')
    pins=plan.get('p1_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_P1_RESIDUAL_PRE_D_PIN_MAP')
    found={}
    for role,path,digest,raw in _registered_artifacts(rows,state,step,loader,work):
        need(role not in found,'C07_P1_RESIDUAL_DUPLICATE_ROLE')
        found[role]=(path,digest,raw)
    def original(role,ext=None):
        x=found.get(role)
        return x[2] if x and pins.get(role)==x[1] and sha(x[2])==x[1] and (
            ext is None or x[0].lower().endswith(ext)) else None
    policy_raw=original('P1_VISUAL_METRICS_POLICY','.json')
    policy=jbytes(policy_raw) if policy_raw is not None else {}
    scene_raw=original('P1_SCENE_CONTRACT','.json')
    scene=jbytes(scene_raw) if scene_raw is not None else {}
    paths_raw=original('P1_PATHS_GEOJSON','.json')
    paths=jbytes(paths_raw) if paths_raw is not None else {}
    qa_raw=original('P1_QA_REPORT','.json')
    qa=jbytes(qa_raw) if qa_raw is not None else {}
    native=original('NATIVE_EXPORT','.glb')
    tris=None;doc=None
    if native is not None:
        try:
            tris=_triangles(native)
            doc,_=_glb_parts(native)
        except (ValueError,KeyError,TypeError,IndexError,OverflowError):
            pass
    def pixels(role):
        raw=original(role,'.png')
        if raw is None:return None
        try:return decode_grid(raw,step=1)
        except (VisualContentBlocked,ValueError,IndexError,OverflowError):return None
    front=pixels('VISUAL_VIEW_FRONT')
    reference=pixels('REFERENCE_IMAGE')
    peer=pixels('SCENE_PEER_REFERENCE')
    material=pixels('IMAGE_MATERIAL')
    top=pixels('VISUAL_VIEW_TOP')
    def limit(name):return policy.get(name) if number(policy.get(name)) else None
    def comparable(a,b):
        return bool(a and b and a[:2]==b[:2] and a[2] and b[2])
    def means_close(a,b,key):
        lim=limit(key)
        return bool(lim is not None and lim>=0 and comparable(a,b)
                    and distance(average(a[2]),average(b[2]))<=lim)
    def diversity(a):
        return len(set(a[2])) if a else 0
    def bbox():
        if not tris:return None
        v=[p for tri in tris for p in tri]
        return ([min(p[i] for p in v) for i in range(3)],
                [max(p[i] for p in v) for i in range(3)])
    box=bbox()
    void=policy.get('void_polygon_xy')
    centroids=([[(t[0][i]+t[1][i]+t[2][i])/3 for i in range(2)] for t in tris]
               if tris else [])
    void_ratio=(sum(inside(c,void) for c in centroids)/len(centroids)
                if centroids and type(void) is list and len(void)>=3 else None)
    focal=policy.get('focal_xy')
    focal_contrast=None
    if front and xy(focal):
        w,h,p=front
        x,y=round(focal[0]*(w-1)),round(focal[1]*(h-1))
        if 0<=x<w and 0<=y<h:
            focal_contrast=luma(p[y*w+x])-sum(map(luma,p))/len(p)
    repeats=None
    if front:
        w,h,p=front
        repeats=sum(p[y*w:y*w+w]==p[(y-1)*w:y*w]
                    for y in range(1,h))/max(1,h-1)
    palette=policy.get('palette_rgb')
    palette_error=None
    if material and type(palette) is list and palette and all(rgb(x) for x in palette):
        palette_error=max(min(distance(p,c) for c in palette)
                          for p in material[2])
    names={m.get('name') for m in doc.get('meshes',[])
           if type(m) is dict and type(m.get('name')) is str} if doc else set()
    roles=policy.get('component_mesh_names')
    cam=policy.get('player_camera')
    player_height=limit('player_eye_height_m')
    camera_ok=bool(box and type(cam) is dict and player_height is not None and
        type(cam.get('position_xyz')) is list and len(cam['position_xyz'])==3 and
        all(number(v) for v in cam['position_xyz']) and
        abs(cam['position_xyz'][2]-(box[0][2]+player_height))<=0.01 and
        type(cam.get('target_xyz')) is list and len(cam['target_xyz'])==3 and
        all(number(v) and box[0][i]<=v<=box[1][i]
            for i,v in enumerate(cam['target_xyz'])))
    entries=policy.get('entry_exit_xy')
    features=paths.get('features')
    lines=([f['geometry']['coordinates'] for f in features
           if type(f) is dict and type(f.get('geometry')) is dict and
           f['geometry'].get('type')=='LineString' and
           type(f['geometry'].get('coordinates')) is list]
           if type(features) is list else [])
    endpoints=[point for line in lines if len(line)>=2
               for point in (line[0],line[-1]) if xy(point)]
    entry_ok=bool(type(entries) is dict and
        xy(entries.get('entrance')) and xy(entries.get('exit')) and
        entries['entrance']!=entries['exit'] and
        all(any(math.dist(pt,e)<=0.001 for e in endpoints)
            for pt in (entries['entrance'],entries['exit'])))
    qa_findings=qa.get('open_findings')
    audit_current=[(i,e) for i,e in enumerate(rows)
        if e.get('step')==step and e.get('attempt_id')==work['attempt_id']
        and e.get('operation_sha256')==work['operation_sha256']]
    blockout=[i for i,e in audit_current if e.get('event')=='BLOCKOUT_QA']
    details=[i for i,e in audit_current if e.get('event')=='DETAIL_STARTED']
    qa_order=bool(blockout and (not details or max(blockout)<min(details)))
    source_ok=bool(policy_raw and scene_raw and native and
                   policy.get('schema')=='c07-p1-visual-metrics-pre-d-v1')
    checks_by_number={
       31:(source_ok and reference is not None,means_close(front,reference,'max_style_rgb_distance')),
       32:(source_ok and peer is not None,means_close(front,peer,'max_peer_rgb_distance')),
       33:(source_ok and material is not None and palette_error is not None,
           palette_error is not None and limit('max_palette_rgb_distance') is not None
           and palette_error<=limit('max_palette_rgb_distance')),
       34:(source_ok and box is not None and void_ratio is not None,
           void_ratio is not None and limit('max_void_triangle_fraction') is not None
           and void_ratio<=limit('max_void_triangle_fraction')),
       35:(source_ok and comparable(front,reference),mask_overlap(front,reference) is not None
           and limit('min_silhouette_iou') is not None and
           mask_overlap(front,reference)>=limit('min_silhouette_iou')),
       36:(source_ok and focal_contrast is not None,focal_contrast is not None
           and limit('min_focal_luma_contrast') is not None and
           focal_contrast>=limit('min_focal_luma_contrast')),
       37:(source_ok and repeats is not None,repeats is not None and
           limit('max_repeated_row_fraction') is not None and
           repeats<=limit('max_repeated_row_fraction')),
       38:(source_ok and material is not None,
           limit('min_distinct_material_rgb') is not None and
           diversity(material)>=limit('min_distinct_material_rgb')),
       39:(source_ok and front is not None and box is not None,camera_ok),
       40:(source_ok and doc is not None and type(roles) is list and bool(roles),
           bool(roles) and len(set(roles))==len(roles) and
           all(type(x) is str and x in names for x in roles)),
       46:(source_ok and paths_raw is not None and box is not None,entry_ok),
       56:(source_ok and front is not None and top is not None,
           bool(front and top and front[:2]==top[:2] and front[2]!=top[2]
                and type(scene.get('cameras')) is dict and
                len(scene['cameras'])>=4)),
       57:(source_ok and qa_raw is not None and type(qa_findings) is list
           and bool(qa_findings),qa_order),
    }
    need(set(checks_by_number)==set(NUMBERS) and
         all(len(v)==2 and all(type(x) is bool for x in v)
             for v in checks_by_number.values()),
         'C07_P1_RESIDUAL_EXACT_FAMILY_CHECKS')
    names=('pre_d_policy_and_current_original_bytes_reopened',
           'rule_specific_original_measurement_within_pre_d_contract')
    results={}
    for n,checks in checks_by_number.items():
        rid='AAA-200-'+('D' if n<=40 else 'E' if n==46 else 'F')+'-%03d'%n
        results[rid]={'schema':SCHEMA,'rule_id':rid,
            'checks':dict(zip(names,checks)),
            'metrics':{'void_triangle_fraction':void_ratio if n==34 else None,
                       'palette_max_rgb_error':palette_error if n==33 else None,
                       'silhouette_iou':mask_overlap(front,reference) if n==35 else None,
                       'focal_luma_contrast':focal_contrast if n==36 else None,
                       'repeated_row_fraction':repeats if n==37 else None},
            'full_rule_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
            'owner_acceptance':'UNKNOWN','fivem_runtime':'UNKNOWN',
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'advancement_authorized':False}
    return {'schema':SCHEMA,'family_rule_count':30,'rule_count':13,
        'rules':results,'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'original_audit_sha256':audit_sha,'original_audit_tail':tail,
        'full_semantic_passes':0,'individual_mg0_passes':0,
        'advancement_authorized':False}

def inspect(source_context,rule_id):
    need(rule_id in IDS,'C07_P1_RESIDUAL_UNKNOWN_RULE')
    return inspect_family(source_context)['rules'][rule_id]
