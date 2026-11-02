"""C07 P6/P8 residual three-literal macro original-source semantics.

P155: every visual solid surface vertex must be supported by original collision
triangles, beyond region labels. P160: independent pre-D source frame budget
recomputed, still not FiveM physics. S190: six original views plus original
internal QA bindings and current-attempt unresolved critical firewall.
Source-only predicates NEVER equal owner/gameplay/MG0 attestation.
"""
import hashlib
import math
from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p678_residual_macro_replay import inspect as residual
from c07_p6_collision_semantics import _triangles
from c07_p1_thirty_native_domain import jbytes
from c07_p4_texture_semantics import rgba

P155='AAA-200-P-155'
P160='AAA-200-P-160'
S190='AAA-200-S-190'
RULES=frozenset((P155,P160,S190))
VIEWS=('FRONT','REAR','LEFT','RIGHT','TOP','UNDERSIDE')
PREDICATES={
 P155:('original_visual_and_collision_surface_vertices_sha_pinned',
       'every_original_visual_solid_vertex_has_real_collision_triangle_support',
       'collision_alignment_is_original_geometry_only_not_live_player_physics'),
 P160:('current_original_fivem_log_and_pre_d_perf_budget_sha_pinned',
       'numeric_original_frame_samples_within_pre_d_source_budget',
       'independent_actual_player_walk_collision_run_provenance'),
 S190:('original_internal_qa_native_and_six_view_sources_sha_pinned',
       'six_distinct_source_pixel_buffers_bound_to_original_qa_report',
       'independent_owner_delivery_and_defect_triage_attestation')}
class ResidualMacroBlocked(ValueError):pass
def need(x,msg):
    if not x:raise ResidualMacroBlocked(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def finite(x):return type(x) in (int,float) and math.isfinite(x)
def diff(a,b):return [a[i]-b[i] for i in range(3)]
def dot(a,b):return sum(a[i]*b[i] for i in range(3))
def cross(a,b):return [a[1]*b[2]-a[2]*b[1],
                        a[2]*b[0]-a[0]*b[2],
                        a[0]*b[1]-a[1]*b[0]]
def point_supported(point,tri,tolerance):
    a,b,c=tri
    u,v=diff(b,a),diff(c,a)
    n=cross(u,v)
    size=math.sqrt(dot(n,n))
    if size<=1e-10:return False
    distance=abs(dot(n,diff(point,a)))/size
    if distance>tolerance:return False
    # Barycentric witness from the actual original collision face,
    # not a broad AABB whose surface might have been cut away.
    w=diff(point,a);uu=dot(u,u);vv=dot(v,v);uv=dot(u,v)
    wu=dot(w,u);wv=dot(w,v);d=uu*vv-uv*uv
    if d<=1e-10:return False
    s=(wu*vv-wv*uv)/d;t=(wv*uu-wu*uv)/d
    return s>=-1e-6 and t>=-1e-6 and s+t<=1+1e-6

def inspect(ctx,rid):
    need(type(ctx) is dict and
         set(ctx)=={'inventory','plan','controller','asset',
                    'step','work','source_loader'} and rid in RULES,
         'C07_P678_THREE_TRUSTED_ORIGINAL_CONTEXT')
    inv,plan,ctl,asset,step,work,loader=(
         ctx[k] for k in ('inventory','plan','controller',
                          'asset','step','work','source_loader'))
    base=residual(ctx,rid)
    audit,tail,state,auditsha=_original_attempt(inv,plan,ctl,asset,step,work)
    need(base['original_audit_sha256']==auditsha and
         base['original_audit_tail']==tail and
         sha(ctl.master.read_bytes())==work['master_sha256']
         and state.get('last_audit_hash')==tail,
         'C07_P678_THREE_AUDIT_OR_MASTER_DRIFT')
    pins=plan.get('p678_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_P678_THREE_PRE_D_PIN_REQUIRED')
    found={}
    for role,path,digest,raw in _registered_artifacts(
            audit,state,step,loader,work):
        need(role not in found,'C07_P678_THREE_DUPLICATE_SOURCE')
        found[role]=(path,digest,raw)
    def source(role,ext):
        x=found.get(role)
        return x[2] if (x and x[0].lower().endswith(ext)
           and pins.get(role)==x[1] and sha(x[2])==x[1]) else None
    checks=[False,False,False]
    complete=False
    proof={}
    if rid==P155:
        native=source('NATIVE_EXPORT','.glb')
        collision=source('COLLISION_EXPORT','.glb')
        policy_raw=source('P6_COLLISION_POLICY','.json')
        complete=bool(native and collision and policy_raw)
        policy=jbytes(policy_raw) if policy_raw else {}
        tol=policy.get('max_solid_collision_surface_gap_m')
        valid=bool(complete and finite(tol) and 0<=tol<=.2)
        supported=False
        if valid:
            visuals=_triangles(native)
            proxies=_triangles(collision)
            supported=bool(visuals and proxies and len(visuals)<=50000
                and len(proxies)<=50000
                and all(point_supported(p,tri,tol)
                    for surface in visuals for p in surface for tri in proxies)
                    if False else False)
            # Per-vertex existence of a surface witness. Requiring one
            # collision triangle for all vertices is incorrect for tiling.
            supported=bool(visuals and proxies and
                all(any(point_supported(p,tri,tol) for tri in proxies)
                    for surface in visuals for p in surface))
        checks=[valid,supported,False]
        proof={'visual_collision_original_vertex_support':supported}
    elif rid==P160:
        log=source('FIVEM_COLLISION_RUNTIME_LOG','.log')
        policy_raw=source('P6_COLLISION_POLICY','.json')
        samples_raw=source('P6_WALKABILITY_RUNTIME_SAMPLES','.json')
        complete=bool(log and policy_raw and samples_raw)
        policy=jbytes(policy_raw) if policy_raw else {}
        samples=jbytes(samples_raw) if samples_raw else {}
        frames=samples.get('frame_ms_samples')
        limit=policy.get('max_fivem_frame_p95_ms')
        structural=bool(complete and
            type(frames) is list and 10<=len(frames)<=2000
            and all(finite(v) and 0<v<10000 for v in frames)
            and finite(limit) and 0<limit<=100
            and samples.get('log_sha256')==sha(log))
        within=bool(structural and
            sorted(frames)[math.ceil(len(frames)*.95)-1]<=limit)
        checks=[structural,within,False]
        proof={'producer_numeric_frame_budget_measured':within}
    else:
        native=source('NATIVE_EXPORT','.glb')
        qa_raw=source('P8_INTERNAL_QA','.json')
        pngs={v:source('VISUAL_VIEW_'+v,'.png') for v in VIEWS}
        complete=bool(native and qa_raw and all(pngs.values()))
        qa=jbytes(qa_raw) if qa_raw else {}
        pins_qa=qa.get('original_sha256')
        referenced=bool(complete and type(pins_qa) is dict and
            pins_qa.get('NATIVE_EXPORT')==sha(native) and
            all(pins_qa.get('VISUAL_VIEW_'+v)==sha(pngs[v]) for v in VIEWS))
        images=[]
        if referenced:
            try:images=[rgba(raw) for raw in pngs.values()]
            except (ValueError,TypeError,KeyError,IndexError):images=[]
        unique=bool(referenced and len(images)==6 and
            all(im and im['width']>1 and im['height']>1 for im in images)
            and len({im['pixel_sha256'] for im in images})==6
            and qa.get('owner_approved') is not True)
        checks=[referenced,unique,False]
        proof={'source_six_qa_pixel_buffers_distinct':unique}
    need(len(checks)==3 and checks[2] is False and
         all(type(v) is bool for v in checks),
         'C07_P678_THREE_NO_UNATTESTED_GAME_OR_OWNER_PASS')
    return {'rule_id':rid,'checks':dict(zip(PREDICATES[rid],checks)),
        'evidence_complete':complete,'original_evidence':proof,
        'full_rule_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
        'gameplay_provenance':'UNVERIFIED','owner_acceptance':'UNKNOWN',
        'advancement_authorized':False,'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'original_audit_sha256':auditsha,'original_audit_tail':tail}
