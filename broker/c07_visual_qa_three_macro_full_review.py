"""C07 P3/P4/P8: three complete original-byte visual QA source replays.

L120 exact export-vs-original-approval reference; N138 four current-attempt
render-capture views; S181 six source views including underside and per-role
zero defect QA. Native triangles, not only PNG labels, must be visible along
every original camera ray. No renderer authentication, MG0 or owner acceptance.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p345_remaining_original_review import inspect as atlas
from c07_camera_views_full_review import inspect as views,VIEWS,TRACE
from c07_p6_collision_semantics import _triangles
from c07_p1_five_camera_native_review import cross,dot,sub,unit,hit
from c07_p1_thirty_native_domain import jbytes

L='AAA-200-L-120'
N='AAA-200-N-138'
S='AAA-200-S-181'
RULES=frozenset((L,N,S))
class ThreeVisualSourceBlocked(ValueError):pass
def need(ok,message):
    if not ok:raise ThreeVisualSourceBlocked(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()

def inspect(ctx,rule_id):
    need(rule_id in RULES and type(ctx) is dict and
         set(ctx)=={'inventory','plan','controller','asset','step','work','source_loader'},
         'C07_P345_P8_VISUAL_FULL_CONTEXT_REQUIRED')
    inv,plan,ctl,asset,step,work,loader=(
        ctx[k] for k in ('inventory','plan','controller','asset',
                         'step','work','source_loader'))
    base=atlas(ctx,rule_id) if rule_id==L else views(ctx,rule_id)
    audit,tail,state,audit_sha=_original_attempt(inv,plan,ctl,asset,step,work)
    need(base['original_audit_sha256']==audit_sha and
         base['original_audit_tail']==tail and
         sha(ctl.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail,
         'C07_P345_P8_VISUAL_FULL_MASTER_AUDIT_MISMATCH')
    key='p345_evidence_contract' if rule_id in (L,N) else 'p678_evidence_contract'
    pins=plan.get(key,{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_P345_P8_VISUAL_FULL_PRE_D_PINS')
    registered={}
    for role,path,digest,raw in _registered_artifacts(audit,state,step,loader,work):
        need(role not in registered,'C07_P345_P8_VISUAL_FULL_DUPLICATE_ROLE')
        registered[role]=(path,digest,raw)
    def original(role,ext):
        v=registered.get(role)
        return v[2] if (v and v[0].lower().endswith(ext) and
             pins.get(role)==v[1] and sha(v[2])==v[1]) else None
    native=original('NATIVE_EXPORT','.glb')
    checks=dict(base['checks'])
    complete=bool(native)
    measurements={}
    if rule_id==L:
        approved=original('P3_APPROVED_EXPORT','.glb')
        complete=bool(native and approved)
        # Byte identity is deliberately stricter than visual resemblance:
        # no changes to winding, UVs, normals, textures, materials or axes.
        identical=bool(complete and sha(native)==sha(approved))
        checks[list(checks)[-1]]=bool(identical)
        measurements={'approved_vs_current_source_byte_identity':identical}
    else:
        trace_raw=original(TRACE[rule_id],'.json')
        trace=jbytes(trace_raw) if trace_raw else {}
        frames=trace.get('frames')
        qa_raw=original('P8_VIEW_QA','.json') if rule_id==S else None
        qa=jbytes(qa_raw) if qa_raw else {}
        complete=bool(complete and trace_raw and
                      (rule_id==N or qa_raw))
        if type(frames) is list and len(frames)==len(VIEWS[rule_id]):
            cam_by_role={f.get('role'):f for f in frames if type(f) is dict}
        else:
            cam_by_role={}
        target=set(VIEWS[rule_id])
        geometrically_visible={}
        if complete and set(cam_by_role)==target:
            faces=_triangles(native)
            if 0<len(faces)<=25000:
                for role in VIEWS[rule_id]:
                    frame=cam_by_role[role]
                    pos=frame.get('position_xyz')
                    look=frame.get('forward_xyz')
                    visible=0;area=0.
                    if (type(pos) is list and len(pos)==3 and
                        all(type(x) in (int,float) and math.isfinite(x)
                            for x in pos) and
                        type(look) is list and len(look)==3):
                        for i,tri in enumerate(faces):
                            mid=[sum(p[k] for p in tri)/3 for k in range(3)]
                            towards=unit(sub(pos,mid))
                            normal=cross(sub(tri[1],tri[0]),sub(tri[2],tri[0]))
                            projected=abs(dot(normal,towards))*.5 if towards else 0
                            if projected<=1e-8:continue
                            if any(hit(mid,pos,other) for j,other in enumerate(faces)
                                   if i!=j):
                                continue
                            area+=projected;visible+=1
                    geometrically_visible[role]=(visible,area)
        coverage=bool(len(geometrically_visible)==len(target) and
                      all(visible>0 and area>1e-5
                          for visible,area in geometrically_visible.values()))
        qa_ok=bool(rule_id!=S or (
            qa.get('checked_roles') is not None and
            type(qa.get('defect_counts')) is dict and
            set(qa['defect_counts'])==target and
            all(type(v) is int and v==0 for v in qa['defect_counts'].values())))
        # Existing reader independently verifies authentic operation audit
        # render events, byte pins, decoded pixel uniqueness, cardinal poses
        # and P8 scope. This adds real original GLB visible surface coverage.
        checks[list(checks)[-1]]=bool(checks[list(checks)[-1]] and
                                      coverage and qa_ok)
        measurements={'source_native_projected_surface_coverage':
                       geometrically_visible,
                       'zero_defect_original_view_qa':qa_ok}
    need(len(checks)==3 and all(type(v) is bool for v in checks.values()),
         'C07_P345_P8_VISUAL_FULL_EXACT_CRITERIA')
    return {'rule_id':rule_id,'checks':checks,'evidence_complete':complete,
            'original_evidence':measurements,
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'render_provenance':'UNVERIFIED',
            'mg0':'UNVERIFIED','owner_approval':'UNVERIFIED',
            'fivem_runtime':'UNVERIFIED','advancement_authorized':False}
