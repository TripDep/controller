"""C07 P4 six-rule N lighting/visual QA ORIGINAL-source macro.

N133..136 and N139..140 are independently recomputed as a coherent P4
review family. Input captures must have current Controller audit events with
exact registered SHA; camera/source geometry, pixel contrast, physical PBR,
and role-separated QA are measured, never inferred from producer labels.
Proof of renderer provenance, owner artistic acceptance and MG0 is absent:
these six remain NON-FULL candidates until independent external attestation.
"""
import hashlib
import math

from c07_p345_remaining_original_review import inspect as scoped
from c07_p345_remaining_original_review import rgb_different
from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p4_texture_semantics import rgba
from c07_p5_budget_semantics import _glb_parts
from c07_p6_collision_semantics import _triangles
from c07_p1_thirty_native_domain import jbytes

NUMBERS=(133,134,135,136,139,140)
RULES=frozenset('AAA-200-N-%03d'%n for n in NUMBERS)
CAPTURES={133:('LIGHT_NEUTRAL_VIEW',),
 134:('LIGHT_NEUTRAL_VIEW','LIGHT_DIRECT_VIEW','LIGHT_SHADOW_VIEW'),
 135:('LIGHT_NEUTRAL_VIEW','LIGHT_DIRECT_VIEW','LIGHT_SHADOW_VIEW'),
 136:('LIGHT_NEUTRAL_VIEW','REFLECTION_VIEW'),
 139:('VISUAL_VIEW_UNDERSIDE',),
 140:('LIGHT_NEUTRAL_VIEW','LIGHT_CINEMATIC_VIEW')}
CODES={
133:('neutral_current_capture_sha_matched','all_original_native_faces_valid',
     'defect_report_has_zero_measured_geometry_failures'),
134:('direct_shadow_neutral_original_capture_events_sha_matched',
     'all_original_light_buffers_have_distinct_measured_pixels',
     'source_light_response_has_physical_ramp_not_fabricated_label'),
135:('shadow_direct_neutral_original_capture_events_sha_matched',
     'original_shadow_pixel_channel_response_measured',
     'actual_shadow_has_consistent_luminance_below_neutral'),
136:('reflection_and_neutral_original_capture_events_sha_matched',
     'original_metallic_native_primitives_and_reflection_pixels_present',
     'actual_reflection_has_scene_color_contrast_not_identical_to_neutral'),
139:('underside_current_capture_and_qa_hashes_authenticated',
     'native_original_bottom_facing_nonzero_triangle_surface_measured',
     'underside_original_qa_findings_and_visibility_separately_covered'),
140:('neutral_and_cinematic_original_capture_events_sha_matched',
     'presentation_and_technical_review_original_evidence_distinct',
     'separate_original_qa_roles_and_reviewed_sha_traces_present')}
class OriginalLightMacroBlocked(ValueError):pass
def need(ok,reason):
    if not ok:raise OriginalLightMacroBlocked(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def number(x):return type(x) in (int,float) and math.isfinite(x)
def xyz(v):return type(v) is list and len(v)==3 and all(number(x) for x in v)

def inspect(ctx,rid):
    need(type(ctx) is dict and set(ctx)=={
        'inventory','plan','controller','asset','step','work','source_loader'}
        and rid in RULES,'C07_N_SIX_ORIGINAL_CONTROLLER_CONTEXT_REQUIRED')
    inv,plan,ctl,asset,step,work,loader=(
        ctx[k] for k in ('inventory','plan','controller',
                         'asset','step','work','source_loader'))
    base=scoped(ctx,rid)
    audit,tail,state,auditsha=_original_attempt(inv,plan,ctl,asset,step,work)
    need(base['original_audit_sha256']==auditsha and
         base['original_audit_tail']==tail and
         state.get('last_audit_hash')==tail and
         sha(ctl.master.read_bytes())==work['master_sha256'],
         'C07_N_SIX_CURRENT_AUDIT_SHA_REQUIRED')
    pins=plan.get('p345_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_N_SIX_PRE_D_PIN_REQUIRED')
    src={}
    for role,path,digest,raw in _registered_artifacts(
            audit,state,step,loader,work):
        need(role not in src,'C07_N_SIX_DUPLICATE_ORIGINAL_ROLE')
        src[role]=(path,digest,raw)
    def original(role,ext):
        r=src.get(role)
        return (r[2] if r and r[0].lower().endswith(ext)
                and pins.get(role)==r[1] and sha(r[2])==r[1] else None)
    n=int(rid[-3:])
    roles=CAPTURES[n]
    captures={role:original(role,'.png') for role in roles}
    frames={}
    complete=bool(all(captures.values()))
    for role,raw in captures.items():
        if raw is None:continue
        matched=[(idx,e) for idx,e in enumerate(audit) if
            e.get('event')=='RENDER_CAPTURED' and
            e.get('step')==step and e.get('attempt_id')==work['attempt_id']
            and e.get('operation_sha256')==work['operation_sha256']
            and e.get('source_role')==role and
            e.get('image_sha256')==sha(raw)]
        if len(matched)==1:frames[role]=matched[0]
    bound=bool(complete and len(frames)==len(roles))
    decoded={}
    if complete:
        try:
            for role,raw in captures.items():
                decoded[role]=rgba(raw)
        except (ValueError,TypeError,KeyError,IndexError,OverflowError):
            decoded={}
    native=original('NATIVE_EXPORT','.glb')
    mesh=_triangles(native) if native else []
    native_ok=bool(mesh and len(mesh)<=50000)
    pbr=False
    if native:
        doc,_=_glb_parts(native)
        mats=doc.get('materials',[])
        for node in doc.get('meshes',[]):
            for p in node.get('primitives',[]):
                mid=p.get('material')
                if type(mid) is int and 0<=mid<len(mats):
                    data=mats[mid].get('pbrMetallicRoughness',{})
                    if (number(data.get('metallicFactor')) and
                        number(data.get('roughnessFactor')) and
                        0<=data['metallicFactor']<=1 and
                        0<=data['roughnessFactor']<=1):
                        pbr=True
    face_measure=False
    bottom=False
    if native_ok:
        face_measure=True
        for tri in mesh:
            e1=[tri[1][i]-tri[0][i] for i in range(3)]
            e2=[tri[2][i]-tri[0][i] for i in range(3)]
            v=(e1[1]*e2[2]-e1[2]*e2[1],
               e1[2]*e2[0]-e1[0]*e2[2],
               e1[0]*e2[1]-e1[1]*e2[0])
            area=math.sqrt(sum(x*x for x in v))*.5
            if area<=1e-9 or not number(area):
                face_measure=False
            if v[2]<-1e-7 and area>1e-9:
                bottom=True
    def dif(a,b):
        x,y=decoded.get(a),decoded.get(b)
        return bool(x and y and rgb_different(x,y))
    def brighter(a,b):
        x,y=decoded.get(a),decoded.get(b)
        return bool(dif(a,b) and x['mean']>y['mean'])
    checks={}
    if n==133:
        report=jbytes(original('P4_GEOMETRY_DEFECT_REPORT','.json') or b'')
        actual_bad=sum(not (
             math.dist(t[0],t[1])>1e-9 and
             math.dist(t[1],t[2])>1e-9 and
             math.dist(t[2],t[0])>1e-9)
             for t in mesh)
        complete=bool(complete and native and report)
        checks=dict(zip(CODES[n],(
            bound,face_measure,
            bool(face_measure and report.get('degenerate_triangle_count')==0
                 and actual_bad==0 and
                 report.get('native_sha256')==sha(native)))))
    elif n in (134,135):
        complete=bool(complete and native and original('P4_LIGHTING_QA','.json'))
        light_ok=bool(bound and pbr and
             dif('LIGHT_DIRECT_VIEW','LIGHT_NEUTRAL_VIEW') and
             dif('LIGHT_SHADOW_VIEW','LIGHT_NEUTRAL_VIEW'))
        physically=bool(light_ok and
             brighter('LIGHT_DIRECT_VIEW','LIGHT_NEUTRAL_VIEW') and
             brighter('LIGHT_NEUTRAL_VIEW','LIGHT_SHADOW_VIEW'))
        checks=dict(zip(CODES[n],(bound,light_ok,physically)))
    elif n==136:
        complete=bool(complete and native and original('P4_MATERIAL_PLAN','.json'))
        checks=dict(zip(CODES[n],(
            bound,bool(pbr and dif('REFLECTION_VIEW','LIGHT_NEUTRAL_VIEW')),
            bool(bound and pbr and dif('REFLECTION_VIEW','LIGHT_NEUTRAL_VIEW')))))
    elif n==139:
        q=jbytes(original('P345_QA_REPORT','.json') or b'')
        complete=bool(complete and native and q)
        positions=[e for e in audit if
            e.get('event')=='UNDER_SIDE_REVIEWED' and
            e.get('step')==step and e.get('attempt_id')==work['attempt_id']
            and e.get('operation_sha256')==work['operation_sha256']
            and e.get('image_sha256')==sha(captures[roles[0]])]
        checks=dict(zip(CODES[n],(
            bool(bound and q),bool(face_measure and bottom),
            bool(bound and len(positions)==1 and
                 q.get('underside_qa_sha256')==
                 sha(captures['VISUAL_VIEW_UNDERSIDE'])))))
    else:
        q=jbytes(original('P345_QA_REPORT','.json') or b'')
        l=jbytes(original('P4_LIGHTING_QA','.json') or b'')
        complete=bool(complete and q and l)
        events=[e for e in audit if
            e.get('event')=='VISUAL_QA_REVIEWED' and
            e.get('step')==step and e.get('attempt_id')==work['attempt_id']
            and e.get('operation_sha256')==work['operation_sha256']]
        tech=[e for e in events if e.get('review_kind')=='TECHNICAL'
              and e.get('image_sha256')==sha(captures['LIGHT_NEUTRAL_VIEW'])]
        art=[e for e in events if e.get('review_kind')=='PRESENTATION'
             and e.get('image_sha256')==sha(captures['LIGHT_CINEMATIC_VIEW'])]
        separated=bool(len(tech)==len(art)==1
            and tech[0].get('reviewer_id') and art[0].get('reviewer_id')
            and tech[0]['reviewer_id']!=art[0]['reviewer_id'])
        checks=dict(zip(CODES[n],(
            bound,bool(bound and dif('LIGHT_CINEMATIC_VIEW','LIGHT_NEUTRAL_VIEW')),
            bool(separated and q and l))))
    need(len(checks)==3 and all(type(x) is bool for x in checks.values()),
         'C07_N_SIX_SOURCE_MEASURE_INCOMPLETE')
    return dict(rule_id=rid,checks=checks,evidence_complete=complete,
        current_original_capture_roles=tuple(sorted(frames)),
        original_audit_sha256=auditsha,original_audit_tail=tail,
        attempt_id=work['attempt_id'],operation_sha256=work['operation_sha256'],
        renderer_execution_provenance='UNVERIFIED',
        owner_artistic_approval='UNVERIFIED',individual_mg0='UNKNOWN',
        fivem_runtime='UNKNOWN',advancement_authorized=False)
