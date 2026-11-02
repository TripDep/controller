"""F-051/F-060: source-byte blockout-first and detail-gate positive replayers.

Recompute original P1 geometry, pre-D numeric acceptance contract, source QA
and current hash-chained operation chronology. This is process/geometry QA,
not artistic owner acceptance, independent MG0 or in-game verification.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p1_thirty_native_domain import inspect as p1_inspect, jbytes
from c07_p6_collision_semantics import _triangles

FIRST = 'AAA-200-F-051'
GATE = 'AAA-200-F-060'
RULES = frozenset((FIRST, GATE))
CRITERIA = {
    FIRST: (
        'original_pre_d_blockout_source_budget_and_shape_contract_sha_pinned',
        'actual_original_major_form_mesh_faces_and_triangle_budget_measured',
        'first_blockout_export_precedes_all_original_detail_operations',
    ),
    GATE: (
        'original_pre_d_blockout_acceptance_and_qa_sha_pinned',
        'all_original_blockout_acceptance_checks_recomputed_from_geometry',
        'no_detail_phase_or_open_qa_finding_before_verified_blockout',
    ),
}
class BlockoutReviewBlocked(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise BlockoutReviewBlocked(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def positive(v):
    return type(v) in (int,float) and math.isfinite(v) and v>0

def triangle_area(tri):
    p,q,r = tri
    u=[q[k]-p[k] for k in range(3)]
    v=[r[k]-p[k] for k in range(3)]
    c=(u[1]*v[2]-u[2]*v[1],u[2]*v[0]-u[0]*v[2],
       u[0]*v[1]-u[1]*v[0])
    return math.sqrt(sum(x*x for x in c))/2

def inspect(source_context, rule_id):
    require(rule_id in RULES and type(source_context) is dict,
            'C07_BLOCKOUT_LITERAL_NOT_REVIEWED')
    inv,plan,controller = (source_context[k] for k in
                           ('inventory','plan','controller'))
    asset,step,work,loader = (source_context[k] for k in
                              ('asset','step','work','source_loader'))
    p1_inspect(inv,plan,controller,asset,step,work,source_loader=loader)
    rows,tail,state,audit_sha = _original_attempt(
        inv,plan,controller,asset,step,work)
    require(state.get('last_audit_hash')==tail and
            sha(controller.master.read_bytes())==work['master_sha256'] and
            (state.get('active_step') or {}).get('step')==step,
            'C07_BLOCKOUT_ORIGINAL_AUDIT_DRIFT')
    found={}
    for role,path,digest,raw in _registered_artifacts(
            rows,state,step,loader,work):
        if role in ('P1_SCENE_CONTRACT','NATIVE_EXPORT','P1_QA_REPORT'):
            require(role not in found,'C07_BLOCKOUT_DUPLICATE_ROLE')
            found[role]=(path,digest,raw)
    contract=plan.get('p1_evidence_contract',{})
    pins=contract.get('original_artifact_sha256',{}) if type(contract) is dict else {}
    require(type(pins) is dict,'C07_BLOCKOUT_PRE_D_PIN_SCHEMA')
    def original(role,ext):
        item=found.get(role)
        return (item[2] if item and item[0].lower().endswith(ext)
                and pins.get(role)==item[1] and sha(item[2])==item[1]
                else None)
    scene_raw=original('P1_SCENE_CONTRACT','.json')
    native_raw=original('NATIVE_EXPORT','.glb')
    qa_raw=original('P1_QA_REPORT','.json')
    scene=jbytes(scene_raw) if scene_raw is not None else {}
    qa=jbytes(qa_raw) if qa_raw is not None else {}
    triangles=_triangles(native_raw) if native_raw is not None else []
    footprint=scene.get('footprint_m')
    envelope=scene.get('expected_bbox_local')
    budget=scene.get('blockout_triangle_budget')
    fraction=scene.get('blockout_min_major_face_fraction')
    shape_contract=(
        type(footprint) is list and len(footprint)==2 and
        all(positive(x) for x in footprint) and
        type(envelope) is dict and
        all(type(envelope.get(k)) is list and len(envelope[k])==3
            and all(type(x) in (int,float) and math.isfinite(x)
                    for x in envelope[k]) for k in ('min','max')) and
        type(budget) is int and 1<=budget<=1000000 and
        positive(fraction) and 0.01<=fraction<=1)
    bounds_ok=False
    major=False
    count_ok=False
    if triangles and shape_contract:
        vertices=[p for tri in triangles for p in tri]
        low=[min(v[k] for v in vertices) for k in range(3)]
        high=[max(v[k] for v in vertices) for k in range(3)]
        bounds_ok=all(abs(low[k]-envelope['min'][k])<=0.01 and
                      abs(high[k]-envelope['max'][k])<=0.01
                      for k in range(3))
        count_ok=0<len(triangles)<=budget
        major=max(triangle_area(tri) for tri in triangles)>=(
            footprint[0]*footprint[1]*fraction)
    # A source-signed producer note is never accepted as a substitute for
    # the actual mesh: each of these checks is recomputed from GLB bytes.
    measured=bool(bounds_ok and count_ok and major)
    reserved=[r for r in rows if r.get('event')=='SUPERVISOR_OPERATION_RESERVED']
    valid_chronology=bool(
        reserved and work.get('phase')=='P1' and
        all(type(r.get('work')) is dict and
            r['work'].get('phase')=='P1' for r in reserved))
    current_artifacts=[r for r in rows if r.get('event')=='ARTIFACT_RECORDED'
                       and r.get('step')==step]
    export_positions=[i for i,r in enumerate(current_artifacts)
                      if r.get('evidence_operation',{}).get('role')=='NATIVE_EXPORT']
    detail_positions=[i for i,r in enumerate(current_artifacts)
                      if r.get('evidence_operation',{}).get('role') in
                      ('DETAIL_EXPORT','P2_DETAIL_EXPORT','FINAL_DETAILED_EXPORT')]
    first_export=bool(export_positions and
                      (not detail_positions or
                       min(export_positions)<min(detail_positions)))
    criteria=CRITERIA[rule_id]
    if rule_id==FIRST:
        checks=dict(zip(criteria,(
            bool(scene_raw is not None and native_raw is not None and
                 shape_contract),
            bool(measured),
            bool(valid_chronology and first_export))))
        complete=bool(scene_raw is not None and native_raw is not None)
    else:
        required=('geometry_within_envelope','triangle_budget','major_faces')
        acceptance=scene.get('blockout_acceptance_criteria')
        qa_policy=bool(scene_raw is not None and qa_raw is not None and
                       acceptance==list(required) and
                       type(qa.get('open_findings')) is list and
                       type(qa.get('passed_checks')) is list)
        qa_clear=bool(qa_policy and qa['open_findings']==[] and
                      qa['passed_checks']==list(required))
        checks=dict(zip(criteria,(
            qa_policy,
            bool(shape_contract and measured),
            bool(qa_clear and valid_chronology and first_export))))
        complete=bool(scene_raw is not None and native_raw is not None and
                      qa_raw is not None)
    return {'rule_id':rule_id,'checks':{k:bool(v) for k,v in checks.items()},
            'evidence_complete':complete,
            'source_sha256':inv['rules'][rule_id]['source_sha256'],
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'individual_mg0':'UNKNOWN','advancement_authorized':False}
