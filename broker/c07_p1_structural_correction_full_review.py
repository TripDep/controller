"""F059: independently verify structural corrections precede detail modelling.

The original current Controller audit, SHA-pinned pre-D correction contract,
source and corrected GLB geometry are replayed. No owner/MG0/FiveM approval.
"""
import hashlib
import math
from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p1_thirty_native_domain import inspect as inspect_p1, jbytes
from c07_native_output_oracle import read_mesh_geometry, OriginalGeometryBlocked
from c07_p3_geometry_semantics import geometry

RULE='AAA-200-F-059'
CRITERIA=(
    'pre_d_complete_structural_defect_correction_and_detail_gate_policy_sha_pinned',
    'every_original_structural_before_after_mesh_recomputed_and_correction_effective',
    'all_original_structural_rechecks_pass_before_first_detail_phase_event',
)
CHECKS=('nondegenerate','no_duplicate_faces','minimum_triangles',
        'bbox_shift_within_tolerance')

class StructuralCorrectionBlocked(ValueError):pass
def need(v,code):
    if not v:raise StructuralCorrectionBlocked(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def finite(x):return type(x) in (int,float) and math.isfinite(x)

def inspect(source_context,rule_id):
    need(rule_id==RULE and type(source_context) is dict and
         set(source_context)=={'inventory','plan','controller','asset',
                               'step','work','source_loader'},
         'C07_F059_LITERAL_OR_CONTEXT')
    inv,plan,ctrl,asset,step,work,loader=(
        source_context[k] for k in ('inventory','plan','controller',
                                    'asset','step','work','source_loader'))
    need(plan.get('phase') in ('P1','P2','P3','P4','P5','P6','P7',
                              'P8','VERIFY','G2','G3','G4','DELIVERY')
         and plan.get('phase')==work.get('phase'),
         'C07_F059_PHASE_REQUIRED')
    inspect_p1(inv,plan,ctrl,asset,step,work,source_loader=loader)
    events,tail,state,audit_sha=_original_attempt(
        inv,plan,ctrl,asset,step,work)
    need(sha(ctrl.master.read_bytes())==work['master_sha256']
         and state.get('last_audit_hash')==tail
         and (state.get('active_step') or {}).get('step')==step,
         'C07_F059_MASTER_OR_AUDIT_DRIFT')
    pins=plan.get('p1_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_F059_PRE_D_PINS')
    found={}
    for role,path,digest,raw in _registered_artifacts(
            events,state,step,loader,work):
        need(role not in found,'C07_F059_DUPLICATE_ORIGINAL_ROLE')
        found[role]=(path,digest,raw)
    def original(role,ext):
        item=found.get(role)
        return item[2] if (item and item[0].lower().endswith(ext)
            and pins.get(role)==item[1] and sha(item[2])==item[1]) else None
    raw=original('P1_STRUCTURAL_FIX_POLICY','.json')
    policy=jbytes(raw) if raw is not None else {}
    qa_raw=original('P1_QA_REPORT','.json')
    qa=jbytes(qa_raw) if qa_raw is not None else {}
    issues=policy.get('issues')
    required=policy.get('required_checks')
    maximum=policy.get('max_bbox_shift_m')
    minimum=policy.get('minimum_final_triangles')
    declared=bool(
        type(issues) is dict and 1<=len(issues)<=64
        and all(type(k) is str and k and type(v) is dict
                and set(v)=={'before_role','after_role'}
                and type(v['before_role']) is str and
                type(v['after_role']) is str and
                v['before_role']!=v['after_role']
                for k,v in issues.items())
        and required==list(CHECKS)
        and finite(maximum) and 0<=maximum<=10
        and type(minimum) is int and minimum>=1
        and qa.get('open_findings')==[])
    opens=[i for i,e in enumerate(events)
           if e.get('event')=='SUPERVISOR_OPERATION_OPENED'
           and e.get('step')==step]
    need(len(opens)==1,'C07_F059_CURRENT_OPEN_REQUIRED')
    scoped=[(i,e) for i,e in enumerate(events[opens[0]+1:],start=opens[0]+1)
            if e.get('step')==step and
            e.get('attempt_id')==work['attempt_id'] and
            e.get('operation_sha256')==work['operation_sha256']]
    kinds=('STRUCTURAL_FINDING','STRUCTURAL_FIX_APPLIED','STRUCTURAL_RECHECK')
    event_groups={k:[(i,e) for i,e in scoped if e.get('event')==k]
                  for k in kinds}
    detail=[i for i,e in scoped if e.get('event')=='DETAIL_PHASE_STARTED']
    complete_events=bool(declared and len(detail)==1 and
        all(len(event_groups[k])==len(issues) and
            {e.get('issue_id') for _,e in event_groups[k]}==set(issues)
            and len({e.get('issue_id') for _,e in event_groups[k]})==
                len(event_groups[k]) for k in kinds))
    originals={}
    if complete_events:
        for issue,roles in issues.items():
            before=original(roles['before_role'],'.glb')
            after=original(roles['after_role'],'.glb')
            finding=next((i,e) for i,e in event_groups[kinds[0]]
                         if e.get('issue_id')==issue)
            fix=next((i,e) for i,e in event_groups[kinds[1]]
                     if e.get('issue_id')==issue)
            rerun=next((i,e) for i,e in event_groups[kinds[2]]
                       if e.get('issue_id')==issue)
            if (before is None or after is None or before==after
                or finding[1].get('status')!='OPEN'
                or finding[1].get('severity') not in ('MAJOR','CRITICAL')
                or fix[1].get('before_role')!=roles['before_role']
                or fix[1].get('after_role')!=roles['after_role']
                or fix[1].get('before_sha256')!=sha(before)
                or fix[1].get('after_sha256')!=sha(after)):
                break
            try:
                old=read_mesh_geometry(before)
                new=read_mesh_geometry(after)
                geo=geometry(after)
            except (OriginalGeometryBlocked,ValueError,KeyError,TypeError,IndexError):
                break
            measured={
                'nondegenerate':bool(geo and all(
                    row['degenerate_triangles']==0 for row in geo)),
                'no_duplicate_faces':bool(geo and all(
                    row['duplicate_geometric_faces']==0 for row in geo)),
                'minimum_triangles':new['triangles']>=minimum,
                'bbox_shift_within_tolerance':all(
                    abs(old['bbox_min'][k]-new['bbox_min'][k])<=maximum and
                    abs(old['bbox_max'][k]-new['bbox_max'][k])<=maximum
                    for k in range(3)),
            }
            originals[issue]=(finding,fix,rerun,measured,sha(after))
    recomputed=bool(complete_events and len(originals)==len(issues))
    all_fixed=bool(recomputed and all(all(v[3].values())
                                    for v in originals.values()))
    chronological=bool(all_fixed)
    if chronological:
        for finding,fix,rerun,measured,digest in originals.values():
            if not (finding[0]<fix[0]<rerun[0]<detail[0]
                    and rerun[1].get('result')=='PASS'
                    and rerun[1].get('after_sha256')==digest
                    and rerun[1].get('check_ids')==list(CHECKS)):
                chronological=False
                break
    checks=dict(zip(CRITERIA,(bool(declared and complete_events),
                              all_fixed,chronological)))
    need(set(checks)==set(CRITERIA) and
         all(type(v) is bool for v in checks.values()),
         'C07_F059_LITERAL_CHECKS')
    return {'rule_id':rule_id,'checks':checks,
            'evidence_complete':recomputed,
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'individual_mg0':'UNKNOWN','advancement_authorized':False}
