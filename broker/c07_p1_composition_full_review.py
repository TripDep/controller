"""F-057: original-source independent composition defect before detail.

A signed QA label alone is NEVER proof. Recompute measured native dimensions
against a pre-D composition limit, bind the exact QA report to the same
Controller operation, and reject any later detail-first workflow.
"""
import hashlib
import math
from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p1_thirty_native_domain import inspect as inspect_p1, jbytes
from c07_native_output_oracle import read_mesh_geometry

RULE='AAA-200-F-057'
CRITERIA=(
    'pre_d_composition_target_policy_and_original_qa_source_sha_bound',
    'reported_composition_defect_independently_recomputed_from_original_glb',
    'original_composition_qa_audited_before_first_detail_operation',
)

class CompositionReviewBlocked(ValueError):
    pass

def need(ok,why):
    if not ok:raise CompositionReviewBlocked(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def numeric(v):return type(v) in (int,float) and math.isfinite(v)

def vector(v):
    return type(v) is list and len(v)==3 and all(numeric(c) for c in v)

def inspect(source_context,rule_id):
    need(rule_id==RULE and type(source_context) is dict and
         set(source_context)=={
            'inventory','plan','controller','asset','step','work','source_loader'},
         'C07_F057_LITERAL_OR_CONTEXT')
    inv,plan,controller,asset,step,work,loader=(
        source_context[k] for k in ('inventory','plan','controller',
                                     'asset','step','work','source_loader'))
    need(type(plan) is dict and type(work) is dict and
         callable(loader) and plan.get('phase')==work.get('phase') and
         plan['phase'] in ('P1','P2','P3','P4','P5','P6','P7','P8'),
         'C07_F057_ORIGINAL_PHASE')
    inspect_p1(inv,plan,controller,asset,step,work,source_loader=loader)
    audit,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'C07_F057_MASTER_OR_AUDIT_TAMPER')
    found={}
    for role,path,digest,raw in _registered_artifacts(
            audit,state,step,loader,work):
        need(role not in found,'C07_F057_DUPLICATE_ORIGINAL_ROLE')
        found[role]=(path,digest,raw)
    pins=plan.get('p1_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_F057_PRE_D_PINS_MISSING')
    def original(role,ext):
        item=found.get(role)
        return item[2] if (item is not None and
            item[0].lower().endswith(ext) and
            pins.get(role)==item[1] and sha(item[2])==item[1]) else None
    scene_raw=original('P1_SCENE_CONTRACT','.json')
    policy_raw=original('P1_VISUAL_METRICS_POLICY','.json')
    report_raw=original('P1_QA_REPORT','.json')
    native_raw=original('NATIVE_EXPORT','.glb')
    complete=all(x is not None for x in (
        scene_raw,policy_raw,report_raw,native_raw))
    checks={criterion:False for criterion in CRITERIA}
    if not complete:
        return dict(rule_id=RULE,checks=checks,evidence_complete=False,
                    attempt_id=work['attempt_id'],
                    operation_sha256=work['operation_sha256'],
                    original_audit_sha256=audit_sha,
                    original_audit_tail=tail)
    scene=jbytes(scene_raw)
    policy=jbytes(policy_raw)
    report=jbytes(report_raw)
    bounds=read_mesh_geometry(native_raw)
    target=scene.get('expected_bbox_local')
    lo=target.get('min') if type(target) is dict else None
    hi=target.get('max') if type(target) is dict else None
    tolerance=policy.get('max_composition_bbox_height_error_m')
    valid=bool(
        policy.get('schema')=='c07-p1-visual-metrics-pre-d-v1' and
        vector(lo) and vector(hi) and all(a<b for a,b in zip(lo,hi)) and
        numeric(tolerance) and 0<tolerance<=2.0 and
        report.get('schema')=='c07-p1-composition-native-qa-v1' and
        report.get('asset')==asset and
        report.get('step')==step and
        report.get('attempt_id')==work['attempt_id'] and
        report.get('operation_sha256')==work['operation_sha256'])
    checks[CRITERIA[0]]=valid
    if valid:
        expected_height=hi[2]-lo[2]
        measured_height=bounds['bbox_max'][2]-bounds['bbox_min'][2]
        delta=abs(expected_height-measured_height)
        findings=report.get('open_findings')
        findings_valid=bool(
            type(findings) is list and len(findings)==1 and
            type(findings[0]) is dict and
            set(findings[0])=={
                'code','observed_height_m','target_height_m','tolerance_m'} and
            findings[0]['code']=='COMPOSITION_BBOX_HEIGHT_MISMATCH' and
            all(numeric(findings[0][k]) for k in (
                'observed_height_m','target_height_m','tolerance_m')) and
            abs(findings[0]['observed_height_m']-measured_height)<=1e-6 and
            abs(findings[0]['target_height_m']-expected_height)<=1e-6 and
            findings[0]['tolerance_m']==tolerance and
            delta>tolerance)
        checks[CRITERIA[1]]=findings_valid
        if findings_valid:
            current=[(i,e) for i,e in enumerate(audit) if
                     e.get('step')==step and
                     e.get('attempt_id')==work['attempt_id'] and
                     e.get('operation_sha256')==work['operation_sha256']]
            # The canonical OPENED event is linked by reservation_hash
            # and step, and deliberately carries no attempt_id itself.
            # _original_attempt above has already authenticated its
            # reservation -> current work/attempt/operation binding.
            opened=[i for i,r in enumerate(audit)
                    if r.get('event')=='SUPERVISOR_OPERATION_OPENED'
                    and r.get('step')==step]
            qa=[i for i,r in current
                if r.get('event')=='BLOCKOUT_QA' and
                r.get('qa_report_sha256')==sha(report_raw) and
                r.get('issue_code')=='COMPOSITION_BBOX_HEIGHT_MISMATCH']
            detail=[i for i,r in current if r.get('event')=='DETAIL_STARTED']
            checks[CRITERIA[2]]=bool(
                len(opened)==1 and len(qa)==1 and
                qa[0]>opened[0] and
                (not detail or max(qa)<min(detail)))
    return dict(rule_id=RULE,checks=checks,evidence_complete=True,
                measured_native_bbox=bounds,
                original_source_sha256={
                    role:sha(raw) for role,raw in (
                        ('P1_SCENE_CONTRACT',scene_raw),
                        ('P1_VISUAL_METRICS_POLICY',policy_raw),
                        ('P1_QA_REPORT',report_raw),
                        ('NATIVE_EXPORT',native_raw))},
                attempt_id=work['attempt_id'],
                operation_sha256=work['operation_sha256'],
                original_audit_sha256=audit_sha,
                original_audit_tail=tail)
