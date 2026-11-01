"""S183 exact original component separation/duplicate intersection replay.

For two original mesh components, disjoint world-space triangle AABBs
conservatively prove no intersection; exactly coincident triangles prove a
real defect. Ambiguous AABB overlap remains UNKNOWN, never a guessed PASS.
No collision-engine, owner or MG0 approval is inferred.
"""
import hashlib
import math
from itertools import combinations

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p678_forty_native_domain import inspect as inspect_p678
from c07_p345_forty_native_evidence import binary_json
from c07_p6_collision_semantics import _triangles
from c07_p1_environment_full_review import pose, world, bounds, separation

RULE='AAA-200-S-183'
CRITERIA=(
    'pre_d_complete_component_roles_placement_and_intersection_policy_sha_pinned',
    'every_current_original_component_world_triangle_independently_recomputed',
    'all_original_component_pairs_decisively_nonintersecting_or_exact_duplicate_detected',
)

class OriginalIntersectionBlocked(ValueError):
    pass

def need(ok,why):
    if not ok:
        raise OriginalIntersectionBlocked(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def inspect(source_context,rule_id):
    need(rule_id==RULE and type(source_context) is dict and
         set(source_context)=={'inventory','plan','controller',
                               'asset','step','work','source_loader'},
         'C07_S183_RULE_OR_CONTEXT')
    inv,plan,controller=(source_context[k] for k in
                          ('inventory','plan','controller'))
    asset,step,work,loader=(source_context[k] for k in
                             ('asset','step','work','source_loader'))
    need(plan.get('phase') in ('P8','VERIFY','G2','G3','G4','DELIVERY'),
         'C07_S183_P8_PHASE_REQUIRED')
    inspect_p678(inv,plan,controller,asset,step,work,source_loader=loader)
    rows,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'C07_S183_CURRENT_AUDIT_DRIFT')
    contract=plan.get('p678_evidence_contract',{})
    pins=contract.get('original_artifact_sha256',{}) if type(contract) is dict else {}
    need(type(pins) is dict,'C07_S183_PRE_D_PINS')
    found={}
    for role,path,digest,raw in _registered_artifacts(
            rows,state,step,loader,work):
        need(role not in found,'C07_S183_DUPLICATE_ROLE')
        found[role]=(path,digest,raw)
    def original(role,ext):
        item=found.get(role)
        return item[2] if (item and item[0].lower().endswith(ext)
            and pins.get(role)==item[1] and sha(item[2])==item[1]) else None
    policy_raw=original('P8_INTERSECTION_POLICY','.json')
    placement_raw=original('P8_COMPONENT_PLACEMENTS','.json')
    policy=binary_json(policy_raw) if policy_raw is not None else {}
    placement=binary_json(placement_raw) if placement_raw is not None else {}
    roles=policy.get('component_roles')
    poses=placement.get('placements')
    clearance=policy.get('min_clearance_m')
    declared=bool(type(roles) is list and
        2<=len(roles)<=64 and len(set(roles))==len(roles) and
        all(type(r) is str and r for r in roles) and
        type(poses) is dict and set(poses)==set(roles) and
        all(pose(p) for p in poses.values()) and
        type(clearance) in (int,float) and math.isfinite(clearance) and
        0<clearance<=10 and
        policy.get('unintended_overlap_forbidden') is True and
        policy.get('allowed_contact_pairs')==[])
    triangles={}
    all_reopened=bool(declared)
    if all_reopened:
        for role in roles:
            raw=original(role,'.glb')
            if raw is None:
                all_reopened=False
                break
            native=_triangles(raw)
            if not native:
                all_reopened=False
                break
            triangles[role]=[[world(p,poses[role]) for p in tri]
                             for tri in native]
    # For every pair of original components, use conservative AABB separation
    # for positive; only exact shared triangle geometry is a certain negative.
    states=[]
    if all_reopened:
        for a,b in combinations(roles,2):
            if all(separation(bounds([ta],{'translation_xyz':[0,0,0],
                 'yaw_deg':0,'scale_xyz':[1,1,1]}),
                 bounds([tb],{'translation_xyz':[0,0,0],
                 'yaw_deg':0,'scale_xyz':[1,1,1]}))>=clearance
                 for ta in triangles[a] for tb in triangles[b]):
                states.append('SEPARATED')
            elif any(tuple(sorted(tuple(p) for p in ta))==
                     tuple(sorted(tuple(p) for p in tb))
                     for ta in triangles[a] for tb in triangles[b]):
                states.append('DUPLICATE_INTERSECTION')
            else:
                states.append('AMBIGUOUS')
    decisive=bool(states and 'AMBIGUOUS' not in states)
    clean=bool(decisive and all(s=='SEPARATED' for s in states))
    checks=dict(zip(CRITERIA,(
        bool(declared and policy_raw is not None and placement_raw is not None),
        all_reopened,clean)))
    complete=bool(declared and all_reopened and decisive)
    need(set(checks)==set(CRITERIA) and
         all(type(v) is bool for v in checks.values()),
         'C07_S183_PER_LITERAL_CHECKS_CHANGED')
    return {'rule_id':rule_id,'checks':checks,
            'evidence_complete':complete,
            'source_sha256':inv['rules'][rule_id]['source_sha256'],
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'original_audit_sha256':audit_sha,
            'original_audit_tail':tail,
            'individual_mg0':'UNKNOWN','advancement_authorized':False}
