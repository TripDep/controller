"""S182/S187 original-source final spatial and correction QA replayers.

Only independent current-operation geometry/audit observations are returned.
MG0, owner acceptance, rendered appearance and FiveM remain unattested.
"""
import hashlib
import math
from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p678_forty_native_domain import inspect as inspect_p678
from c07_p345_forty_native_evidence import binary_json
from c07_p6_collision_semantics import _triangles
from c07_p1_environment_full_review import pose, world
from c07_p1_site_contract_full_review import signed_basis
from c07_native_output_oracle import read_mesh_geometry, OriginalGeometryBlocked
from c07_p3_geometry_semantics import geometry

SPATIAL='AAA-200-S-182'
RECHECK='AAA-200-S-187'
RULES=frozenset((SPATIAL,RECHECK))
CRITERIA={
 SPATIAL:(
  'pre_d_complete_original_component_alignment_proportion_and_axis_policy_sha_pinned',
  'every_original_world_component_bounds_and_forward_axis_independently_measured',
  'all_original_anchor_alignments_and_dimension_ratios_meet_pre_d_limits'),
 RECHECK:(
  'pre_d_full_significant_correction_and_required_recheck_scope_sha_pinned',
  'every_current_audit_correction_bound_to_distinct_original_before_after_meshes',
  'all_required_after_correction_geometry_checks_replayed_and_audited_in_order'),
}
CHECKS=('no_degenerate','no_duplicate','minimum_triangles','bounds_shift')
PHASES=frozenset(('P8','VERIFY','G2','G3','G4','DELIVERY'))

class FinalProcessBlocked(ValueError):pass
def need(v,code):
    if not v:raise FinalProcessBlocked(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def finite(v):return type(v) in (int,float) and math.isfinite(v)
def vec(v):return type(v) is list and len(v)==3 and all(finite(x) for x in v)
def box(v):
    return (type(v) is list and len(v)==2 and all(vec(x) for x in v)
            and all(v[0][k]<=v[1][k] for k in range(3)))
def bounds(points):
    return [[min(p[i] for p in points) for i in range(3)],
            [max(p[i] for p in points) for i in range(3)]]

def original_scope(ctx):
    inv,plan,ctrl,asset,step,work,loader=(
        ctx[k] for k in ('inventory','plan','controller','asset',
                         'step','work','source_loader'))
    need(plan.get('phase') in PHASES and plan.get('phase')==work.get('phase'),
         'C07_FINAL_PROCESS_PHASE')
    inspect_p678(inv,plan,ctrl,asset,step,work,source_loader=loader)
    events,tail,state,audit_sha=_original_attempt(
        inv,plan,ctrl,asset,step,work)
    need(sha(ctrl.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'C07_FINAL_PROCESS_MASTER_AUDIT_DRIFT')
    contract=plan.get('p678_evidence_contract',{})
    pins=contract.get('original_artifact_sha256',{}) if type(contract) is dict else {}
    need(type(pins) is dict,'C07_FINAL_PROCESS_PRE_D_PINS')
    found={}
    for role,path,digest,raw in _registered_artifacts(
            events,state,step,loader,work):
        need(role not in found,'C07_FINAL_PROCESS_DUPLICATE_ROLE')
        found[role]=(path,digest,raw)
    def original(role,ext):
        item=found.get(role)
        return item[2] if (item and item[0].lower().endswith(ext)
            and pins.get(role)==item[1] and sha(item[2])==item[1]) else None
    return events,tail,audit_sha,original

def spatial(original):
    raw=original('P8_SPATIAL_POLICY','.json')
    policy=binary_json(raw) if raw is not None else {}
    roles=policy.get('component_roles')
    poses=policy.get('placements')
    targets=policy.get('world_bounds')
    anchors=policy.get('forward_anchor_vertices')
    forward=policy.get('expected_forward_world')
    align=policy.get('alignment_pairs')
    ratios=policy.get('dimension_ratios')
    err=policy.get('max_bounds_error_m')
    angle=policy.get('max_forward_error_deg')
    units=policy.get('meters_per_unit')
    axis=policy.get('native_to_world_axis_matrix')
    declared=bool(
        type(roles) is list and 2<=len(roles)<=32
        and len(set(roles))==len(roles)
        and all(type(r) is str and r for r in roles)
        and all(type(d) is dict and set(d)==set(roles)
                for d in (poses,targets,anchors,forward))
        and all(pose(p) for p in poses.values())
        and all(box(v) for v in targets.values())
        and all(type(a) is list and len(a)==2 and all(vec(v) for v in a)
                for a in anchors.values())
        and all(vec(v) and abs(math.dist(v,[0,0,0])-1)<1e-5
                for v in forward.values())
        and signed_basis(axis) and finite(units) and units==1
        and finite(err) and 0<err<=0.25
        and finite(angle) and 0<angle<=10
        and type(align) is list and 1<=len(align)<=128
        and type(ratios) is list and 1<=len(ratios)<=128)
    # Apply the pre-D native-to-world basis to actual original vertices.
    # Merely validating the matrix shape would silently miss axis swaps.
    def oriented(point):
        return [sum(axis[i][j]*point[j] for j in range(3))
                for i in range(3)]
    points={};actual={};axis_ok={}
    if declared:
        for role in roles:
            native=original(role,'.glb')
            tris=_triangles(native) if native is not None else None
            if not tris:break
            local={tuple(p) for tri in tris for p in tri}
            pair=anchors[role]
            if not all(tuple(p) in local for p in pair):break
            worldpoints=[world(oriented(p),poses[role]) for tri in tris for p in tri]
            a,b=[world(oriented(p),poses[role]) for p in pair]
            delta=[b[i]-a[i] for i in range(3)]
            length=math.dist(a,b)
            if length<=1e-9:break
            cosine=sum(delta[i]*forward[role][i] for i in range(3))/length
            points[role]=local
            actual[role]=bounds(worldpoints)
            axis_ok[role]=cosine>=math.cos(math.radians(angle))
    reopened=bool(declared and len(actual)==len(roles))
    measured=bool(reopened and all(
        all(abs(actual[r][side][i]-targets[r][side][i])<=err
            for side in range(2) for i in range(3)) and axis_ok[r]
        for r in roles))
    used_a=set();used_r=set();aligned=bool(reopened)
    if aligned:
        for item in align:
            if (type(item) is not dict or
                set(item)!={'a','b','a_vertex_xyz','b_vertex_xyz','max_gap_m'}):
                aligned=False;break
            a,b=item['a'],item['b']
            if (a==b or a not in points or b not in points
                or not vec(item['a_vertex_xyz']) or not vec(item['b_vertex_xyz'])
                or tuple(item['a_vertex_xyz']) not in points[a]
                or tuple(item['b_vertex_xyz']) not in points[b]
                or not finite(item['max_gap_m'])
                or not 0<item['max_gap_m']<=0.25):
                aligned=False;break
            used_a.update((a,b))
            aligned=(math.dist(world(oriented(item['a_vertex_xyz']),poses[a]),
                               world(oriented(item['b_vertex_xyz']),poses[b]))
                     <=item['max_gap_m'])
            if not aligned:break
    proportional=bool(reopened)
    if proportional:
        for item in ratios:
            if (type(item) is not dict or
                set(item)!={'a','b','axis','min_ratio','max_ratio'}):
                proportional=False;break
            a,b,i=item['a'],item['b'],item['axis']
            if (a==b or a not in actual or b not in actual
                or type(i) is not int or i not in (0,1,2)
                or not finite(item['min_ratio']) or
                not finite(item['max_ratio']) or
                not 0<item['min_ratio']<=item['max_ratio']):
                proportional=False;break
            da=actual[a][1][i]-actual[a][0][i]
            db=actual[b][1][i]-actual[b][0][i]
            used_r.update((a,b))
            proportional=bool(db>1e-9 and
                item['min_ratio']<=da/db<=item['max_ratio'])
            if not proportional:break
    checks=dict(zip(CRITERIA[SPATIAL],(
        declared,measured,bool(aligned and proportional and
                               used_a==set(roles) and used_r==set(roles)))))
    return checks,bool(declared and reopened)

def recheck(original,events,work,step):
    raw=original('P8_REGRESSION_POLICY','.json')
    policy=binary_json(raw) if raw is not None else {}
    corrections=policy.get('corrections')
    required=policy.get('required_checks')
    max_delta=policy.get('max_bounds_shift_m')
    minimum=policy.get('minimum_final_triangles')
    declared=bool(
        type(corrections) is dict and 1<=len(corrections)<=64
        and all(type(k) is str and k and type(v) is dict
                and set(v)=={'before_role','after_role'}
                and type(v['before_role']) is str
                and type(v['after_role']) is str
                and v['before_role']!=v['after_role']
                for k,v in corrections.items())
        and required==list(CHECKS)
        and finite(max_delta) and 0<=max_delta<=10
        and type(minimum) is int and minimum>=1)
    opens=[i for i,row in enumerate(events)
           if row.get('event')=='SUPERVISOR_OPERATION_OPENED'
           and row.get('step')==step]
    need(len(opens)==1,'C07_S187_CURRENT_OPEN')
    scoped=[(i,row) for i,row in enumerate(events[opens[0]+1:],
            start=opens[0]+1) if row.get('step')==step
            and row.get('attempt_id')==work['attempt_id']
            and row.get('operation_sha256')==work['operation_sha256']]
    applied=[(i,row) for i,row in scoped
             if row.get('event')=='CORRECTION_APPLIED']
    reruns=[(i,row) for i,row in scoped
            if row.get('event')=='QA_RECHECK']
    coverage=bool(
        declared and len(applied)==len(corrections)==len(reruns)
        and {r.get('correction_id') for _,r in applied}==set(corrections)
        and {r.get('correction_id') for _,r in reruns}==set(corrections)
        and len({r.get('correction_id') for _,r in applied})==len(applied)
        and len({r.get('correction_id') for _,r in reruns})==len(reruns))
    measured={}
    if coverage:
        for cid,roles in corrections.items():
            event=next(v for _,v in applied if v.get('correction_id')==cid)
            before=original(roles['before_role'],'.glb')
            after=original(roles['after_role'],'.glb')
            if (before is None or after is None
                or event.get('before_role')!=roles['before_role']
                or event.get('after_role')!=roles['after_role']
                or event.get('before_sha256')!=sha(before)
                or event.get('after_sha256')!=sha(after)
                or before==after):break
            try:
                old=read_mesh_geometry(before)
                new=read_mesh_geometry(after)
                geo=geometry(after)
            except (OriginalGeometryBlocked,ValueError,KeyError,IndexError,TypeError):
                break
            measured[cid]={
                'no_degenerate':bool(geo and all(
                    x['degenerate_triangles']==0 for x in geo)),
                'no_duplicate':bool(geo and all(
                    x['duplicate_geometric_faces']==0 for x in geo)),
                'minimum_triangles':new['triangles']>=minimum,
                'bounds_shift':all(
                    abs(old['bbox_min'][k]-new['bbox_min'][k])<=max_delta
                    and abs(old['bbox_max'][k]-new['bbox_max'][k])<=max_delta
                    for k in range(3)),
            }
    originals=bool(coverage and len(measured)==len(corrections))
    rerun_ok=bool(originals)
    if rerun_ok:
        for cid,roles in corrections.items():
            ai=next(i for i,v in applied if v.get('correction_id')==cid)
            ri,event=next((i,v) for i,v in reruns
                          if v.get('correction_id')==cid)
            after=original(roles['after_role'],'.glb')
            if (ri<=ai or event.get('result')!='PASS'
                or event.get('after_sha256')!=sha(after)
                or event.get('check_ids')!=list(CHECKS)
                or not all(measured[cid].values())):
                rerun_ok=False;break
    checks=dict(zip(CRITERIA[RECHECK],(
        bool(declared and coverage),originals,rerun_ok)))
    return checks,bool(declared and originals)

def inspect(source_context,rule_id):
    need(type(source_context) is dict and
         set(source_context)=={'inventory','plan','controller',
                               'asset','step','work','source_loader'}
         and rule_id in RULES,'C07_FINAL_PROCESS_RULE_OR_CONTEXT')
    events,tail,audit_sha,original=original_scope(source_context)
    if rule_id==SPATIAL:checks,complete=spatial(original)
    else:checks,complete=recheck(
        original,events,source_context['work'],source_context['step'])
    need(set(checks)==set(CRITERIA[rule_id])
         and all(type(x) is bool for x in checks.values()),
         'C07_FINAL_PROCESS_LITERAL_CHECKS')
    return {'rule_id':rule_id,'checks':checks,'evidence_complete':complete,
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'attempt_id':source_context['work']['attempt_id'],
            'operation_sha256':source_context['work']['operation_sha256'],
            'individual_mg0':'UNKNOWN','advancement_authorized':False}
