"""O149: measure original vegetation/transparent alpha cost against pre-D budget.

Counts actual GLB alpha primitive triangles, draws and decoded RGBA bytes.
This is a source-level cost evaluation, NOT FiveM FPS, shader overdraw
profiling, independent MG0 or aesthetic acceptance.
"""
import hashlib
from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p5_optimization_semantics import inspect as inspect_p5,_mesh
from c07_p5_budget_semantics import _json,_texture_bytes,_glb_parts

RULE='AAA-200-O-149'
CRITERIA=(
 'pre_d_complete_vegetation_transparency_cost_budget_and_roles_sha_pinned',
 'all_original_alpha_primitives_and_texture_bytes_independently_measured',
 'actual_original_vegetation_transparent_triangle_draw_and_rgba_costs_within_pre_d_budget',
)
class AlphaCostBlocked(ValueError):pass
def need(ok,why):
    if not ok:raise AlphaCostBlocked(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def integer(v,lo=0,hi=1000000000):
    return type(v) is int and lo<=v<=hi

def inspect(source_context,rule_id):
    need(rule_id==RULE and type(source_context) is dict and
         set(source_context)=={'inventory','plan','controller','asset',
                               'step','work','source_loader'},
         'C07_O149_RULE_OR_CONTEXT')
    inv,plan,ctrl,asset,step,work,loader=(
        source_context[k] for k in ('inventory','plan','controller',
                                    'asset','step','work','source_loader'))
    inspect_p5(inv,plan,ctrl,asset,step,work,source_loader=loader)
    rows,tail,state,audit_sha=_original_attempt(
        inv,plan,ctrl,asset,step,work)
    need(sha(ctrl.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'C07_O149_CURRENT_AUDIT_DRIFT')
    contract=plan.get('p345_evidence_contract',{})
    pins=contract.get('original_artifact_sha256',{}) if type(contract) is dict else {}
    need(type(pins) is dict,'C07_O149_PRE_D_PINS')
    found={}
    for role,path,digest,raw in _registered_artifacts(
            rows,state,step,loader,work):
        need(role not in found,'C07_O149_DUPLICATE_ROLE')
        found[role]=(path,digest,raw)
    def original(role,ext):
        row=found.get(role)
        return row[2] if (row and row[0].lower().endswith(ext)
            and pins.get(role)==row[1] and sha(row[2])==row[1]) else None
    raw=original('P5_ALPHA_COST_POLICY','.json')
    policy=_json(raw) if raw is not None else {}
    native_raw=original('NATIVE_EXPORT','.glb')
    roles=policy.get('material_roles')
    budgets=policy.get('max_cost')
    expected=policy.get('native_sha256')
    declared=bool(
        type(roles) is dict and len(roles)>=2
        and all(type(k) is str and k.isdecimal() and
                v in ('vegetation','transparent') for k,v in roles.items())
        and {'vegetation','transparent'}<=set(roles.values())
        and type(budgets) is dict and
        set(budgets)=={'vegetation_triangles','transparent_triangles',
                      'vegetation_draws','transparent_draws','rgba_bytes'}
        and all(integer(v,1) for v in budgets.values())
        and native_raw is not None and expected==sha(native_raw))
    measured=False;within=False
    if declared:
        native=_mesh(native_raw)
        doc,binary=_glb_parts(native_raw)
        images=_texture_bytes(doc,binary)
        materials=doc.get('materials',[])
        counts={'vegetation_triangles':0,'transparent_triangles':0,
                'vegetation_draws':0,'transparent_draws':0}
        all_alpha=set()
        complete=bool(native and images and type(materials) is list
                      and len(materials)>0)
        if complete:
            for material_index,triangles in native['primitive_materials']:
                if type(material_index) is not int or not 0<=material_index<len(materials):
                    complete=False;break
                mat=materials[material_index]
                mode=mat.get('alphaMode','OPAQUE')
                if mode not in ('OPAQUE','MASK','BLEND'):
                    complete=False;break
                if mode=='OPAQUE':
                    continue
                all_alpha.add(str(material_index))
                category=roles.get(str(material_index))
                if category is None or (category=='vegetation' and mode!='MASK') or (
                        category=='transparent' and mode!='BLEND'):
                    complete=False;break
                counts[category+'_triangles']+=triangles
                counts[category+'_draws']+=1
        measured=bool(complete and set(roles)==all_alpha and
            all(counts[k]>0 for k in counts))
        if measured:
            rgba=sum(im['width']*im['height']*4 for im in images)
            within=bool(rgba<=budgets['rgba_bytes'] and
                all(counts[k]<=budgets[k] for k in counts))
    checks=dict(zip(CRITERIA,(declared,measured,within)))
    need(set(checks)==set(CRITERIA) and
         all(type(v) is bool for v in checks.values()),
         'C07_O149_LITERAL_CHECKS')
    return {'rule_id':rule_id,'checks':checks,
            'evidence_complete':bool(declared and measured),
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'individual_mg0':'UNKNOWN','advancement_authorized':False}
