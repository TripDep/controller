"""C07 T-phase macro: original-byte semantic replay for concrete delivery.

Exact-operation source, native GLB, CRC-checked ZIP and original audit are
independently reopened. A source-level verdict is NEVER a FiveM, owner or MG0
approval. Recurring-cause and process claims require *measured* improvements,
not producer text. T200 remains non-certifiable without external acceptance.
"""
import ast
import hashlib
import math
import re

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p8_delivery_semantics import (
    _zip, safe_member, inspect as delivery_inspect)
from c07_p8_closure_semantics import inspect as closure_inspect
from c07_p5_budget_semantics import _json
from c07_native_output_oracle import read_mesh_geometry

RULES={
 'AAA-200-T-191':(
   'source_and_native_export_reopened_from_current_original_audit',
   'crc_verified_package_contains_exact_editable_and_native_export',
   'independently_parsed_real_native_geometry_and_original_manifest_consistent'),
 'AAA-200-T-193':(
   'all_original_required_members_are_safe_and_crc_verified',
   'every_required_native_export_has_parseable_original_glb_geometry',
   'editable_source_has_blender_block_structure_not_just_magic_header'),
 'AAA-200-T-195':(
   'original_guide_binds_exact_editable_and_native_source_sha',
   'installation_paths_match_original_package_and_source_assets',
   'maintenance_instructions_cover_source_version_and_revalidation_without_extraneous_claims'),
 'AAA-200-T-198':(
   'recurrent_original_defect_events_and_precorrection_geometry_authenticated',
   'measured_original_before_geometry_violates_precommitted_origin_limit',
   'original_after_geometry_corrects_same_recurring_cause_within_source_limit'),
 'AAA-200-T-199':(
   'original_before_and_after_method_code_sha_and_valid_python_ast_reopened',
   'method_change_targets_independently_proven_recurring_geometry_defect',
   'changed_method_and_corrected_original_geometry_bound_to_same_current_operation'),
}
HEX=re.compile(r'[0-9a-f]{64}\Z')
class DeliveryMacroBlocked(ValueError):pass
def require(ok,code):
    if not ok:raise DeliveryMacroBlocked(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def finite(v):return type(v) in (int,float) and math.isfinite(v)

def blender_blocks(raw):
    """Validate the Blender file-block envelope, not an unverifiable label.

    This does not replace opening the file in Blender and never claims that
    arbitrary blend data is artistically valid or FiveM-compatible.
    """
    if not isinstance(raw,bytes) or len(raw)<36 or raw[:7]!=b'BLENDER':
        return False
    pointer=raw[7:8];endian=raw[8:9];version=raw[9:12]
    if pointer not in (b'_',b'-') or endian not in (b'v',b'V') or not (
            version.isdigit() and 200<=int(version)<=999):
        return False
    ptr_size=4 if pointer==b'_' else 8
    size=4+4+ptr_size+4+4
    offset=12
    seen=0
    byte_order='little' if endian==b'v' else 'big'
    while offset+size<=len(raw) and seen<100000:
        tag=raw[offset:offset+4]
        length=int.from_bytes(raw[offset+4:offset+8],byte_order)
        if length>len(raw) or offset+size+length>len(raw):
            return False
        if tag==b'ENDB':
            return length==0 and offset+size==len(raw) and seen>0
        if not all(32<=x<=126 for x in tag):
            return False
        offset+=size+length;seen+=1
    return False

def _origin_error(bounds,target):
    if not (type(target) is list and len(target)==3 and
            all(finite(v) for v in target)):
        return None
    return math.dist(bounds['bbox_min'],target)

def _safe_origin_formula(script):
    """Statically interpret a tiny coordinate-only Python AST. NEVER execute it.

    Contract: exactly def correct_origin(vertices):
        return [[p[0]-dx,p[1]-dy,p[2]-dz] for p in vertices]
    Identity expressions p[i] are permitted for unchanged axes. Arbitrary
    user scripts, calls, imports, lambdas and side effects are rejected.
    """
    if type(script) is not bytes or not 1<=len(script)<=10000:
        return None
    try:
        tree=ast.parse(script.decode('utf-8'))
    except (SyntaxError,UnicodeError,ValueError,RecursionError):
        return None
    if len(tree.body)!=1 or type(tree.body[0]) is not ast.FunctionDef:
        return None
    function=tree.body[0]
    arguments=function.args
    if (function.name!='correct_origin' or function.decorator_list or
            function.returns is not None or function.type_comment is not None or
            len(function.body)!=1 or type(function.body[0]) is not ast.Return or
            len(arguments.posonlyargs)!=0 or len(arguments.args)!=1 or
            arguments.args[0].arg!='vertices' or
            arguments.vararg is not None or arguments.kwarg is not None or
            arguments.kwonlyargs or arguments.defaults or
            arguments.kw_defaults):
        return None
    value=function.body[0].value
    if type(value) is not ast.ListComp or len(value.generators)!=1:
        return None
    gen=value.generators[0]
    if (gen.is_async or gen.ifs or type(gen.target) is not ast.Name or
            gen.target.id!='p' or type(gen.iter) is not ast.Name or
            gen.iter.id!='vertices' or type(value.elt) is not ast.List or
            len(value.elt.elts)!=3):
        return None
    offsets=[]
    for index,expression in enumerate(value.elt.elts):
        delta=0.0
        coordinate=expression
        if type(expression) is ast.BinOp:
            if type(expression.op) not in (ast.Sub,ast.Add):
                return None
            number=expression.right
            if type(number) is not ast.Constant or not finite(number.value):
                return None
            delta=(1 if type(expression.op) is ast.Sub else -1)*number.value
            if not math.isfinite(delta) or abs(delta)>100:
                return None
            coordinate=expression.left
        if (type(coordinate) is not ast.Subscript or
                type(coordinate.value) is not ast.Name or
                coordinate.value.id!='p' or
                type(coordinate.slice) is not ast.Constant or
                type(coordinate.slice.value) is not int or
                coordinate.slice.value!=index):
            return None
        offsets.append(float(delta))
    return tuple(offsets)


def _method_reproduces_actual_geometry(before_script,after_script,
                                        before_glb,after_glb):
    """Replay a source-only affine correction on ALL original triangle faces."""
    identity=_safe_origin_formula(before_script)
    delta=_safe_origin_formula(after_script)
    if identity!=(0.0,0.0,0.0) or delta is None or not any(delta):
        return False
    try:
        from c07_p6_collision_semantics import _triangles
        before=_triangles(before_glb)
        after=_triangles(after_glb)
        if not before or len(before)!=len(after):
            return False
        def oriented(tri,shift):
            pts=[tuple(round(float(p[i])-shift[i],6) for i in range(3))
                 for p in tri]
            if not all(math.isfinite(x) for p in pts for x in p):
                return None
            # Preserve front-face winding and duplicate triangle multiplicity.
            return min(tuple(pts[n:]+pts[:n]) for n in range(3))
        predicted=sorted(oriented(t,delta) for t in before)
        measured=sorted(oriented(t,(0.0,0.0,0.0)) for t in after)
        return predicted==measured
    except (ValueError,KeyError,TypeError,IndexError,OverflowError):
        return False


def inspect(context, rule_id):
    require(type(context) is dict and set(context)=={
        'inventory','plan','controller','asset','step','work','source_loader'}
        and rule_id in RULES,
        'C07_T_MACRO_LITERAL_OR_TRUSTED_SOURCE_REQUIRED')
    inv,plan,controller,asset,step,work,loader=(
        context[k] for k in ('inventory','plan','controller','asset',
                             'step','work','source_loader'))
    require(type(plan) is dict and type(work) is dict and
            plan.get('phase')==work.get('phase') and
            plan['phase'] in ('P8','VERIFY','G2','G3','G4','DELIVERY')
            and callable(loader),'C07_T_MACRO_PHASE_OR_OPERATION')
    # Recompute both canonical original family readers on the exact operation.
    delivery=delivery_inspect(inv,plan,controller,asset,step,work,
                              source_loader=loader)
    closure=closure_inspect(inv,plan,controller,asset,step,work,
                            source_loader=loader)
    audit,tail,state,audit_sha=_original_attempt(inv,plan,controller,
                                                  asset,step,work)
    require(state.get('last_audit_hash')==tail and
            sha(controller.master.read_bytes())==work['master_sha256'] and
            (state.get('active_step') or {}).get('step')==step and
            delivery['original_audit_sha256']==audit_sha and
            closure['original_audit_sha256']==audit_sha,
            'C07_T_MACRO_CURRENT_AUDIT_DRIFT')
    found={}
    for role,path,digest,raw in _registered_artifacts(
            audit,state,step,loader,work):
        require(role not in found,'C07_T_MACRO_DUPLICATE_ORIGINAL_ROLE')
        found[role]=(path,digest,raw)
    pins=plan.get('p678_evidence_contract',{}).get('original_artifact_sha256',{})
    require(type(pins) is dict,'C07_T_MACRO_PRE_D_PIN_REQUIRED')
    def original(role,suffix=None):
        a=found.get(role)
        if a is None or (suffix is not None and not a[0].lower().endswith(suffix)):
            return None
        return a[2] if pins.get(role)==a[1] and sha(a[2])==a[1] else None
    source=original('SOURCE_EDITABLE','.blend')
    export=original('NATIVE_EXPORT','.glb')
    archive=original('DELIVERY_PACKAGE','.zip')
    plan_raw=original('P8_DELIVERY_PLAN','.json')
    guide_raw=original('P8_MAINTENANCE_GUIDE','.json')
    history_raw=original('P8_DEFECT_HISTORY','.json')
    method_raw=original('P8_METHOD_CHANGE','.json')
    before=original('BASELINE_SNAPSHOT','.glb')
    before_script=original('P8_METHOD_BEFORE','.py')
    after_script=original('P8_METHOD_AFTER','.py')
    target_raw=original('P8_ROOT_CAUSE_POLICY','.json')
    members=_zip(archive) if archive is not None else None
    dp=_json(plan_raw) if plan_raw is not None else {}
    guide=_json(guide_raw) if guide_raw is not None else {}
    history=_json(history_raw) if history_raw is not None else {}
    method=_json(method_raw) if method_raw is not None else {}
    policy=_json(target_raw) if target_raw is not None else {}
    native=None;baseline=None
    try:
        if export is not None:native=read_mesh_geometry(export)
        if before is not None:baseline=read_mesh_geometry(before)
    except (ValueError,KeyError,TypeError,IndexError,OverflowError):
        pass
    names=dp.get('required_members')
    source_name=dp.get('source_member')
    export_name=dp.get('export_member')
    valid_names=bool(type(names) is list and names and
        len(set(names))==len(names) and
        all(safe_member(x) for x in names) and
        safe_member(source_name) and safe_member(export_name) and
        {source_name,export_name,'DELIVERY_MANIFEST.json'}<=set(names))
    package_ok=bool(valid_names and members and set(names)<=set(members)
        and source is not None and export is not None
        and members.get(source_name)==source
        and members.get(export_name)==export)
    manifest=_json(members['DELIVERY_MANIFEST.json']) if package_ok else {}
    identities=bool(package_ok and manifest.get('asset')==asset
        and manifest.get('version')==dp.get('version') and
        manifest.get('source_member')==source_name
        and manifest.get('export_member')==export_name
        and manifest.get('source_sha256')==sha(source)
        and manifest.get('export_sha256')==sha(export)
        and dp.get('source_sha256')==sha(source)
        and dp.get('export_sha256')==sha(export))
    readable=bool(native is not None and
        native['triangles']>0 and native['primitive_count']>0)
    checks={key:False for key in RULES[rule_id]}
    if rule_id=='AAA-200-T-191':
        vals=(bool(source and export and plan_raw),
              package_ok,
              bool(readable and identities))
    elif rule_id=='AAA-200-T-193':
        vals=(package_ok, bool(package_ok and readable),
              bool(package_ok and blender_blocks(source)))
    elif rule_id=='AAA-200-T-195':
        paths=guide.get('install_paths')
        steps=guide.get('maintenance_steps')
        exact=bool(type(guide) is dict and set(guide)=={
            'asset','source_sha256','export_sha256','install_paths',
            'maintenance_steps','status','owner_approved'})
        bound=bool(exact and guide.get('asset')==asset and
            source is not None and export is not None and
            guide.get('source_sha256')==sha(source) and
            guide.get('export_sha256')==sha(export) and
            guide.get('owner_approved') is False and
            guide.get('status')=='CANDIDATE')
        # Guide must mention the actual source and native export paths, not
        # arbitrary claimed filenames or an undocumented extra.
        paths_ok=bool(bound and valid_names and type(paths) is list and
            set(paths)=={source_name,export_name} and len(paths)==2 and
            type(steps) is list and len(steps)==3 and
            all(type(s) is str and 5<=len(s)<=300 for s in steps))
        instructions=bool(paths_ok and all(token in ' '.join(steps).lower()
            for token in ('source','version','revalidate')))
        vals=(bound,paths_ok,instructions)
    else:
        issues=history.get('issues')
        recurring=bool(type(issues) is list and 2<=len(issues)<=100
            and all(type(i) is dict and
                set(i)=={'id','root_cause','corrective_action',
                         'before_sha256','after_sha256'} and
                type(i['id']) is str and i['id'] and
                i['root_cause']=='ORIGIN_DEVIATION' and
                type(i['corrective_action']) is str and
                i['corrective_action'] and
                export is not None and
                i['after_sha256']==sha(export) for i in issues)
            and len(set(i['id'] for i in issues))==len(issues))
        center=policy.get('target_bbox_min')
        threshold=policy.get('max_origin_error_m')
        original_policy=bool(target_raw is not None and
            policy.get('schema')=='c07-p8-origin-defect-pre-d-v1' and
            policy.get('asset')==asset and
            finite(threshold) and 0<=threshold<=1 and
            type(center) is list and len(center)==3 and
            all(finite(x) for x in center))
        prior_error=_origin_error(baseline,center) if baseline and original_policy else None
        after_error=_origin_error(native,center) if native and original_policy else None
        # Two text rows pointing at one 'before' GLB are not recurrence.
        # Each original case is a different hash-pinned, independently decoded
        # mesh with a measured pre-correction origin defect.
        independently_bad=[]
        if recurring and original_policy:
            for issue in issues:
                case_id=issue['id']
                if type(case_id) is not str or not re.fullmatch(r'case-[A-Z]',case_id):
                    independently_bad=[];break
                role='P8_DEFECT_CASE_'+case_id[-1]
                case_raw=original(role,'.glb')
                if case_raw is None or sha(case_raw)!=issue['before_sha256']:
                    independently_bad=[];break
                try:
                    measured=read_mesh_geometry(case_raw)
                    deviation=_origin_error(measured,center)
                except (ValueError,TypeError,KeyError,IndexError,OverflowError):
                    independently_bad=[];break
                if deviation is None or deviation<=threshold:
                    independently_bad=[];break
                independently_bad.append((sha(case_raw),deviation))
        separate_cases=bool(recurring and len(independently_bad)==len(issues)
            and len({h for h,_ in independently_bad})==len(issues))
        was_bad=bool(separate_cases and original_policy and
             prior_error is not None and prior_error>threshold)
        fixed=bool(was_bad and after_error is not None and
             after_error<=threshold and after_error<prior_error and
             all(after_error<error for _,error in independently_bad) and
             before is not None and sha(before)!=sha(export))
        if rule_id=='AAA-200-T-198':
            vals=(separate_cases,was_bad,fixed)
        else:
            changed=bool(before_script and after_script and
                before_script!=after_script and method.get('before_sha256')==
                sha(before_script) and method.get('after_sha256')==
                sha(after_script))
            parsed=bool(changed and _safe_origin_formula(before_script)==
                        (0.0,0.0,0.0) and
                        _safe_origin_formula(after_script) not in
                        (None,(0.0,0.0,0.0)))
            genuine_effect=bool(parsed and before is not None and
                    export is not None and _method_reproduces_actual_geometry(
                        before_script,after_script,before,export))
            vals=(changed and parsed,
                  bool(fixed and genuine_effect and
                       method.get('root_cause')=='ORIGIN_DEVIATION'),
                  bool(fixed and genuine_effect and
                       method.get('verification_method')==
                       'independent_bbox_origin_measurement'))
    checks=dict(zip(RULES[rule_id],map(bool,vals)))
    return {
        'rule_id':rule_id,'checks':checks,
        'evidence_complete':bool(all(x is not None for x in
            ((archive,source,export,plan_raw) if rule_id in
                ('AAA-200-T-191','AAA-200-T-193') else
             (guide_raw,source,export,plan_raw) if rule_id==
                'AAA-200-T-195' else
             (history_raw,target_raw,before,export,method_raw,
              before_script,after_script) if rule_id=='AAA-200-T-199'
             else (history_raw,target_raw,before,export)))),
        'original_audit_sha256':audit_sha,
        'original_audit_tail':tail,
        'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'advancement_authorized':False,
        'fivem_runtime':'UNVERIFIED',
        'owner_acceptance':'UNVERIFIED',
    }
