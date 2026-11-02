"""C07 original 100: 40 remaining AAA-200 + 60 remaining BEHAVIOR rules.

Reads the same authenticated original work attempt, real registered SHA-bound
artifacts, plan, Controller audit, and GLB/PBR/winding bytes. Each of 100 rules
has individually named and required source predicates. Observed machine
evidence is *not* full semantic satisfaction, owner approval, game proof,
behavioral enforcement, or individual MG0 certification.

No new objects/assets, accepted baseline, MASTER or original source are changed.
"""
import re
from pathlib import Path
from c07_positive_native_process import _original_attempt,_registered_artifacts,sha
from glb_machine_qa import audit_bytes,parse,MAX_BYTES,GLBError
from glb_winding_readback import scan_bytes,WindingBlocked
from glb_pbr_evidence import validate_png_chunks,MaterialEvidenceError
from c07_batch100_canonical import (
    AAA,BEHAVIOR,AAA_IDS,BEHAVIOR_IDS,IDS,CATALOG_SHA,REGISTRY_SHA
)
from c07_batch100_predicates import AAA_SPEC,BEHAVIOR_SPEC
from c07_batch100_probes import AAA_PROBES,BEHAVIOR_PROBES

SCHEMA="gg-c07-batch100-all-original-domain-native-v1"
class Batch100Blocked(ValueError):pass
def need(test,reason):
    if not test:raise Batch100Blocked(reason)
def nonempty(x):return type(x) is str and bool(x.strip())

def pin_sources(inv):
    need(type(inv) is dict and inv.get('schema')=='gg-effective-family-inventory-v1'
         and inv.get('rule_count')==763
         and inv.get('source_digests',{}).get('aaa_catalog')==CATALOG_SHA
         and inv.get('source_digests',{}).get('error_registry')==REGISTRY_SHA
         and len(AAA)==40 and len(BEHAVIOR)==60 and len(IDS)==100
         and len(set(IDS))==100 and
         set(AAA)==set(AAA_SPEC)==set(AAA_PROBES) and
         set(BEHAVIOR)==set(BEHAVIOR_SPEC)==set(BEHAVIOR_PROBES),
         'BATCH100_CANONICAL_100_SOURCE_IDS_REQUIRED')
    rules=inv.get('rules',{})
    for n,(letter,wording,phase,kind) in AAA.items():
        rid='AAA-200-'+letter+'-%03d'%n
        row=rules.get(rid,{})
        need(row.get('family')=='AAA-200' and
             row.get('catalog_number')==n and
             row.get('catalog_section')==letter and
             row.get('catalog_phase')==phase and
             row.get('asset_type')==kind and
             row.get('source_sha256')==CATALOG_SHA and
             row.get('requirement')==wording and
             row.get('requirement_sha256')==sha(wording.encode('utf-8')),
             'BATCH100_AAA_LITERAL_RULE_CHANGED:'+rid)
    for n,wording in BEHAVIOR.items():
        rid='BEHAVIOR-%03d'%n
        row=rules.get(rid,{})
        need(row.get('family')=='BEHAVIOR_110' and
             row.get('source')=='error_registry' and
             row.get('source_path')==
                'governance/sources/REGISTRO_110_ERRORI_E_PREVENZIONE.md'
             and row.get('source_sha256')==REGISTRY_SHA and
             row.get('requirement_sha256')==sha(wording.encode('utf-8'))
             and row.get('requirement')==wording
             and row.get('required_mg0') is True,
             'BATCH100_BEHAVIOR_LITERAL_RULE_CHANGED:'+rid)

def actual_originals(records,artifacts,plan,state,work,asset,step,controller,source_loader):
    """All positive observations trace to SHA-matched original artifact bytes,
    original Controller state, original plan, or audited exact-attempt events."""
    by_role={};paths=set()
    for role,path,digest,raw in artifacts:
        need(type(role) is str and nonempty(role) and
             type(path) is str and nonempty(path) and path not in paths and
             type(digest) is str and re.fullmatch('[a-f0-9]{64}',digest) and
             type(raw) is bytes and len(raw)>0 and sha(raw)==digest,
             'BATCH100_UNAUTHENTICATED_OR_DUPLICATED_ORIGINAL_ARTIFACT')
        paths.add(path)
        by_role.setdefault(role,[]).append((path,digest,raw))
    def role_row(name):
        values=by_role.get(name,())
        return values[0] if len(values)==1 else None

    glbs=[x for x in by_role.get('NATIVE_EXPORT',())
          if Path(x[0]).suffix.lower()=='.glb']
    need(len(glbs)<=1,'BATCH100_AMBIGUOUS_NATIVE_ORIGINAL_GLB')
    technical=None;glb=None;winding=None
    if glbs:
        raw=glbs[0][2]
        need(len(raw)<=MAX_BYTES,'BATCH100_GLB_EXCEEDS_BYTE_BUDGET')
        try:
            technical=audit_bytes(raw)
            glb,_=parse(raw)
            need(technical['source_sha256']==glbs[0][1],
                 'BATCH100_GLB_ORIGINAL_SHA_MISMATCH')
            try:
                winding=scan_bytes(raw,glbs[0][1])
            except (WindingBlocked,GLBError,ValueError,TypeError,KeyError,IndexError):
                winding=None
        except (GLBError,ValueError,TypeError,KeyError,IndexError,
                OverflowError,RecursionError) as exc:
            raise Batch100Blocked('BATCH100_CORRUPT_ORIGINAL_GLB:'+str(exc)) from exc
    pbr=(technical or {}).get('material_source_evidence',{})
    cross=(technical or {}).get('triangle_surface_crossing_evidence',{})
    mats=(glb or {}).get('materials',[])
    meshes=(glb or {}).get('meshes',[])
    prims=[p for m in meshes for p in m.get('primitives',())]
    attrs=[p.get('attributes',{}) for p in prims]
    dims=[x for x in pbr.get('referenced_image_dimensions',{}).values()
          if type(x) is list and len(x)==2 and
          all(type(z) is int and z>0 for z in x)]
    current=[x for x in records if
             x.get('step')==step and
             x.get('attempt_id')==work.get('attempt_id') and
             x.get('operation_sha256')==work.get('operation_sha256')]
    def event(name):
        return any(x.get('event')==name for x in current)
    def field(path):
        obj=plan
        for part in path.split('.'):
            if type(obj) is not dict or part not in obj:return None
            obj=obj[part]
        return obj
    def original_role(name):
        row=role_row(name)
        if not row:return False
        suffix=Path(row[0]).suffix.lower()
        if name.startswith('VISUAL_VIEW_'):
            if suffix!='.png':return False
            try:
                validate_png_chunks(row[2])
                return True
            except (MaterialEvidenceError,ValueError,TypeError,KeyError,IndexError):
                return False
        if name=='NATIVE_EXPORT' and suffix=='.glb':
            return technical is not None
        # For other roles, this is a SHA-attested REGISTERED FILE observation,
        # not a claim the file contents pass their domain-specific semantics.
        return True
    def dep_readback():
        deps=field('dependency_files')
        work_deps=work.get('work_dependencies')
        if type(deps) is not dict or not deps or type(work_deps) is not dict:
            return False
        if set(deps)!=set(work_deps):return False
        root=getattr(controller,'root',None)
        if not isinstance(root,Path):return False
        for key,path in deps.items():
            need(type(key) is str and re.fullmatch('[a-f0-9]{64}',key)
                 and nonempty(path) and not Path(path).is_absolute()
                 and '..' not in Path(path).parts and
                 (root/path).resolve().is_relative_to(root.resolve()),
                 'BATCH100_DEPENDENCY_ESCAPED_ORIGINAL_CONTROLLER_ROOT')
            raw=source_loader(str(root/path))
            if type(raw) is not bytes or sha(raw)!=work_deps[key]:return False
        return True

    def metric(name):
        if technical is None:return False
        return {
          'valid_glb':not technical['errors'] and
                      not technical['unsupported_requires_independent_check'],
          'triangles':technical['triangles_examined']>0,
          'primitives':technical['mesh_primitives']>0,
          'vertices':technical['vertices_examined']>0,
          'zero_degenerate':technical['degenerate_triangles']==0,
          'zero_nonfinite':technical['nonfinite_positions']==0,
          'normals':bool(attrs) and all('NORMAL' in a for a in attrs),
          'uv_scans':pbr.get('uv_sets_finite_checked',0)>0,
          'texture_dimensions':bool(dims),
          'material_count':pbr.get('used_materials_count',0)>0,
          'texture_count':pbr.get('referenced_textures_count',0)>0,
          'normal_texture':any(type(m) is dict and 'normalTexture' in m for m in mats),
          'tangents':any('TANGENT' in a for a in attrs),
          'transforms':technical['checks'].get('static_world_transform')=='VERIFIED',
          'bounds':technical['geometry_groups_with_bounds']>0,
          'overlap_count':type(technical.get('aabb_overlap_candidates_count')) is int,
          'valid_pbr':not pbr.get('pbr_structural_errors',[]),
          'alpha_material':any(type(m) is dict and
                      m.get('alphaMode') in ('MASK','BLEND') for m in mats),
        }.get(name,False)
    def checked(name):
        kind,_,key=name.partition(':')
        if kind=='R':return original_role(key)
        if kind=='E':return event(key)
        if kind=='P':
            val=field(key)
            return bool(val) and type(val) in (dict,list,str,int,float)
        if kind=='M':return metric(key)
        if kind=='X':
            return {
              'master':sha(controller.master.read_bytes())==work.get('master_sha256'),
              'audit':state.get('last_audit_hash')==(
                  records[-1]['record_hash'] if records else state.get('last_audit_hash')),
              'operation':type(work.get('operation_sha256')) is str and
                  re.fullmatch('[a-f0-9]{64}',work['operation_sha256']) is not None,
              'deps':dep_readback(),
              'pending':state.get('delivery_status') in ('PENDING','NOT_DELIVERABLE','BLOCKED'),
              'export_changed':bool(role_row('BASELINE_SNAPSHOT') and
                  role_row('NATIVE_EXPORT') and
                  role_row('BASELINE_SNAPSHOT')[1]!=role_row('NATIVE_EXPORT')[1]),
              'winding':winding is not None,
              'winding_clean':winding is not None and
                  winding['orientation_conflict_meshes']==0 and
                  winding['nonmanifold_edges']==0,
              'crossings_complete':cross.get('all_requested_pairs_fully_scanned') is True,
              'registry':False,
              'unknown_protected':False,
              'no_sensitive_data_unknown':False,
            }.get(key,False)
        raise Batch100Blocked('BATCH100_UNKNOWN_EVIDENCE_KIND:'+name)
    return checked, technical

def inspect(inv,plan,controller,asset,step,work,*,source_loader):
    need(callable(source_loader),'BATCH100_ORIGINAL_SOURCE_READER_REQUIRED')
    pin_sources(inv)
    records,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==
         inv['canonical_master_sha256']==work.get('master_sha256') and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'BATCH100_MASTER_STATE_OR_AUDIT_SHA_DRIFT')
    artifacts=_registered_artifacts(records,state,step,source_loader,work)
    checked,technical=actual_originals(records,artifacts,plan,state,work,
                                      asset,step,controller,source_loader)
    need(len(AAA_PROBES)==40 and len(BEHAVIOR_PROBES)==60
         and set(AAA_SPEC)==set(AAA_PROBES) and
         set(BEHAVIOR_SPEC)==set(BEHAVIOR_PROBES),
         'BATCH100_MISSING_PER_RULE_NATIVE_PREDICATE')
    results={};count=0;observed=0
    for family,sources,scopes,probes in (
          ('AAA',AAA,AAA_SPEC,AAA_PROBES),
          ('BEHAVIOR',BEHAVIOR,BEHAVIOR_SPEC,BEHAVIOR_PROBES)):
        for n,clause in sources.items():
            rid=('AAA-200-'+clause[0]+'-%03d'%n if family=='AAA'
                 else 'BEHAVIOR-%03d'%n)
            names=scopes[n];descriptors=probes[n]
            expected=4 if family=='AAA' else 3
            need(len(names)==expected and len(set(names))==expected and
                 len(descriptors)==expected-1 and
                 all(type(x) is str and ':' in x for x in descriptors),
                 'BATCH100_SOURCE_SPECIFIC_PROBES_MISSING:'+rid)
            positives={field:bool(checked(descriptor))
                       for field,descriptor in zip(names,descriptors)}
            need(names[-1] not in positives,
                 'BATCH100_ARTISTIC_OR_BEHAVIOR_MG0_AUTOPASS_FORBIDDEN:'+rid)
            conditions={**positives,names[-1]:False}
            count+=len(conditions)
            observed+=sum(conditions.values())
            phase=clause[2] if family=='AAA' else None
            current=work.get('phase')
            order=['P0','P1','P2','P3','P4','P5','P6','P7','P8']
            if phase and current not in order:
                applicability='UNKNOWN'
            elif phase and order.index(current)<order.index(phase):
                applicability='FUTURE_PHASE'
            else:applicability='DUE'
            results[rid]={
               'rule_id':rid,
               'canonical_requirement':clause[1] if family=='AAA' else clause,
               'source_sha256':CATALOG_SHA if family=='AAA' else REGISTRY_SHA,
               'requirement_sha256':inv['rules'][rid]['requirement_sha256'],
               'applicability':applicability,
               'original_native_criteria':conditions,
               'observed_original_source_conditions':sorted(
                   k for k,v in conditions.items() if v),
               'unproven_conditions':sorted(k for k,v in conditions.items() if not v),
               'full_rule_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
               'owner_approval':'UNKNOWN','advancement_authorized':False,
            }
    need(len(results)==100 and set(results)==set(IDS) and count==340
         and all(type(v) is bool for row in results.values()
                 for v in row['original_native_criteria'].values()),
         'BATCH100_HUNDRED_REAL_RULE_OBSERVATIONS_NOT_COMPLETE')
    return {
      'schema':SCHEMA,'source_rules_examined':100,
      'aaa_rules_examined':40,'behavior_rules_examined':60,
      'native_conditions_evaluated':340,
      'native_conditions_observed':observed,
      'attempt_id':work['attempt_id'],
      'operation_sha256':work['operation_sha256'],
      'original_audit_sha256':audit_sha,'original_audit_tail':tail,
      'original_glb_sha256':technical['source_sha256'] if technical else None,
      'full_rule_passes':0,'individual_mg0_passes':0,
      'advancement_authorized':False,'rules':results,
    }
