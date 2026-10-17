"""C07 R124: eight additional canonical P0 process-rule positive *evidence predicates*.

Executes original Controller audit and original registered bytes. Every rule has
literal canonical text, source identity, explicit machine criteria and missing
semantic limits. Scoped positive != complete-rule PASS != independent MG0 PASS.
Assets never go to Git. This is not a vendor, licence, owner or artistic review.
"""
import hashlib
import json
import math
import re
import struct
from pathlib import Path
from zipfile import ZipFile, BadZipFile
import io

from c07_positive_native_process import (
    _original_attempt, _registered_artifacts, sha,
    NativeEvidenceBlocked as EvidenceBlocked,
)

TEXT = {
 171:'Organizzare i sorgenti con nomi e strutture coerenti.',
 173:'Utilizzare il controllo versione per proteggere il lavoro.',
 174:'Conservare copie verificabili degli asset approvati.',
 175:'Automatizzare verifiche ripetitive quando il beneficio è concreto.',
 176:'Verificare che gli script producano il risultato atteso, non soltanto che terminino senza errori.',
 177:'Evitare che una procedura automatica sovrascriva asset approvati.',
 179:'Riprendere da un checkpoint valido dopo un’interruzione, senza duplicare lavoro.',
 180:'Misurare il progresso tramite produzione effettiva, non tramite quantità di registrazioni o documenti.',
}
SCHEMA='gg-c07-r124-eight-source-positive-process-evidence-v1'
MAX_GLB=250_000_000
SHA=re.compile(r'[a-f0-9]{64}\Z')


def need(value,reason):
    if not value: raise EvidenceBlocked(reason)


def _verified_rules(inventory):
    need(inventory.get('schema')=='gg-effective-family-inventory-v1' and
         inventory.get('rule_count')==763 and isinstance(inventory.get('source_digests'),dict),
         'R124_CANONICAL_INVENTORY_REQUIRED')
    source=inventory['source_digests'].get('aaa_catalog')
    need(type(source) is str and SHA.fullmatch(source),'R124_SOURCE_PIN_MISSING')
    for num, requirement in TEXT.items():
        rid=f'AAA-200-R-{num:03}'
        row=inventory['rules'].get(rid)
        need(type(row) is dict and row.get('family')=='AAA-200' and
             row.get('catalog_number')==num and row.get('catalog_phase')=='P0' and
             row.get('catalog_section')=='R' and row.get('requirement')==requirement and
             row.get('source_sha256')==source and
             row.get('requirement_sha256')==sha(requirement.encode('utf-8')),
             'R124_SOURCE_CLAUSE_DRIFT:'+rid)


def _glb_mesh(raw):
    """Verify real GLB2 nondegenerate POSITION bytes, not just JSON mesh names.

    Strictly bounded supporting evidence. Does NOT prove UV/PBR, proper scale,
    collision, scene visibility, runtime compatibility or artistic approval.
    """
    if type(raw) is not bytes or not 48<=len(raw)<=MAX_GLB:
        return False
    try:
        magic,ver,declared=struct.unpack_from('<4sII',raw,0)
        if magic!=b'glTF' or ver!=2 or declared!=len(raw): return False
        jlen,jtype=struct.unpack_from('<I4s',raw,12)
        if jtype!=b'JSON' or jlen<2 or jlen%4 or 20+jlen+8>len(raw): return False
        doc=json.loads(raw[20:20+jlen].decode('utf-8'))
        bin_length,bin_type=struct.unpack_from('<I4s',raw,20+jlen)
        start=28+jlen
        if bin_type!=b'BIN\x00' or bin_length%4 or start+bin_length!=len(raw): return False
        buffers=doc.get('buffers',[])
        views=doc.get('bufferViews',[])
        accessors=doc.get('accessors',[])
        meshes=doc.get('meshes',[])
        if not (type(buffers) is list and len(buffers)==1 and
                type(views) is list and type(accessors) is list and type(meshes) is list):
            return False
        if type(buffers[0].get('byteLength')) is not int or not 0<buffers[0]['byteLength']<=bin_length:
            return False
        for mesh in meshes:
            if type(mesh) is not dict:continue
            for prim in mesh.get('primitives',[]):
                if type(prim) is not dict or prim.get('mode',4)!=4: continue
                i=prim.get('attributes',{}).get('POSITION')
                if type(i) is not int or not 0<=i<len(accessors):continue
                acc=accessors[i]
                if type(acc) is not dict or type(acc.get('count')) is not int or acc['count']<3 \
                        or acc.get('type')!='VEC3' or acc.get('componentType')!=5126 \
                        or acc.get('sparse') is not None: continue
                v=acc.get('bufferView')
                if type(v) is not int or not 0<=v<len(views):continue
                view=views[v]
                if type(view) is not dict or view.get('buffer')!=0:continue
                vo=view.get('byteOffset',0)
                ao=acc.get('byteOffset',0)
                ln=view.get('byteLength')
                stride=view.get('byteStride',12)
                if any(type(x) is not int for x in (vo,ao,ln,stride)) or \
                   min(vo,ao,ln,stride)<0 or stride<12 or stride%4 or ao%4:
                    continue
                length=(acc['count']-1)*stride+12
                if ao+length>ln or vo+ln>buffers[0]['byteLength']:continue
                offset=start+vo+ao
                points=[struct.unpack_from('<3f',raw,offset+k*stride) for k in range(3)]
                if not all(math.isfinite(c) for p in points for c in p):continue
                a,b,c=points
                u=tuple(b[k]-a[k] for k in range(3))
                v=tuple(c[k]-a[k] for k in range(3))
                cross=(u[1]*v[2]-u[2]*v[1],u[2]*v[0]-u[0]*v[2],u[0]*v[1]-u[1]*v[0])
                if sum(x*x for x in cross)>1e-16:return True
    except (ValueError, KeyError, AttributeError, IndexError, TypeError, UnicodeError,
            json.JSONDecodeError, struct.error):
        return False
    return False

def _audit_evidence(records, attempt_id, operation_sha256):
    return [e for e in records if e.get('attempt_id')==attempt_id and
            e.get('operation_sha256')==operation_sha256]


def _has_native_check(e):
    """Positive for a *recorded* machine check only; never asserts it truly passed."""
    if e.get('event')!='SUPERVISOR_CANONICAL_NATIVE_NEGATIVE_GATE':return False
    reports=e.get('native_reports')
    if type(reports) is not list or not reports:return False
    raw=json.dumps(reports,sort_keys=True,separators=(',',':')).encode()
    return e.get('native_reports_sha256')==sha(raw) and e.get('advancement_authorized') is False


def _same_sha_two_paths(artifacts, first, second):
    a=[x for x in artifacts if x[0]==first]
    b=[x for x in artifacts if x[0]==second]
    return len(a)==len(b)==1 and a[0][1]!=b[0][1] and a[0][2]==b[0][2]


def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    """One source-locked original readback; 8 independent rule-specific checks.

    Missing evidence stays UNKNOWN, negative evidence may hard block; no
    invented original art or human approvals, no producer-PASS shortcut.
    """
    need(callable(source_loader),'R124_ORIGINAL_BYTE_READER_REQUIRED')
    _verified_rules(inventory)
    records,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'R124_MASTER_STATE_OR_AUDIT_DRIFT')
    artifacts=_registered_artifacts(records,state,step,source_loader)
    by_role={r: [x for x in artifacts if x[0]==r] for r in (
        'SOURCE_EDITABLE','NATIVE_EXPORT','DELIVERY_PACKAGE',
        'BASELINE_SNAPSHOT','CURRENT_SOURCE_COPY')}
    scopes=_audit_evidence(records,work['attempt_id'],work['operation_sha256'])
    audit_identity=all(type(x.get('record_hash')) is str and SHA.fullmatch(x['record_hash'])
                       for x in scopes)
    artifact_paths=[Path(a[1]) for a in artifacts]
    roles=[a[0] for a in artifacts]
    names=[p.name for p in artifact_paths]
    input_files=[a for a in artifacts if a[0]=='SOURCE_EDITABLE']
    exports=[a for a in artifacts if a[0]=='NATIVE_EXPORT']
    glb_nonempty=[a for a in exports if Path(a[1]).suffix.lower()=='.glb'
                  and _glb_mesh(a[3])]
    genuine_output=bool(glb_nonempty)
    report_checks=[e for e in scopes if _has_native_check(e)]
    # Explicit state/version snapshots are not equivalent to approved backups.
    backups=_same_sha_two_paths(artifacts,'BASELINE_SNAPSHOT','CURRENT_SOURCE_COPY')
    if backups:
        prior=by_role['BASELINE_SNAPSHOT'][0]
        protected=by_role['CURRENT_SOURCE_COPY'][0]
        backups=prior[2]==protected[2] and prior[1]!=protected[1]
    steps=[e for e in records if e.get('event')=='STEP_OPEN' and e.get('step')==step]
    opened=[e for e in records if e.get('event')=='SUPERVISOR_OPERATION_OPENED'
            and e.get('step')==step]
    reserved=[e for e in records if e.get('event')=='SUPERVISOR_OPERATION_RESERVED'
              and e.get('work')==work]
    # Unique transaction and no duplicate close means one observed attempt,
    # not proof of recovery from a previous checkpoint.
    transaction_unique=len(steps)==len(opened)==len(reserved)==1 and not any(
        e.get('event')=='STEP_CLOSE' and e.get('step')==step for e in records)
    basename_coherent=(len(input_files)==len(exports)==1 and
                       artifact_paths[roles.index('SOURCE_EDITABLE')].stem==
                       artifact_paths[roles.index('NATIVE_EXPORT')].stem)
    checked={
       171:{'registered_source_and_export_bytes':len(input_files)==len(exports)==1,
            'source_export_name_stems_coherent':basename_coherent,
            'no_duplicate_artifact_names':len(names)==len(set(names)),
            'explicit_source_export_roles':all(roles.count(r)==1 for r in ('SOURCE_EDITABLE','NATIVE_EXPORT'))},
       173:{'current_attempt_in_append_only_audit':bool(reserved) and transaction_unique,
            'prior_version_history_independently_read':bool([e for e in records
               if e.get('event')=='SUPERVISOR_OPERATION_CLOSED' and e.get('result')=='PASS'
               and e.get('attempt_id')!=work['attempt_id']]),
            'original_asset_version_control_verified':False},
       174:{'two_distinct_registered_protected_files_byte_identical':backups,
            'original_approval_source_authenticated':False,
            'preservation_after_current_attempt_authenticated':False},
       175:{'repeated_distinct_source_bound_machine_checks_observed':len({e['record_hash'] for e in report_checks})>=2,
            'machine_checks_on_current_attempt':bool(report_checks),
            'real_benefit_measured_not_assumed':False},
       176:{'nonempty_export_bytes_independently_parsed':genuine_output,
            'registered_output_bytes_match_source':all(a[2]==sha(a[3]) for a in glb_nonempty),
            'required_geometry_outcome_independently_verified':False,
            'native_exit_code_not_only_proof':genuine_output},
       177:{'prior_protected_bytes_equal_current_copy':backups,
            'source_original_approved_lock_authenticated':False,
            'no_unobserved_overwrite_proven':False},
       179:{'one_unique_reservation_and_open':transaction_unique,
            'exact_current_attempt_binding':bool(reserved) and transaction_unique,
            'original_prior_checkpoint_sha_verified':False,
            'no_duplicated_work_across_earlier_attempts_proven':False},
       180:{'new_non_document_binary_output_present':genuine_output,
            'output_is_not_just_report_or_exit_code':genuine_output,
            'previous_output_original_bytes_compared':False,
            'measured_quality_or_completion_delta_verified':False},
    }
    result={}
    for n,checks in checked.items():
        rid=f'AAA-200-R-{n:03}'
        observed=all(v is True for v in checks.values())
        positives=sorted(k for k,v in checks.items() if v is True)
        missing=sorted(k for k,v in checks.items() if v is not True)
        result[rid]={
            'rule_id':rid,'requirement_sha256':sha(TEXT[n].encode()),
            'source_sha256':inventory['rules'][rid]['source_sha256'],
            'machine_checks':checks,'positive_subpredicates':positives,
            'missing_subpredicates':missing,
            'machine_scope':'OBSERVED_SCOPE_PASS' if observed else 'PARTIAL_OR_UNKNOWN',
            'full_rule_semantics':'UNKNOWN','independent_git_native_semantics':'UNKNOWN',
            'individual_mg0':'UNKNOWN','artistic_approval':'UNKNOWN',
            'advancement_authorized':False,
        }
    return {'schema':SCHEMA,'source_rules_evaluated':8,'rules':result,
        'observed_scoped_predicates':sum(len(x['positive_subpredicates']) for x in result.values()),
        'full_native_semantic_certifications_new':0,
        'full_current_attempt_rule_passes':0,'individual_mg0_passes':0,
        'real_controller_audit_sha256':audit_sha,'real_controller_audit_tail':tail,
        'master_sha256':work['master_sha256'],'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'source_specific_missing':{rid:x['missing_subpredicates'] for rid,x in result.items()},
        'advancement_authorized':False}