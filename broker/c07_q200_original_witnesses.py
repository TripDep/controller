"""R148: 200 canonically sourced original-question evidence witnesses.

Existing C07 300-question bank already establishes rule identity, contextual
applicability and UNKNOWN by default. This module adds 200 question-specific
real current-attempt witness slots (Q-001..Q-200). Each slot must be
pre-enrolled with the exact question's source SHA and current registered
original file SHA. One independently measured machine property is evaluated
by the relevant *question family* (10 different measurable domains).

Authentic witness bytes prove only that an evidence item is real and tied
to the current attempt. They do NOT prove the whole natural-language
question, actual artwork, owner approval, FiveM runtime or individual MG0.
A self-reported YES is never used to mark the source question PASS.
"""
import hashlib
import json
import re
from pathlib import Path
from c07_questions_300 import extract_bank
from c07_positive_native_process import _original_attempt,_registered_artifacts,sha
from c07_native_output_oracle import read_mesh_geometry, OriginalGeometryBlocked
from c07_a10_c10_original_evidence import original_image
from c07_positive200_evidence import R122_FROZEN_IDS

SCHEMA='gg-c07-r148-q200-current-original-witness-v1'
CONTRACT='gg-c07-r148-200-pre-d-actual-evidence-slots-v1'
IDS=tuple('Q-'+str(i).zfill(3) for i in range(1,201))
DOMAINS=('GOAL','REFERENCE','DEPENDENCIES','GEOMETRY','STRUCTURAL',
         'PLAYER','COMPLETENESS','MATERIAL','PACKAGE','FAILURE')
ROLES={
 'GOAL':'Q200_GOAL_BRIEF',
 'REFERENCE':'REFERENCE_IMAGE',
 'DEPENDENCIES':'Q200_DEPENDENCY_REGISTER',
 'GEOMETRY':'NATIVE_EXPORT',
 'STRUCTURAL':'Q200_STRUCTURAL_QA',
 'PLAYER':'Q200_PLAYER_QA',
 'COMPLETENESS':'P8_REQUIRED_FILES',
 'MATERIAL':'MATERIAL_REFERENCE_IMAGE',
 'PACKAGE':'DELIVERY_PACKAGE',
 'FAILURE':'Q200_REGRESSION_REPORT',
}
class OriginalQuestionBlocked(ValueError):pass
def need(ok,reason):
    if not ok:raise OriginalQuestionBlocked(reason)
def digest(obj):
    return sha(json.dumps(obj,sort_keys=True,separators=(',',':'),
                         ensure_ascii=False,allow_nan=False).encode())
def structured(raw):
    if type(raw) is not bytes or not 0<len(raw)<=2_000_000:return {}
    try:
        value=json.loads(raw)
        return value if type(value) is dict else {}
    except (TypeError,ValueError,UnicodeError):return {}
def domain_for(number):
    need(type(number) is int and 1<=number<=200,'R148_QUESTION_NUMBER')
    return DOMAINS[(number-1)//20]
def file_type_for(domain):return ROLES[domain]

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and inventory.get('schema')==
         'gg-effective-family-inventory-v1' and
         inventory.get('rule_count')==763 and len(IDS)==200 and
         set(IDS).isdisjoint(set(R122_FROZEN_IDS)) and
         callable(source_loader),
         'R148_CANONICAL_200_QUESTION_SCOPE_REQUIRED')
    raw=controller.master.read_bytes()
    need(sha(raw)==inventory.get('canonical_master_sha256')==
         work.get('master_sha256')==plan.get('master_sha256'),
         'R148_LIBRARY_MASTER_CURRENT_SHA_CHANGED')
    bank=extract_bank(raw)
    need(len(bank)==300 and inventory['families'].get('QUESTIONS_300')==
         ['Q-'+str(n).zfill(3) for n in range(1,301)],
         'R148_CANONICAL_300_SOURCE_BANK_MISSING')
    for rid in IDS:
        row=inventory['rules'].get(rid,{})
        text=bank[rid]
        need(row.get('family')=='QUESTIONS_300' and row.get('source')=='master'
             and row.get('source_sha256')==sha(raw)
             and row.get('requirement')==text
             and row.get('requirement_sha256')==sha(text.encode('utf-8'))
             and row.get('required_mg0') is True,
             'R148_CHANGED_ORIGINAL_QUESTION:'+rid)
    rows,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'R148_AUDIT_CURRENT_STEP_CHANGED')
    registered=_registered_artifacts(rows,state,step,source_loader,work)
    file_rows={}
    for role,path,hexdigest,raw_bytes in registered:
        need(role not in file_rows,'R148_DUPLICATE_ORIGINAL_WITNESS_ROLE:'+role)
        file_rows[role]=(path,hexdigest,raw_bytes)
    def file_original(role):
        row=file_rows.get(role)
        return (row is not None and type(row[2]) is bytes and
                len(row[2])>0 and sha(row[2])==row[1])
    def doc(role):
        return structured(file_rows[role][2]) if file_original(role) else {}
    def image(role):
        return original_image(file_rows[role][2]) if file_original(role) else None
    def geometry(role):
        row=file_rows.get(role)
        if row is None or not row[0].lower().endswith('.glb'):return None
        try:return read_mesh_geometry(row[2])
        except (OriginalGeometryBlocked,ValueError,TypeError,IndexError,KeyError):return None
    sources={
     'GOAL':doc('Q200_GOAL_BRIEF'),
     'DEPENDENCIES':doc('Q200_DEPENDENCY_REGISTER'),
     'STRUCTURAL':doc('Q200_STRUCTURAL_QA'),
     'PLAYER':doc('Q200_PLAYER_QA'),
     'COMPLETENESS':doc('P8_REQUIRED_FILES'),
     'FAILURE':doc('Q200_REGRESSION_REPORT')
    }
    geometry_current=geometry('NATIVE_EXPORT')
    reference=image('REFERENCE_IMAGE')
    material=image('MATERIAL_REFERENCE_IMAGE')
    original_export=file_original('NATIVE_EXPORT')
    original_source=file_original('SOURCE_EDITABLE')
    old_geometry=geometry('BASELINE_SNAPSHOT')
    original_zip=file_original('DELIVERY_PACKAGE')
    state_failures=[r for r in rows if r.get('step')==step
                  and (r.get('result') in ('FAIL','BLOCKED') or
                  r.get('event')=='QUALITY_FINDING')]
    topic={
      'GOAL':bool(sources['GOAL'].get('asset')==asset and
                  isinstance(sources['GOAL'].get('deliverables'),list) and
                  sources['GOAL']['deliverables']),
      'REFERENCE':reference is not None,
      'DEPENDENCIES':bool(sources['DEPENDENCIES'].get('dependency_sha256') and
                        type(sources['DEPENDENCIES']['dependency_sha256']) is dict and
                        set(sources['DEPENDENCIES']['dependency_sha256'])==
                            set(plan.get('dependency_files',{}))),
      'GEOMETRY':bool(geometry_current and geometry_current['triangles']>0),
      'STRUCTURAL':bool(sources['STRUCTURAL'].get('component_ids') and
                        type(sources['STRUCTURAL']['component_ids']) is list
                        and geometry_current),
      'PLAYER':bool(sources['PLAYER'].get('player_height_m') and
                   type(sources['PLAYER']['player_height_m']) in (int,float)
                   and geometry_current),
      'COMPLETENESS':bool(type(sources['COMPLETENESS'].get('files')) is list and
                         sources['COMPLETENESS']['files'] and
                         all(name in file_rows for name in
                             sources['COMPLETENESS']['files'])),
      'MATERIAL':material is not None and original_export,
      'PACKAGE':bool(original_zip and original_source and original_export),
      'FAILURE':bool(type(sources['FAILURE'].get('failure_modes')) is list and
                      sources['FAILURE']['failure_modes']),
    }
    # Derive fresh independent machine fingerprints from original registered
    # files, not from producer-provided YES/NO responses or fake 64-hex proofs.
    fingerprints={
      'GOAL':digest(sources['GOAL']),
      'REFERENCE':reference['sha256'] if reference else None,
      'DEPENDENCIES':digest(sources['DEPENDENCIES']),
      'GEOMETRY':digest(geometry_current) if geometry_current else None,
      'STRUCTURAL':digest({'source':sources['STRUCTURAL'],
                            'geometry':geometry_current}),
      'PLAYER':digest({'source':sources['PLAYER'],'geometry':geometry_current}),
      'COMPLETENESS':digest(sources['COMPLETENESS']),
      'MATERIAL':material['sha256'] if material else None,
      'PACKAGE':file_rows['DELIVERY_PACKAGE'][1] if original_zip else None,
      'FAILURE':digest({'source':sources['FAILURE'],
                         'original_current_attempt_failures':[
                          r['record_hash'] for r in state_failures]})
    }
    evidence=plan.get('question_200_original_witnesses')
    envelope=type(evidence) is dict and evidence.get('schema')==CONTRACT
    enrolled=evidence.get('rules') if envelope else None
    if type(enrolled) is not dict:enrolled={}
    need(not (set(enrolled)-set(IDS)),
         'R148_UNREGISTERED_QUESTION_EVIDENCE_ID')
    # This is NOT an approval check. Even when a source file and live measure
    # agree, independent semantic, MG0 and owner review remain mandatory.
    current_failures={r.get('rule_id') for r in rows
        if r.get('step')==step and r.get('event') in
        ('VERIFIED_STATE_REVOKED','QUALITY_FINDING') and
        r.get('rule_id') in IDS and r.get('result') in ('FAIL','BLOCKED')}
    answers={};native_confirmed=0;negative=0
    for n,rid in enumerate(IDS,1):
        group=domain_for(n);source_role=file_type_for(group)
        source_row=file_rows.get(source_role)
        witness=enrolled.get(rid)
        spec_ok=(type(witness) is dict and
            set(witness)=={'question_sha256','source_role','source_sha256',
                           'measured_fingerprint','claim_status'}
            and witness.get('question_sha256')==
                inventory['rules'][rid]['requirement_sha256']
            and witness.get('source_role')==source_role
            and source_row is not None
            and witness.get('source_sha256')==source_row[1]
            and witness.get('claim_status')=='OBSERVATION_ONLY')
        verified=bool(spec_ok and topic[group] and
                      fingerprints[group] is not None and
                      witness['measured_fingerprint']==fingerprints[group] and
                      file_original(source_role))
        if rid in current_failures:negative+=1
        native_confirmed+=int(verified)
        answers[rid]={
          'rule_id':rid,
          'original_question':bank[rid],
          'source_sha256':inventory['rules'][rid]['source_sha256'],
          'requirement_sha256':inventory['rules'][rid]['requirement_sha256'],
          'question_domain':group,
          'individual_evidence_role':source_role,
          'original_file_readback_bound':bool(spec_ok and file_original(source_role)),
          'domain_machine_fingerprint_matches':verified,
          'current_attempt_failure_observed':rid in current_failures,
          'machine_evidence_scope':'SOURCE_OBSERVED' if verified
                    else 'UNKNOWN',
          'semantic_verdict':'FAIL' if rid in current_failures else 'UNKNOWN',
          'individual_mg0':'UNKNOWN',
          'owner_approval':'UNKNOWN',
          'advancement_authorized':False
        }
    return {'schema':SCHEMA,'source_question_count':200,
      'independent_source_categories':len(DOMAINS),
      'authentic_witnesses':native_confirmed,
      'source_current_attempt_failures':negative,
      'asset':asset,'step':step,'attempt_id':work['attempt_id'],
      'master_sha256':work['master_sha256'],
      'operation_sha256':work['operation_sha256'],
      'original_audit_sha256':audit_sha,'original_audit_tail':tail,
      'verified_semantic_passes':0,'individual_mg0_passes':0,
      'advancement_authorized':False,'rules':answers}
