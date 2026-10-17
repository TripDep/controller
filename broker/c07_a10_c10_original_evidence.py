"""C07 R140 — twenty P0 original-source process/reference domain checks.

Rule-specific machine observations, not 20 certified rules: originality,
aesthetic suitability, licensor identity, architectural truth and owner MG0
remain UNKNOWN without external independent evidence. All source bytes and
pre-D evidence expectations bind to the same original Controller transaction.
"""
import hashlib
import json
import math
import re
import struct
import zlib
from pathlib import Path
from c07_positive_native_process import _original_attempt, _registered_artifacts, sha

TEXT = {
 1:"Comprendere esattamente l’obiettivo prima di iniziare qualsiasi attività.",
 2:"Distinguere il risultato richiesto dalle attività necessarie per raggiungerlo.",
 3:"Non confondere il tempo lavorato con il progresso realmente ottenuto.",
 4:"Rispettare tutte le istruzioni e i vincoli già stabiliti.",
 5:"Non cambiare obiettivo senza una motivazione tecnica verificabile o un’autorizzazione.",
 6:"Assumersi la responsabilità della qualità del proprio lavoro.",
 7:"Individuare autonomamente gli errori prima che li scopra il cliente.",
 8:"Riconoscere la differenza tra un fatto verificato e una supposizione.",
 9:"Non dichiarare mai completato ciò che non è stato verificato.",
 10:"Scegliere la soluzione più semplice che soddisfa tutti i requisiti, evitando complessità inutile.",
 21:"Cercare reference fotografiche autentiche e pertinenti.",
 22:"Cercare disegni tecnici, sezioni e planimetrie quando disponibili.",
 23:"Studiare le proporzioni degli oggetti e degli edifici reali.",
 24:"Comprendere come le strutture vengono costruite nel mondo reale.",
 25:"Analizzare materiali e superfici dei riferimenti originali.",
 26:"Raccogliere reference da diverse angolazioni.",
 27:"Separare le reference strutturali da quelle puramente estetiche.",
 28:"Verificare epoca, luogo, cultura e identità dell’architettura.",
 29:"Controllare copyright e licenze di modelli, texture e fotografie.",
 30:"Preparare una raccolta di reference coerente prima del blockout.",
}
IDS=tuple(f"AAA-200-{'A' if n<=10 else 'C'}-{n:03}" for n in TEXT)
SCHEMA='gg-c07-r140-a10-c10-original-evidence-v1'
CONTRACT_SCHEMA='gg-c07-original-pre-d-research-contract-v1'
NOTE_SCHEMA='gg-c07-research-source-note-v1'
NOTE_ROLES=('NOTE_OBJECTIVE','NOTE_PROPORTIONS','NOTE_CONSTRUCTION',
            'NOTE_MATERIALS','NOTE_HISTORY','NOTE_LICENSE',
            'NOTE_REFERENCE_INDEX','NOTE_QA')
PHOTO_ROLES=('PHOTO_FRONT','PHOTO_SIDE','PHOTO_REAR')
DOC_ROLES=('DOC_PLAN','DOC_SECTION','DOC_CONSTRUCTION')
SOURCE_ROLES=NOTE_ROLES+PHOTO_ROLES+DOC_ROLES+('IMAGE_MATERIAL',)
HEX64=re.compile(r'[a-f0-9]{64}\Z')
class ResearchBlocked(ValueError):pass
def need(ok,why):
    if not ok:raise ResearchBlocked(why)

def original_image(raw):
    """Only independently decode/check true PNG raster data, never filename or MIME."""
    if type(raw) is not bytes or not 45<=len(raw)<=8_000_000:
        return None
    if not raw.startswith(bytes((137,80,78,71,13,10,26,10))):
        return None
    offset=8; dimensions=None; compressed=[]; ended=False; chunks=0
    try:
        while offset+12<=len(raw) and chunks<1000:
            size=struct.unpack_from('>I',raw,offset)[0]
            kind=raw[offset+4:offset+8]
            end=offset+12+size
            if end>len(raw) or size>8_000_000:return None
            payload=raw[offset+8:offset+8+size]
            checksum=struct.unpack_from('>I',raw,offset+8+size)[0]
            if zlib.crc32(kind+payload)&0xffffffff != checksum:return None
            if chunks==0:
                if kind!=b'IHDR' or size!=13:return None
                w,h,depth,color,compression,filter_,interlace=struct.unpack('>IIBBBBB',payload)
                if (not 2<=w<=8192 or not 2<=h<=8192 or depth!=8 or
                    color not in (0,2,6) or (compression,filter_,interlace)!=(0,0,0)):
                    return None
                dimensions=(w,h,color)
            elif kind==b'IDAT':
                compressed.append(payload)
            elif kind==b'IEND':
                if size!=0 or end!=len(raw):return None
                ended=True;break
            elif kind in (b'IHDR',b'PLTE') and kind==b'IHDR':
                return None
            offset=end;chunks+=1
        if not (ended and dimensions and compressed):return None
        w,h,color=dimensions
        channels={0:1,2:3,6:4}[color]
        expected=h*(1+w*channels)
        if expected>128_000_000:return None
        decompressor=zlib.decompressobj()
        result=decompressor.decompress(b''.join(compressed),expected+1)
        result+=decompressor.flush()
        if len(result)!=expected or not decompressor.eof or decompressor.unused_data:
            return None
        stride=1+w*channels
        if any(result[row*stride]>4 for row in range(h)):
            return None
        return {'width':w,'height':h,'color_type':color,'sha256':sha(raw)}
    except (ValueError,IndexError,struct.error,zlib.error,OverflowError):
        return None

def _pdf(raw):
    return type(raw) is bytes and len(raw)>=13 and raw.startswith(b'%PDF-') and b'%%EOF' in raw[-1024:]

def _note(raw):
    try:
        d=json.loads(raw)
        return d if type(d) is dict and d.get('schema')==NOTE_SCHEMA else {}
    except (ValueError,TypeError,UnicodeError):
        return {}

def _nonempty(v):return type(v) is str and bool(v.strip())
def _textlist(v):
    return type(v) is list and len(v)>0 and len(v)==len(set(map(str,v))) and all(_nonempty(s) for s in v)
def _positive(v):return type(v) in (int,float) and math.isfinite(v) and v>0

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(callable(source_loader),'R140_NEEDS_ACTUAL_BYTES')
    need(inventory.get('schema')=='gg-effective-family-inventory-v1'
         and inventory.get('rule_count')==763
         and inventory.get('canonical_master_sha256')==work.get('master_sha256'),
         'R140_REAL_SOURCE_INVENTORY')
    catalog=inventory.get('source_digests',{}).get('aaa_catalog')
    need(type(catalog) is str and HEX64.fullmatch(catalog),
         'R140_SOURCE_CATALOG_PIN_MISSING')
    for n,requirement in TEXT.items():
        rid=f"AAA-200-{'A' if n<=10 else 'C'}-{n:03}"
        row=inventory['rules'].get(rid,{})
        need(row.get('family')=='AAA-200' and
             row.get('catalog_number')==n and
             row.get('catalog_phase')=='P0' and
             row.get('catalog_section')==('A' if n<=10 else 'C') and
             row.get('requirement')==requirement and
             row.get('requirement_sha256')==sha(requirement.encode('utf-8')) and
             row.get('source_sha256')==catalog,
             'R140_ORIGINAL_RULE_CHANGED:'+rid)
    rows,tail,state,audit_sha=_original_attempt(
         inventory,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256']
         and state.get('last_audit_hash')==tail
         and (state.get('active_step') or {}).get('step')==step,
         'R140_ORIGINAL_MASTER_AUDIT_OR_WORK_DRIFT')
    registered=_registered_artifacts(rows,state,step,source_loader,work)
    file_roles={}
    for role,path,digest,raw in registered:
        if role in SOURCE_ROLES:
            need(role not in file_roles,
                 'R140_DUPLICATE_ORIGINAL_REFERENCE_ROLE:'+role)
            file_roles[role]=(path,digest,raw)
    contract=plan.get('reference_evidence_contract')
    valid_contract=(type(contract) is dict and
        contract.get('schema')==CONTRACT_SCHEMA and
        type(contract.get('artifact_sha256')) is dict and
        all(type(role) is str and role in SOURCE_ROLES and
            type(hash_) is str and HEX64.fullmatch(hash_)
            for role,hash_ in contract['artifact_sha256'].items()))
    bound={}
    if valid_contract:
        bound={role: v for role,v in file_roles.items() if
               contract['artifact_sha256'].get(role)==v[1]}
    def has(role):return role in bound
    def doc(role):return _note(bound[role][2]) if has(role) else {}
    def img(role):return original_image(bound[role][2]) if has(role) else None
    def pdf(role):return _pdf(bound[role][2]) if has(role) else False
    goal=doc('NOTE_OBJECTIVE')
    props=doc('NOTE_PROPORTIONS')
    build=doc('NOTE_CONSTRUCTION')
    materials=doc('NOTE_MATERIALS')
    history=doc('NOTE_HISTORY')
    license_=doc('NOTE_LICENSE')
    references=doc('NOTE_REFERENCE_INDEX')
    qa=doc('NOTE_QA')
    photos={role:img(role) for role in PHOTO_ROLES}
    distinct_photos=(all(photos.values()) and
         len({p['sha256'] for p in photos.values()})==3)
    docs=[role for role in DOC_ROLES if pdf(role)]
    source_index=references.get('indexed_sha256')
    covered=(type(source_index) is dict and
             all(type(v) is str and k in bound and v==bound[k][1]
                 for k,v in source_index.items())
             and len(source_index)>=3)
    # Per-source predicates, not signoff. Every rule includes an independent
    # native readback of some original evidence; no signed claims accepted.
    conditions={
      1: {'goal_text_in_original_pre_d_record':_nonempty(goal.get('goal')),
          'real_work_scope_matches_original_goal':goal.get('asset')==asset,
          'planned_output_types_explicit':_textlist(goal.get('deliverables'))},
      2: {'actual_deliverable_list_precedes_work':_textlist(goal.get('deliverables')),
          'action_steps_distinct_from_deliverables':_textlist(goal.get('tasks')) and
             not set(goal.get('tasks',[]))&set(goal.get('deliverables',[])),
          'original_controller_action_matches_plan':goal.get('action')==plan.get('operation',{}).get('action')},
      3: {'current_original_nonreport_bytes_recorded':any(
              role=='NATIVE_EXPORT' and raw and sha(raw)==digest
              for role,path,digest,raw in registered),
          'original_baseline_export_byte_delta_observed':(
              'NATIVE_EXPORT' in {role for role,_,_,_ in registered} and
              'BASELINE_SNAPSHOT' in {role for role,_,_,_ in registered} and
              len({digest for role,_,digest,_ in registered
                   if role in ('NATIVE_EXPORT','BASELINE_SNAPSHOT')})==2),
          'no_report_count_used_as_completion_metric':qa.get('completion_metric')=='DELIVERABLE_ORIGINAL_BYTES'},
      4: {'constraints_predeclared_in_original_note':_textlist(goal.get('constraints')),
          'exact_source_deps_present':bool(plan.get('dependency_files')),
          'all_known_lock_names_explicit':_textlist(goal.get('protected_assets'))},
      5: {'current_asset_matches_original_scope':goal.get('asset')==asset,
          'intended_action_not_switched':goal.get('action')==plan.get('operation',{}).get('action'),
          'documented_authorized_change_if_any':goal.get('scope_changed') is False or
              (_nonempty(goal.get('scope_change_authorization_file')) and
               goal.get('scope_changed') is True)},
      6: {'original_technical_qa_file_reread':has('NOTE_QA'),
          'registered_actual_binary_output_present':any(role=='NATIVE_EXPORT' for role,_,_,_ in registered),
          'qa_names_testable_failure_modes':_textlist(qa.get('failure_classes'))},
      7: {'original_pre_delivery_defect_categories_present':_textlist(qa.get('failure_classes')),
          'defect_reproduction_evidence_original_bytes':_textlist(qa.get('independent_evidence_shas')) and
               all(HEX64.fullmatch(v) and
                   v in {digest for _role,_path,digest,_raw in registered}
                   for v in qa['independent_evidence_shas']),
          'self_review_not_called_independent':qa.get('reviewer')!='assistant' and
               _nonempty(qa.get('reviewer'))},
      8: {'factual_claims_are_pinned_original_digests':_textlist(goal.get('fact_source_hashes')) and
              all(HEX64.fullmatch(v) for v in goal['fact_source_hashes']),
          'inferences_distinct_from_facts':_textlist(goal.get('inferences')),
          'unknown_assumptions_explicit':_textlist(goal.get('unverified_assumptions'))},
      9: {'actual_delivery_status_not_from_producer_flag':state.get('delivery_status')=='NOT_DELIVERABLE',
          'known_open_test_failures_not_declared_pass':qa.get('status') in ('PENDING','FAIL','UNKNOWN'),
          'explicit_full_completion_test_not_forged':goal.get('claim_status')!='DONE'},
      10:{'pre_d_deliverables_have_specific_names':_textlist(goal.get('deliverables')),
          'alternative_costs_predeclared_in_source_note':type(goal.get('alternative_costs')) is dict and
               len(goal['alternative_costs'])>=2 and
               all(_positive(v) for v in goal['alternative_costs'].values()),
          'selected_method_defined_before_execution':_nonempty(goal.get('selected_method'))},
      21:{'original_photo_front_is_valid_png_bytes':photos['PHOTO_FRONT'] is not None,
          'reference_photo_has_provenance_url_recorded':_nonempty(references.get('photo_source_url')) and
              references['photo_source_url'].startswith('https://'),
          'photo_sha_bound_pre_d':has('PHOTO_FRONT')},
      22:{'original_plan_pdf_bytes_present':pdf('DOC_PLAN'),
          'original_section_pdf_bytes_present':pdf('DOC_SECTION'),
          'availability_statement_in_original_index':references.get('technical_drawings_availability') in
               ('PRESENT','ABSENT_VERIFIED')},
      23:{'measured_real_world_dimensions_recorded':all(_positive(props.get(k))
               for k in ('width_m','height_m','depth_m')),
          'measured_aspect_ratio_consistent':all(_positive(props.get(k))
               for k in ('width_m','height_m','depth_m')) and
               abs(props['width_m']/props['height_m']-props.get('ratio_wh',-1))<=0.02,
          'source_drawing_bytes_present':pdf('DOC_PLAN')},
      24:{'original_construction_drawing_opened':pdf('DOC_CONSTRUCTION'),
          'structural_member_inventory_not_empty':_textlist(build.get('members')),
          'assembly_connection_hierarchy_recorded':_textlist(build.get('connections'))},
      25:{'original_material_closeup_image_validated':img('IMAGE_MATERIAL') is not None,
          'physical_material_classes_identified':_textlist(materials.get('physical_classes')),
          'material_reference_original_digest_linked':materials.get('image_sha256')==
              (bound.get('IMAGE_MATERIAL') or (None,None,None))[1]},
      26:{'three_distinct_angular_original_images':bool(distinct_photos),
          'front_and_side_and_rear_dimensions_decoded':bool(distinct_photos and
               all(p['width']>=2 and p['height']>=2 for p in photos.values())),
          'photo_shas_explicit_in_pre_d_contract':all(has(role) for role in PHOTO_ROLES)},
      27:{'structural_and_aesthetic_categories_explicit':_textlist(references.get('structural_roles')) and
             _textlist(references.get('aesthetic_roles')),
          'categories_have_no_overlap':_textlist(references.get('structural_roles')) and
             _textlist(references.get('aesthetic_roles')) and
             not set(references['structural_roles'])&set(references['aesthetic_roles']),
          'both_categories_reference_actual_original_bytes':all(has(role) for role in
             references.get('structural_roles',[])+references.get('aesthetic_roles',[]))},
      28:{'historical_period_or_year_in_source_note':_nonempty(history.get('period')),
          'place_and_culture_named':_nonempty(history.get('place')) and _nonempty(history.get('culture')),
          'architectural_identity_supported_by_original_reference':has('NOTE_HISTORY')
             and pdf('DOC_PLAN') and _nonempty(history.get('architectural_identity'))},
      29:{'actual_original_license_note_present':has('NOTE_LICENSE'),
          'license_scope_and_author_identified':_nonempty(license_.get('license')) and
             _nonempty(license_.get('author')) and _nonempty(license_.get('license_url')),
          'specific_original_reference_sha_listed':_textlist(license_.get('covered_sha256')) and
             all(HEX64.fullmatch(v) and
                 v in {digest for _role,_path,digest,_raw in registered}
                 for v in license_['covered_sha256'])},
      30:{'single_original_reference_index_present':has('NOTE_REFERENCE_INDEX'),
          'source_index_sha_matches_original_artifact_bytes':bool(covered),
          'index_before_D_in_enrolled_operation':valid_contract and
             references.get('work_asset')==asset and len(bound)>=3},
    }
    need(len(conditions)==20 and set(conditions)==set(TEXT)
         and all(type(cs) is dict and len(cs)==3 and
                 all(type(v) is bool for v in cs.values())
                 for cs in conditions.values())
         and len({key for cs in conditions.values() for key in cs})==60,
         'R140_SIXTY_SOURCE_SPECIFIC_NATIVE_CRITERIA_MISSING')
    result={}
    for n,cs in conditions.items():
        rid=f"AAA-200-{'A' if n<=10 else 'C'}-{n:03}"
        rule=inventory['rules'][rid]
        result[rid]={
          'rule_id':rid,'source_sha256':rule['source_sha256'],
          'requirement_sha256':rule['requirement_sha256'],
          'native_original_file_criteria':cs,
          'observed_native_conditions':sorted(k for k,v in cs.items() if v),
          'missing_native_conditions':sorted(k for k,v in cs.items() if not v),
          'source_semantics':'SOURCE_SCOPE_OBSERVED' if all(cs.values()) else 'UNKNOWN',
          'independent_provenance_or_artistic_verification':'UNKNOWN',
          'full_rule_pass':False,'individual_mg0':'UNKNOWN',
          'owner_approval':'UNKNOWN','advancement_authorized':False
        }
    return {'schema':SCHEMA,'source_rules_examined':20,
       'asset':asset,'step':step,
       'master_sha256':work['master_sha256'],
       'attempt_id':work['attempt_id'],
       'operation_sha256':work['operation_sha256'],
       'original_audit_sha256':audit_sha,'original_audit_tail':tail,
       'native_conditions_evaluated':60,
       'native_conditions_observed':sum(sum(v is True for v in cs.values())
                                         for cs in conditions.values()),
       'full_rule_passes':0,'individual_mg0_passes':0,
       'advancement_authorized':False,'rules':result}
