"""Source-derived control inventory and structural coverage; no work PASS.

The trusted runner builds the inventory from actual canonical source bytes.
Never accept an inventory or a PASS list supplied by the producer as authority.
Evidence authenticity/semantics and work advancement remain separate gates.
"""
import ast
import hashlib
import json
import re
import unicodedata

class Blocked(ValueError):
    pass

def need(value,reason):
    if not value:raise Blocked(reason)

def sha(raw):return hashlib.sha256(raw).hexdigest()

AUX_PINS={
 'developer_rules':'b0f7ce762ae49d7c190273329bca98a4dcd3f019e461bfc9ffade8700305aafc',
 'behavior_rules':'75b0fa388ad4a8c1c7471adac2451d0a8c10fcbf95b9686f122588188a70335d',
 'aaa_catalog':'f9e7e0d11398c26095f5b3a83a2cf1e8a14ea459bc47dc09c4dfad891664fcf9',
 'professional_phases':'00fe684e66dad8acca0afa973f3fa2618afcebea0b591b817184d237b8d6a700',
 'error_registry':'59f0565ca0842206b2649caa3d9a17c939507c3f74d445a21246732d00261e55',
 'operating_contract':'dfbed18000b111dd7d6c976da1636e3ff79d338e9946c66aea5d9efd3c8cbbdb'}
SOURCES={
 'master':'governance/sources/GOLDEN_GARDEN_MASTER_RULES_AND_STATE.md',
 'developer_rules':'governance/sources/ISTRUZIONI_V2_INTEGRALI_CON_110_ERRORI.txt',
 'behavior_rules':'governance/sources/ISTRUZIONI_PROGETTO_GUARD_ASSISTENTE.txt',
 'aaa_catalog':'governance/sources/AAA_200_CANONICAL_CATALOG.json',
 'professional_phases':'governance/sources/GOLDEN_GARDEN_PROFESSIONAL_ENVIRONMENT_SYSTEM_R110.md',
 'error_registry':'governance/sources/REGISTRO_110_ERRORI_E_PREVENZIONE.md',
 'operating_contract':'governance/sources/ASSISTANT_OPERATING_CONTRACT.md',
 'registry':'governance/rule_family_registry.json','namespace':'governance/aaa_namespace_policy.json',
 'guard':'governance/gg_phase_guard.py'}
PHASES=('G0','G1','A','B','C','D0','D','P0','P1','P2','P3','P4','P5','P6','P7','P8','VERIFY','G2','G3','G4','DELIVERY')
PRO_PHASES=tuple('P'+str(i) for i in range(9))
ASSET_TYPES=('architecture','organic','vegetation','terrain')
HEX=re.compile(r'[a-f0-9]{64}\Z')

# Source anchors, not new requirements. Each aggregate retains its entire
# canonical clause, including sub-obligations; a heading match is not work QA.
MASTER_BINDINGS={
 'MASTER_CHAIN':{k:('## '+k+' —',) for k in ('Q','A','B','C','D0','D','E','F')},
 'META':{'MG0':('## MG0 —',)},
 'GLOBAL_GATES':{k:('## '+k+' —',) for k in ('G0','G1','G2','G3','G4')},
 'COGNITIVE':{k:('## '+k+' —',) for k in ('CG1','CG2','CG3','CG4')},
 'D_SUBGATES':{k:('## '+k+' —',) for k in ('D-TEMPO','D-METODO','D-RISULTATO')},
 'GLOBAL_COMPLETION':{
  'DEFINITION_OF_DONE':('## Definition of Done per piece',),
  'CROSS_PIECE_COHERENCE':('## Coherence between pieces VERIFIED',),
  'AUTONOMOUS_PRE_PASS_QUESTION':('## Mandatory autonomous question before PASS',),
  'PROCESS_DESIGN_STOP_RULE':('## Stop condition on process design',)},
 'DELIVERY':{
  'NO_USER_AS_QA':('# 10. No User-as-QA / Delivery Firewall',),
  'DELIVERY_FIREWALL':('# 10. No User-as-QA / Delivery Firewall',),
  'FRESH_EYES':('## EXEC-016 —',),'INTENTION_BLIND':('## EXEC-020 —',),
  'MACHINE_QA':('# 10. No User-as-QA / Delivery Firewall',),
  'VISUAL_QA':('# 10. No User-as-QA / Delivery Firewall',),
  'ADVERSARIAL_QA':('# 10. No User-as-QA / Delivery Firewall',),
  'EXPORT_REIMPORT':('## 0.0B Golden Controller enforcement',),
  'REGRESSION_QA':('## EXEC-002 —','## EXEC-014 —')},
 'GOVERNANCE':{
  'MASTER_BEFORE_AFTER':('## 0.0 Continuous Master re-check','## 0.0P Pine Haven global asset governance'),
  'GOLDEN_CONTROLLER':('## 0.0B Golden Controller enforcement','## 0.0C Full gate-through-Master passage'),
  'WORK_STATE':('## 0.0B Golden Controller enforcement',),
  'APPEND_ONLY_AUDIT':('## 0.0A Persistent observable audit trail',),
  'LOCK_MATRIX':('## 0.2 GLOBAL LOCK / AUTONOMY MATRIX','## 0.3 Asset-specific lock rows','## 0.0H — LOCK ASSOLUTO:'),
  'USER_AUTHORIZATION_D0':('## D0 —',),
  'BLOCK_ON_UNKNOWN':('## 0.0 Continuous Master re-check','## 0.1 Status vocabulary'),
  'DEPENDENCY_RECHECK':('## EXEC-003 —','## 0.0 Continuous Master re-check'),
  'SOURCE_HIERARCHY':('# 1. Source of truth hierarchy',)},
 'DESIGN_STANDARDS':{
  'ARCHITECTURAL_QUALITY_FLOOR':('# 11. Current architectural quality floor',),
  'HARD_FAILURE_CLASSES':('# 11. Current architectural quality floor',),
  'ROUND_QUALITY':('### ROUND_QUALITY standard',),
  'ARCHITECTURE_1TO1':('# 12. Architecture vs procedural policy',),
  'FIVEM_TARGET':('## 0.2 GLOBAL LOCK / AUTONOMY MATRIX',),
  'REFERENCE_HIERARCHY':('# 1. Source of truth hierarchy',)}}
BEHAVIOR_BINDINGS={'ASSISTANT_BEHAVIOR_PROTOCOL':'behavior_rules','110_ERROR_REGISTRY':'error_registry',
 'INTEGRAL_110_INSTRUCTIONS':'developer_rules','OPERATING_CONTRACT':'operating_contract',
 'DEVELOPER_RULES_CANONICAL':'developer_rules'}
SYSTEM_ANCHORS={
 'SYSTEM_SOURCE_RELATIONSHIP':'## 0. Relationship to existing governance',
 'SYSTEM_TASK_DEPENDENCIES':'## 3. Task / dependency graph',
 'SYSTEM_MG0_ESCALATION':'## 4. Error escalation / MG0 hard rule',
 'SYSTEM_TECHNICAL_ENVIRONMENT':'## 5. Technical Environment Study',
 'SYSTEM_MONITORING_CONSTRAINTS':'## 6. Monitoring constraints',
 'SYSTEM_RELEASE_PRIORITIES':'## 7. Current release priority'}

def block(text,prefix):
    headings=list(re.finditer(r'(?m)^(#{1,6}) ([^\n]+)$',text))
    found=[(i,h) for i,h in enumerate(headings) if h.group(0).startswith(prefix)]
    need(len(found)==1,'CANONICAL_ANCHOR_NOT_UNIQUE:'+prefix)
    i,h=found[0];level=len(h.group(1));end=len(text)
    for other in headings[i+1:]:
        if len(other.group(1))<=level:end=other.start();break
    return text[h.start():end].strip()

def numbered(text,prefix,count,pattern=r'(?m)^(\d+)\. (.+)$'):
    body=block(text,prefix);rows=re.findall(pattern,body)
    need([int(n) for n,_ in rows]==list(range(1,count+1)),'CANONICAL_SEQUENCE:'+prefix)
    return rows

def build_inventory(raw,canonical_master_sha):
    need(set(raw)==set(SOURCES),'SOURCE_SET_INCOMPLETE')
    need(sha(raw['master'])==canonical_master_sha,'CURRENT_MASTER_DIGEST_MISMATCH')
    for key,pin in AUX_PINS.items():need(sha(raw[key])==pin,'CANONICAL_AUX_DRIFT:'+key)
    text={k:v.decode('utf-8',errors='strict') for k,v in raw.items()}
    reg=json.loads(text['registry']);namespace=json.loads(text['namespace']);cat=json.loads(text['aaa_catalog'])
    need(reg.get('schema')=='gg-rule-family-registry-v1','REGISTRY_SCHEMA')
    need(namespace.get('schema')=='gg-aaa-namespace-policy-v1'
         and namespace.get('master_rule_namespace')=='MASTER'
         and namespace.get('aaa_rule_namespace')=='AAA-200','NAMESPACE_COLLISION')
    need(cat.get('schema')=='GG_AAA200_CATALOG_V1' and cat.get('phase_order')==list(PRO_PHASES)
         and cat.get('asset_types')==list(ASSET_TYPES),'CATALOG_PHASE_OR_TYPE_DRIFT')
    phase_match=re.search(r'(?m)^PHASES = (\(.*\))$',text['guard'])
    need(phase_match is not None and ast.literal_eval(phase_match.group(1))==PHASES,'PHASE_CHAIN_SOURCE_DRIFT')
    families={};items={}
    # Later historical appendices repeat mother-rule headings. The active
    # recovered global process definitions precede the asset-state section13.
    boundary=text['master'].find('# 13. Current Pavilion / Golden Ting state')
    need(boundary>0,'MASTER_ACTIVE_PROCESS_BOUNDARY')
    core=text['master'][:boundary]
    def add(family,rule,key,requirement,**extra):
        need(rule not in items,'DUPLICATE_CANONICAL_ID:'+rule)
        families.setdefault(family,[]).append(rule)
        items[rule]={'family':family,'source':key,'source_path':SOURCES[key],
          'source_sha256':sha(raw[key]),'requirement_sha256':sha(requirement.encode()),
          'requirement':requirement,'required_mg0':True,**extra}
    for family,mapping in MASTER_BINDINGS.items():
        for rule,prefixes in mapping.items():add(family,rule,'master','\n\n'.join(block(core,p) for p in prefixes))
    exec_rows=re.findall(r'(?m)^## EXEC-(\d{3}) —',core)
    need(exec_rows==[str(n).zfill(3) for n in range(1,26)],'EXEC_SOURCE_SEQUENCE')
    for n in exec_rows:add('EXECUTION','EXEC-'+n,'master',block(core,'## EXEC-'+n+' —'))
    for n,body in numbered(core,'### Exact recovered 30-control source list',30):add('G0_CONTROLS','G0-'+n.zfill(2),'master',body)
    for n,body in numbered(core,'## The exact 12 provocation directions',12,pattern=r'(?m)^(\d+)\. (\*\*.+)$'):add('PROVOCATION','PROVOCATION-'+n.zfill(2),'master',body)
    for n,body in numbered(core,'## Canonical 300 base questions',300):add('QUESTIONS_300','Q-'+n.zfill(3),'master',body)
    legacy=block(core,'## 3A. LEGACY / ASSET-BUILD INTERNAL GATES')
    legacy_rows=re.findall(r'(?m)^- \*\*(G[0-9](?:B)?)\b([^\n]*)$',legacy)
    need([n for n,_ in legacy_rows]==['G0','G1','G2','G3','G4','G5','G6','G6B','G7','G8','G9'],'LEGACY_GATE_NAMESPACE')
    for n,body in legacy_rows:add('HISTORICAL_ASSET_GATES','LEGACY_'+n,'master',n+body,applicability='CANONICAL_ASSET_CONTEXT_REQUIRED')
    for rule,key in BEHAVIOR_BINDINGS.items():add('BEHAVIOR',rule,key,text[key])
    errors=re.findall(r'(?m)^(\d{3})\. (Errore:[^\n]+)$',text['error_registry'])
    need([n for n,_ in errors]==[str(n).zfill(3) for n in range(1,111)],'BEHAVIOR_110_SOURCE_SEQUENCE')
    for n,body in errors:add('BEHAVIOR_110','BEHAVIOR-'+n,'error_registry',body)
    professional=text['professional_phases'];pheads=re.findall(r'(?m)^### (P[0-8]) —',professional)
    need(pheads==list(PRO_PHASES),'PROFESSIONAL_PHASE_SOURCE_SEQUENCE')
    for phase in pheads:add('PROFESSIONAL_PHASES',phase,'professional_phases',block(professional,'### '+phase+' —'))
    # Compare every legacy family and ID with source-derived IDs, not total count.
    legacy_families=set(families)
    declared=reg.get('families');need(isinstance(declared,list),'REGISTRY_FAMILY_SET')
    need(all(isinstance(f,dict) and isinstance(f.get('id'),str) and isinstance(f.get('required'),list) for f in declared),'REGISTRY_FAMILY_SCHEMA')
    names=[f['id'] for f in declared]
    need(len(names)==len(set(names)) and set(names)==legacy_families,'REGISTRY_FAMILY_OMITTED_ADDED_OR_DUPLICATE')
    for f in declared:
        expected=families[f['id']];actual=f['required']
        need(len(actual)==len(set(actual)) and set(actual)==set(expected),'REGISTRY_RULE_SET:'+f['id'])
    # R110 obligations were in the source but absent as explicit legacy slots.
    profiles=block(professional,'## 2. Mandatory asset profiles')
    profile_names=re.findall(r'(?m)^### ([A-Z_]+)_PROFILE$',profiles)
    need(profile_names==['ARCHITECTURE','FOLIAGE','ROCK_ROCKERY','TERRAIN_PATH','WATER_FOUNTAIN','PROP'],'PROFILE_SOURCE_SEQUENCE')
    for name in profile_names:add('ASSET_PROFILE_READINESS','PROFILE_'+name,'professional_phases',block(professional,'### '+name+'_PROFILE'),profile=name+'_PROFILE')
    for rule,prefix in SYSTEM_ANCHORS.items():add('PROFESSIONAL_SYSTEM',rule,'professional_phases',block(professional,prefix))
    embedded=re.findall(r'(?m)^(\d+)\. \[([A-T])\] (.*?)  \*\*Fase:\*\* `(P[0-8])` · \*\*Asset:\*\* `(\w+)`$',text['master'])
    need(len(embedded)==200 and [int(r[0]) for r in embedded]==list(range(1,201)),'MASTER_AAA_COUNT_OR_SEQUENCE')
    rows=cat.get('catalog');need(isinstance(rows,list) and len(rows)==200,'AAA_CATALOG_COUNT')
    expected_mapping=[]
    for entry,master_entry in zip(rows,embedded):
        n,section,requirement,phase,asset=master_entry
        need(entry.get('id')==int(n) and entry.get('section')==section and entry.get('phase')==phase
             and entry.get('asset_type')==asset
             and unicodedata.normalize('NFC',entry.get('requirement',''))==unicodedata.normalize('NFC',requirement),
             'AAA_MASTER_CATALOG_DIVERGENCE:'+n)
        rule='AAA-200-'+section+'-'+n.zfill(3)
        expected_mapping.append({'id':rule,'catalog_number':int(n),'catalog_section':section,'catalog_phase':phase})
        add('AAA-200',rule,'aaa_catalog',requirement,catalog_number=int(n),catalog_section=section,
            catalog_phase=phase,asset_type=asset)
    need(namespace.get('mapping')==expected_mapping and namespace.get('catalog_sha256')==sha(raw['aaa_catalog'])
         and namespace.get('catalog_source')==SOURCES['aaa_catalog'],'AAA_MAPPING_OR_SOURCE_DRIFT')
    return {'schema':'gg-effective-family-inventory-v1','families':families,'rules':items,
       'source_digests':{k:sha(v) for k,v in raw.items()},'canonical_master_sha256':canonical_master_sha,
       'source_read_mode':'PINNED_TO_VERIFIED_LIBRARY_DIGEST','library_live_read':False,
       'legacy_rule_count':sum(len(f['required']) for f in declared),'legacy_family_count':len(declared),
       'explicit_r110_additions':12,'rule_count':len(items),'family_count':len(families),
       'aaa_section_count':len({r['catalog_section'] for r in items.values() if 'catalog_section' in r}),
       'coverage_scope':'REGISTERED_GLOBAL_RULES_AND_CANONICAL_R110_SOURCE_BASE',
       'asset_specific_context_extensions_verified':False,
       'asset_execution_passes':0,'advancement_authorized':False}

def expected_result(row,phase,asset_type,profiles):
    if row.get('profile') and row['profile'] not in profiles:return 'N_A_PROFILE_NOT_SELECTED'
    if 'catalog_phase' in row:
        if row['asset_type'] not in ('all',asset_type):return 'N_A_ASSET_TYPE'
        index=PRO_PHASES.index(phase) if phase in PRO_PHASES else (8 if PHASES.index(phase)>PHASES.index('P8') else 0)
        if PRO_PHASES.index(row['catalog_phase'])>index:return 'FUTURE_PHASE'
    return 'PASS'

def validate_coverage(inventory,ledger,*,phase,asset_type,profiles):
    """Validate structure/bindings only; C06/C07 must actually verify evidence.

    The caller supplies phase/type/profiles from the trusted work context, not
    a producer's waiver. N/A does not remove an ID or its required MG0/evidence.
    """
    need(phase in PHASES and asset_type in ASSET_TYPES,'WORK_CONTEXT_PHASE_OR_TYPE')
    known={r['profile'] for r in inventory['rules'].values() if 'profile' in r}
    need(isinstance(profiles,list) and profiles and len(profiles)==len(set(profiles))
         and set(profiles)<=known,'WORK_PROFILE_CONTEXT_REQUIRED')
    need(isinstance(ledger,dict) and ledger.get('phase')==phase,'LEDGER_PHASE')
    groups=ledger.get('families');need(isinstance(groups,dict) and set(groups)==set(inventory['families']),'LEDGER_FAMILY_COVERAGE')
    passed=future=na=0
    for family,ids in inventory['families'].items():
        checks=groups[family];need(isinstance(checks,dict) and set(checks)==set(ids),'LEDGER_RULE_COVERAGE:'+family)
        for rule in ids:
            row=inventory['rules'][rule];check=checks[rule];need(isinstance(check,dict),'LEDGER_RULE_SCHEMA:'+rule)
            wanted=expected_result(row,phase,asset_type,profiles)
            need(check.get('result')==wanted,'LEDGER_RULE_RESULT:'+rule)
            need(check.get('source_sha256')==row['source_sha256'] and check.get('requirement_sha256')==row['requirement_sha256'],'LEDGER_SOURCE_BINDING:'+rule)
            if 'catalog_phase' in row:
                for field in ('catalog_number','catalog_section','catalog_phase','asset_type'):
                    need(check.get(field)==row[field],'LEDGER_CATALOG_BINDING:'+rule+':'+field)
            evidence=check.get('evidence');need(isinstance(evidence,dict) and isinstance(evidence.get('ref'),str) and evidence['ref']
                 and isinstance(evidence.get('sha256'),str) and HEX.fullmatch(evidence['sha256']),'LEDGER_EVIDENCE_REQUIRED:'+rule)
            mg0=check.get('mg0');need(isinstance(mg0,dict) and mg0.get('result')=='PASS'
                 and mg0.get('rule_id')==rule and mg0.get('phase')==phase
                 and mg0.get('master_sha256')==inventory['canonical_master_sha256'],'LEDGER_MG0_BINDING:'+rule)
            proof=mg0.get('evidence');need(isinstance(proof,dict) and isinstance(proof.get('ref'),str) and proof['ref']
                 and isinstance(proof.get('sha256'),str) and HEX.fullmatch(proof['sha256']),'LEDGER_MG0_EVIDENCE_REQUIRED:'+rule)
            if wanted=='PASS':passed+=1
            elif wanted=='FUTURE_PHASE':future+=1
            else:na+=1
    need(phase!='DELIVERY' or future==0,'FUTURE_RULES_CANNOT_CLOSE')
    return {'status':'COVERAGE_STRUCTURE_PRESENT_ONLY','required_ids':inventory['rule_count'],
       'families':inventory['family_count'],'declared_pass_slots':passed,'future_phase_slots':future,'na_slots':na,
       'actual_evidence_contents_verified':False,'actual_work_passes':0,'advancement_authorized':False}
