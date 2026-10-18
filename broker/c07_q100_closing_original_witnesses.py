"""R149: remaining hundred canonical Q-201..Q-300 source/original witnesses.

The late questions explicitly demand adversarial visual review, real user
authorization, unknown discovery, and G2/G3/G4 independent proofs. No original
machine readback or producer answer can certify owner or individual MG0 PASS.
Questions 280..285 are NON-EXCLUDABLE dynamic-question discovery requirements.
"""
import json
from c07_questions_300 import extract_bank
from c07_positive_native_process import _original_attempt,_registered_artifacts,sha
from c07_a10_c10_original_evidence import original_image
from c07_q200_original_witnesses import digest,structured,OriginalQuestionBlocked as Blocked
from c07_positive200_evidence import R122_FROZEN_IDS

IDS=tuple('Q-'+str(n).zfill(3) for n in range(201,301))
SCHEMA='gg-c07-r149-q100-final-original-witness-v1'
CONTRACT='gg-c07-r149-100-pre-d-actual-evidence-slots-v1'
DOMAINS=('REGRESSION','VISUAL','ADVERSARIAL','OWNER','DISCOVERY')
ROLES={'REGRESSION':'Q100_REGRESSION_AUDIT',
       'VISUAL':'VISUAL_VIEW_FRONT',
       'ADVERSARIAL':'VISUAL_VIEW_UNDERSIDE',
       'OWNER':'Q100_OWNER_DECISIONS',
       'DISCOVERY':'Q100_DYNAMIC_DISCOVERY'}
def need(x,why):
    if not x:raise Blocked(why)
def topic(n):
    need(type(n) is int and 201<=n<=300,'R149_QUESTION_INDEX')
    return ('REGRESSION' if n<=220 else 'VISUAL' if n<=240 else
            'ADVERSARIAL' if n<=260 else 'OWNER' if n<=279 else
            'DISCOVERY')

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and inventory.get('rule_count')==763 and
         inventory.get('schema')=='gg-effective-family-inventory-v1' and
         len(IDS)==100 and set(IDS).isdisjoint(R122_FROZEN_IDS) and
         callable(source_loader),'R149_CANONICAL_100_Q_SCOPE_REQUIRED')
    raw=controller.master.read_bytes()
    need(sha(raw)==inventory.get('canonical_master_sha256')==
         plan.get('master_sha256')==work.get('master_sha256'),
         'R149_CURRENT_LIBRARY_MASTER_DRIFT')
    questions=extract_bank(raw)
    need(len(questions)==300 and inventory['families'].get('QUESTIONS_300')==
         ['Q-'+str(n).zfill(3) for n in range(1,301)],
         'R149_CANONICAL_300_BASE_BANK_MISSING')
    for rid in IDS:
        row=inventory['rules'].get(rid,{})
        source=questions[rid]
        need(row.get('family')=='QUESTIONS_300' and
             row.get('source')=='master' and
             row.get('source_sha256')==sha(raw) and
             row.get('requirement')==source and
             row.get('requirement_sha256')==sha(source.encode('utf-8')) and
             row.get('required_mg0') is True,
             'R149_CHANGED_ORIGINAL_Q_SOURCE:'+rid)
    journal,tail,state,audit_sha=_original_attempt(
       inventory,plan,controller,asset,step,work)
    need(state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'R149_ORIGINAL_AUDIT_CHANGED')
    artifacts=_registered_artifacts(journal,state,step,source_loader,work)
    files={}
    for role,path,hexdigest,data in artifacts:
        need(role not in files,'R149_DUPLICATE_ORIGINAL_ARTIFACT:'+role)
        files[role]=(path,hexdigest,data)
    def original(role):
        t=files.get(role)
        return t is not None and type(t[2]) is bytes and len(t[2])>0 and sha(t[2])==t[1]
    def data(role):return structured(files[role][2]) if original(role) else {}
    def raster(role):return original_image(files[role][2]) if original(role) else None
    regression=data('Q100_REGRESSION_AUDIT')
    decisions=data('Q100_OWNER_DECISIONS')
    discovery=data('Q100_DYNAMIC_DISCOVERY')
    views={role:raster('VISUAL_VIEW_'+role) for role in
       ('FRONT','REAR','LEFT','RIGHT','TOP','UNDERSIDE')}
    authentic_views=bool(all(views.values()) and
       len({v['sha256'] for v in views.values()})==6)
    scoping={
      'REGRESSION':bool(type(regression.get('failure_cases')) is list and
                    regression['failure_cases'] and
                    original('Q100_REGRESSION_AUDIT')),
      'VISUAL':bool(authentic_views),
      'ADVERSARIAL':bool(authentic_views and
                    type(regression.get('failure_cases')) is list and
                    regression['failure_cases']),
      'OWNER':bool(type(decisions.get('pending_decision_ids')) is list and
                   decisions['pending_decision_ids'] and
                   original('Q100_OWNER_DECISIONS')),
      'DISCOVERY':bool(type(discovery.get('new_material_questions')) is list and
                      discovery['new_material_questions'] and
                      original('Q100_DYNAMIC_DISCOVERY'))
    }
    fingerprints={
      'REGRESSION':digest(regression),
      'VISUAL':digest({k:v['sha256'] if v else None
                       for k,v in views.items()}),
      'ADVERSARIAL':digest({'images':{k:v['sha256'] if v else None
                          for k,v in views.items()},'regression':regression}),
      'OWNER':digest(decisions),
      'DISCOVERY':digest(discovery)}
    envelopes=plan.get('question_100_original_witnesses')
    slots=(envelopes.get('rules') if type(envelopes) is dict and
           envelopes.get('schema')==CONTRACT else {})
    if type(slots) is not dict:slots={}
    need(not set(slots)-set(IDS),'R149_EXTRA_UNREGISTERED_QUESTION')
    negatives={row.get('rule_id') for row in journal
       if row.get('step')==step and row.get('rule_id') in IDS
       and row.get('result') in ('FAIL','BLOCKED')}
    result={};source_observed=0
    for n in range(201,301):
        rid='Q-'+str(n).zfill(3)
        domain=topic(n);role=ROLES[domain]
        slot=slots.get(rid)
        row=files.get(role)
        matching=(type(slot) is dict and
           set(slot)=={'question_sha256','source_role','source_sha256',
                       'measured_fingerprint','claim_status'} and
           slot.get('question_sha256')==inventory['rules'][rid]['requirement_sha256']
           and slot.get('source_role')==role and
           row is not None and slot.get('source_sha256')==row[1]
           and slot.get('claim_status')=='OBSERVATION_ONLY')
        actual=bool(matching and original(role) and scoping[domain] and
                    slot['measured_fingerprint']==fingerprints[domain])
        source_observed+=int(actual)
        result[rid]={
          'rule_id':rid,'canonical_question':questions[rid],
          'source_sha256':inventory['rules'][rid]['source_sha256'],
          'requirement_sha256':inventory['rules'][rid]['requirement_sha256'],
          'evidence_domain':domain,'source_role':role,
          'native_original_source_witness':actual,
          'dynamic_discovery_mandatory':280<=n<=285,
          'closing_gate_mandatory':n in (286,287,288,289,290,291,292,293,294,295,296,297,298,299,300),
          'original_attempt_failure_observed':rid in negatives,
          'semantic_verdict':'FAIL' if rid in negatives else 'UNKNOWN',
          'individual_mg0':'UNKNOWN','owner_approval':'UNKNOWN',
          'advancement_authorized':False}
    need(len(result)==100 and
         all(result['Q-'+str(n).zfill(3)]['dynamic_discovery_mandatory']
             for n in range(280,286)),
         'R149_NONEXCLUDABLE_DYNAMIC_DISCOVERY')
    return {'schema':SCHEMA,'source_question_count':100,
      'additional_dynamic_questions_required':6,
      'closing_questions_required':15,
      'source_witnesses_observed':source_observed,
      'individual_negative_findings':len(negatives),
      'asset':asset,'step':step,'attempt_id':work['attempt_id'],
      'master_sha256':work['master_sha256'],
      'operation_sha256':work['operation_sha256'],
      'original_audit_sha256':audit_sha,'original_audit_tail':tail,
      'semantic_passes':0,'individual_mg0_passes':0,
      'advancement_authorized':False,'rules':result}
