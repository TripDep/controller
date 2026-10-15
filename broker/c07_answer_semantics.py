"""C07 reviewed question polarity and fail-closed declarations.

A producer's answer can establish FAIL, never work PASS. Only explicitly
source-reviewed questions have a polarity. All others remain UNKNOWN.
"""
import hashlib
import json
import re
from pathlib import Path

REVIEWED={
 'AAA-200-G-067':('Individuare e correggere compenetrazioni.',(
   ('CHECK','CONTROL_PERFORMED','Hai controllato le compenetrazioni?'),
   ('REMAIN','DEFECT_PRESENT','Rimangono compenetrazioni non corrette?'))),
 'Q-075':('Esistono elementi che attraversano altri elementi?',(
   ('DEFECT','DEFECT_PRESENT','Esistono elementi che attraversano altri elementi?'),)),
 'Q-021':('Ho tutti gli input necessari?',(
   ('INPUTS','REQUIREMENT_SATISFIED','Hai tutti gli input necessari?'),)),
 'Q-001':('Qual è esattamente il risultato richiesto?',(
   ('RESULT','OPEN_ANALYSIS','Descrivi il risultato richiesto e la sua verifica.'),)),
 'Q-280':('Esiste qualcosa che non ho nemmeno pensato di controllare?',(
   ('DISCOVERY','OPEN_ANALYSIS','Quali controlli ulteriori hai cercato e quali omissioni rimangono?'),))
}
HEX=re.compile(r'[a-f0-9]{64}\Z')
class Blocked(ValueError):pass
def need(ok,why):
 if not ok:raise Blocked(why)
def digest(s):return hashlib.sha256(s.encode('utf-8')).hexdigest()


# These are question *wordings* reviewed against immutable canonical sources.
# They are NOT source-specific native semantic verifiers or independent asset QA.
QUESTION_MASTER_PIN='b5f33d4ea13f888e87bdf698169af68fbeeeab6429f8868f77c6c6ad451df165'
QUESTION_FILES=('c07_questions_758_part1.json','c07_questions_758_part2.json')

def _verified_wording(inv):
 """Refuse drift, missing/extra IDs, conflicting overlaps or stale Library pins."""
 count=inv['rule_count']
 # Small six-rule fixture is explicitly non-operational and keeps old unit tests.
 if count != 763:
  need(count < 20 and inv['canonical_master_sha256'] in ('a'*64, QUESTION_MASTER_PIN),
       'ANSWER_NONCANONICAL_INVENTORY')
  return {}
 need(inv['canonical_master_sha256']==QUESTION_MASTER_PIN,
      'ANSWER_758_LIBRARY_MASTER_DRIFT')
 merged={}
 for index,name in enumerate(QUESTION_FILES,1):
  try:
   part=json.loads((Path(__file__).resolve().parent/name).read_text(encoding='utf-8'))
  except (OSError,ValueError) as err:
   raise Blocked('ANSWER_758_SOURCE_NOT_READABLE:'+name) from err
  need(part.get('schema')=='gg-c07-reviewed-part-v1' and part.get('index')==index
       and isinstance(part.get('questions'),dict),'ANSWER_758_PART_SCHEMA')
  for rid,row in part['questions'].items():
   need(type(row) is dict and
        set(row)=={'requirement_sha256','source_sha256','question','compound_review'}
        and type(row['question']) is str and row['question'].strip().endswith('?')
        and isinstance(row['compound_review'],bool)
        and HEX.fullmatch(row['requirement_sha256'])
        and HEX.fullmatch(row['source_sha256']),
        'ANSWER_758_ROW_SCHEMA:'+rid)
   if rid in merged:need(merged[rid]==row,'ANSWER_758_OVERLAP_CONFLICT:'+rid)
   merged[rid]=row
 need(len(merged)==758 and set(merged)==set(inv['rules'])-set(REVIEWED),
      'ANSWER_758_MEMBERSHIP')
 need(sum(x['compound_review'] for x in merged.values())==72,
      'ANSWER_758_COMPOUND_COUNT')
 for rid,row in merged.items():
  canonical=inv['rules'][rid]
  need(row['requirement_sha256']==canonical['requirement_sha256'] and
       row['source_sha256']==canonical['source_sha256'],
       'ANSWER_758_SOURCE_DRIFT:'+rid)
 return merged

def questions_for(inv):
 """Shared source-checked source of C07/obligation ledger questions."""
 wording=_verified_wording(inv)
 specs={}
 for rid in inv['rules']:
  reviewed=REVIEWED.get(rid)
  if reviewed:
   qs=[{'id':rid+':'+key,'type':kind,'text':prompt}
       for key,kind,prompt in reviewed[1]]
   cls='REVIEWED'
   compound=False
  elif rid in wording:
   row=wording[rid]
   qs=[{'id':rid+':REQUIREMENT','type':'REQUIREMENT_SATISFIED',
        'text':row['question']}]
   cls='YES_NO_WORDING_REVIEWED_PROOF_PENDING'
   compound=row['compound_review']
  else:
   qs=[{'id':rid+':CONTROL_CHECK','type':'CONTROL_PERFORMED',
        'text':'Hai effettuato il controllo previsto dalla regola canonica '+rid+'?'}]
   cls='GENERIC_CHECK_REVIEW_PENDING'
   compound=False
  specs[rid]={'classification':cls,'questions':qs,'compound_subchecks_pending':compound}
 return specs

def build(inv):
 """Full inventory, exact source binding, explicit unreviewed classification."""
 need(isinstance(inv,dict) and inv.get('schema')=='gg-effective-family-inventory-v1','ANSWER_INVENTORY_SCHEMA')
 families,rows=inv.get('families'),inv.get('rules')
 need(isinstance(families,dict) and isinstance(rows,dict),'ANSWER_FAMILIES')
 flat=[rid for items in families.values() for rid in items]
 need(len(flat)==len(set(flat))==len(rows)==inv.get('rule_count') and
      len(families)==inv.get('family_count') and set(flat)==set(rows),'ANSWER_CANONICAL_MEMBERSHIP')
 master=inv.get('canonical_master_sha256')
 need(isinstance(master,str) and HEX.fullmatch(master),'ANSWER_MASTER_DIGEST')
 specs=questions_for(inv)
 entries={}
 for rid in flat:
  r=rows[rid];clause=r.get('requirement')
  need(r.get('family') in families and rid in families[r['family']] and
       isinstance(clause,str) and bool(clause) and r.get('requirement_sha256')==digest(clause) and
       isinstance(r.get('source_sha256'),str) and HEX.fullmatch(r['source_sha256']),
       'ANSWER_RULE_SOURCE:'+rid)
  reviewed=REVIEWED.get(rid)
  if reviewed:need(clause==reviewed[0],'ANSWER_REVIEWED_CLAUSE_DRIFT:'+rid)
  spec=specs[rid]
  entries[rid]={'family':r['family'],'requirement_sha256':r['requirement_sha256'],
                'source_sha256':r['source_sha256'],
                'classification':spec['classification'],
                'compound_subchecks_pending':spec['compound_subchecks_pending'],
                'questions':spec['questions'],'verdict':'UNKNOWN'}
 return {'schema':'gg-c07-answer-contract-v1','master_sha256':master,
         'rule_count':len(entries),'reviewed_count':sum(x['classification']=='REVIEWED' for x in entries.values()),
         'unreviewed_count':sum(x['classification']!='REVIEWED' for x in entries.values()),
         'question_count':sum(len(x['questions']) for x in entries.values()),
         'wording_reviewed_count':sum(x['classification']=='YES_NO_WORDING_REVIEWED_PROOF_PENDING' for x in entries.values()),
         'generic_count':sum(x['classification']=='GENERIC_CHECK_REVIEW_PENDING' for x in entries.values()),
         'compound_pending_count':sum(x['compound_subchecks_pending'] for x in entries.values()),
         'entries':entries,'advancement_authorized':False}

def assess(ledger,due_ids,packets,*,attempt_id,operation_sha256):
 """Typed answers for Controller-derived due IDs, never a native semantic PASS."""
 need(ledger.get('schema')=='gg-c07-answer-contract-v1' and
      type(due_ids) is list and len(due_ids)==len(set(due_ids)) and
      set(due_ids)<=set(ledger['entries']),'ANSWER_TRUSTED_SCOPE')
 need(isinstance(attempt_id,str) and HEX.fullmatch(attempt_id) and
      isinstance(operation_sha256,str) and HEX.fullmatch(operation_sha256),
      'ANSWER_ATTEMPT_BINDING')
 need(type(packets) is list,'ANSWER_PACKET_LIST')
 expected={q['id']:(rid,q) for rid in due_ids for q in ledger['entries'][rid]['questions']}
 seen={}
 keys={'rule_id','question_id','requirement_sha256','master_sha256',
       'attempt_id','operation_sha256','answer','statement','evidence_refs'}
 for p in packets:
  need(type(p) is dict and set(p)==keys,'ANSWER_PACKET_SCHEMA')
  qid,rid=p['question_id'],p['rule_id']
  need(qid in expected and expected[qid][0]==rid,'ANSWER_UNREVIEWED_OR_NOT_DUE')
  need(qid not in seen,'ANSWER_DUPLICATE_OR_CONTRADICTORY:'+qid)
  row=ledger['entries'][rid]
  need(p['requirement_sha256']==row['requirement_sha256'] and
       p['master_sha256']==ledger['master_sha256'] and
       p['attempt_id']==attempt_id and p['operation_sha256']==operation_sha256,
       'ANSWER_REPLAY_OR_DRIFT:'+qid)
  refs=p['evidence_refs']
  need(type(refs) is list and len(refs)<=20 and all(
       type(x) is dict and set(x)=={'ref','sha256'} and type(x['ref']) is str and
       0<len(x['ref'])<=1024 and type(x['sha256']) is str and HEX.fullmatch(x['sha256'])
       for x in refs),'ANSWER_UNTRUSTED_EVIDENCE_SCHEMA:'+qid)
  kind=expected[qid][1]['type'];ans=p['answer'];statement=p['statement']
  need(type(ans) is str and type(statement) is str and len(statement)<=4000,
       'ANSWER_FORMAT:'+qid)
  if kind=='OPEN_ANALYSIS':
   need(ans=='TEXT','ANSWER_OPEN_NOT_BOOLEAN:'+qid)
   status='UNKNOWN' if len(statement.strip())>=20 else 'FAIL'
   reason='AWAIT_INDEPENDENT_REVIEW' if status=='UNKNOWN' else 'NO_SUBSTANTIVE_ANSWER'
  else:
   need(ans in ('YES','NO','UNKNOWN') and not statement.strip(),
        'ANSWER_BINARY_CONTRADICTION:'+qid)
   if (kind in ('CONTROL_PERFORMED','REQUIREMENT_SATISFIED') and ans=='NO') or (
       kind=='DEFECT_PRESENT' and ans=='YES'):
    status,reason='FAIL','ADMITTED_MISSING_CONTROL_OR_DEFECT'
   else:
    status='UNKNOWN'
    reason=('UNRESOLVED' if ans=='UNKNOWN' else
            'SELF_DECLARATION_ONLY' if not refs else 'PROOF_REFS_NOT_INDEPENDENTLY_VERIFIED')
  seen[qid]={'answer':ans,'status':status,'reason':reason}
 missing=sorted(set(expected)-set(seen))
 unreviewed=sorted(rid for rid in due_ids if ledger['entries'][rid]['classification']!='REVIEWED')
 fails=sorted(qid for qid,row in seen.items() if row['status']=='FAIL')
 return {'schema':'gg-c07-answer-assessment-v1','status':'FAIL' if fails else 'UNKNOWN',
         'answered':seen,'failed':fails,'missing':missing,'unreviewed_due':unreviewed,
         'independent_proof_verified':False,'mg0_pass':False,'advancement_authorized':False}
