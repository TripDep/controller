"""C07 reviewed question polarity and fail-closed declarations.

A producer's answer can establish FAIL, never work PASS. Only explicitly
source-reviewed questions have a polarity. All others remain UNKNOWN.
"""
import hashlib
import re

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
 entries={}
 for rid in flat:
  r=rows[rid];clause=r.get('requirement')
  need(r.get('family') in families and rid in families[r['family']] and
       isinstance(clause,str) and bool(clause) and r.get('requirement_sha256')==digest(clause) and
       isinstance(r.get('source_sha256'),str) and HEX.fullmatch(r['source_sha256']),
       'ANSWER_RULE_SOURCE:'+rid)
  reviewed=REVIEWED.get(rid)
  if reviewed:need(clause==reviewed[0],'ANSWER_REVIEWED_CLAUSE_DRIFT:'+rid)
  qs=[{'id':rid+':'+key,'type':kind,'text':prompt}
      for key,kind,prompt in reviewed[1]] if reviewed else [
      {'id':rid+':CONTROL_CHECK','type':'CONTROL_PERFORMED',
       'text':'Hai effettuato il controllo previsto dalla regola canonica '+rid+'?'}]
  entries[rid]={'family':r['family'],'requirement_sha256':r['requirement_sha256'],
                'source_sha256':r['source_sha256'],
                'classification':'REVIEWED' if reviewed else 'GENERIC_CHECK_REVIEW_PENDING',
                'questions':qs,'verdict':'UNKNOWN'}
 return {'schema':'gg-c07-answer-contract-v1','master_sha256':master,
         'rule_count':len(entries),'reviewed_count':sum(x['classification']=='REVIEWED' for x in entries.values()),
         'unreviewed_count':sum(x['classification']!='REVIEWED' for x in entries.values()),
         'question_count':sum(len(x['questions']) for x in entries.values()),
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
