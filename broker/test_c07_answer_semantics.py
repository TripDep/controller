"""Regression tests for polarity, provenance and fail-closed declarations."""
import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch
import c07_answer_semantics as s

def sha(t):return hashlib.sha256(t.encode('utf-8')).hexdigest()
def fixture():
 rows={};families={'AAA-200':[],'QUESTIONS_300':[],'BEHAVIOR_110':[]}
 for rid,(clause,questions) in s.REVIEWED.items():
  fam='AAA-200' if rid.startswith('AAA-') else 'QUESTIONS_300'
  rows[rid]={'family':fam,'requirement':clause,
             'requirement_sha256':sha(clause),'source_sha256':'c'*64}
  families[fam].append(rid)
 rows['BEHAVIOR-051']={'family':'BEHAVIOR_110','requirement':'Non aggirare il controllo.',
                      'requirement_sha256':sha('Non aggirare il controllo.'),
                      'source_sha256':'f'*64}
 families['BEHAVIOR_110'].append('BEHAVIOR-051')
 return {'schema':'gg-effective-family-inventory-v1','families':families,
         'rules':rows,'rule_count':len(rows),'family_count':len(families),
         'canonical_master_sha256':'a'*64}
def answer(l,qid,ans,statement='',refs=None):
 rid=qid.split(':')[0]
 return {'rule_id':rid,'question_id':qid,
         'requirement_sha256':l['entries'][rid]['requirement_sha256'],
         'master_sha256':l['master_sha256'],'attempt_id':'b'*64,
         'operation_sha256':'d'*64,'answer':ans,'statement':statement,
         'evidence_refs':refs or []}
def assess(l,packets):
 return s.assess(l,list(l['entries']),packets,attempt_id='b'*64,
                 operation_sha256='d'*64)

class PolarityRegression(unittest.TestCase):
 def setUp(self):self.inv=fixture();self.l=s.build(self.inv)
 def test_all_ids_and_no_work_pass(self):
  self.assertEqual((self.l['reviewed_count'],self.l['unreviewed_count']),(5,1))
  self.assertFalse(self.l['advancement_authorized'])
 def test_unperformed_check_is_fail(self):
  self.assertEqual(assess(self.l,[answer(self.l,'AAA-200-G-067:CHECK','NO')])['status'],'FAIL')
 def test_present_uncorrected_defect_is_fail(self):
  for qid in ('AAA-200-G-067:REMAIN','Q-075:DEFECT'):
   with self.subTest(qid=qid):
    self.assertIn(qid,assess(self.l,[answer(self.l,qid,'YES')])['failed'])
 def test_absent_defect_not_inverted_to_fail_or_pass(self):
  res=assess(self.l,[answer(self.l,'Q-075:DEFECT','NO')])
  self.assertEqual(res['status'],'UNKNOWN');self.assertFalse(res['advancement_authorized'])
 def test_required_inputs_missing_is_fail(self):
  self.assertEqual(assess(self.l,[answer(self.l,'Q-021:INPUTS','NO')])['status'],'FAIL')
 def test_yes_and_evidence_pointer_are_not_independent_pass(self):
  q='AAA-200-G-067:CHECK'
  res=assess(self.l,[answer(self.l,q,'YES',refs=[{'ref':'GitHub PR #123','sha256':'f'*64}])])
  self.assertEqual(res['answered'][q]['reason'],'PROOF_REFS_NOT_INDEPENDENTLY_VERIFIED')
  self.assertEqual(res['status'],'UNKNOWN');self.assertFalse(res['independent_proof_verified'])
 def test_open_question_rejects_binary(self):
  with self.assertRaisesRegex(s.Blocked,'ANSWER_OPEN_NOT_BOOLEAN'):
   assess(self.l,[answer(self.l,'Q-280:DISCOVERY','NO')])
 def test_open_question_narrative_still_unknown(self):
  res=assess(self.l,[answer(self.l,'Q-280:DISCOVERY','TEXT',
                            'Ho cercato errori nelle quote reali e mancano ancora misure.')])
  self.assertEqual(res['status'],'UNKNOWN')
 def test_empty_open_answer_is_fail(self):
  self.assertEqual(assess(self.l,[answer(self.l,'Q-001:RESULT','TEXT','ok')])['status'],'FAIL')
 def test_duplicate_conflicting_answers_rejected(self):
  q='Q-075:DEFECT'
  with self.assertRaisesRegex(s.Blocked,'ANSWER_DUPLICATE_OR_CONTRADICTORY'):
   assess(self.l,[answer(self.l,q,'NO'),answer(self.l,q,'YES')])
 def test_binary_text_contradiction_rejected(self):
  with self.assertRaisesRegex(s.Blocked,'ANSWER_BINARY_CONTRADICTION'):
   assess(self.l,[answer(self.l,'Q-075:DEFECT','NO','In realta esistono difetti')])
 def test_wrong_attempt_rejected(self):
  x=answer(self.l,'Q-075:DEFECT','NO');x['attempt_id']='0'*64
  with self.assertRaisesRegex(s.Blocked,'ANSWER_REPLAY_OR_DRIFT'):
   assess(self.l,[x])
 def test_unreviewed_question_cannot_be_invented(self):
  x=answer(self.l,'Q-075:DEFECT','NO');x['rule_id']='BEHAVIOR-051'
  with self.assertRaisesRegex(s.Blocked,'ANSWER_UNREVIEWED_OR_NOT_DUE'):
   assess(self.l,[x])
 def test_reviewed_source_change_blocks(self):
  i=copy.deepcopy(self.inv)
  i['rules']['Q-075']['requirement']='Invented question?'
  i['rules']['Q-075']['requirement_sha256']=sha('Invented question?')
  with self.assertRaisesRegex(s.Blocked,'ANSWER_REVIEWED_CLAUSE_DRIFT'):s.build(i)
 def test_unreviewed_and_missing_remain_open(self):
  r=assess(self.l,[])
  self.assertIn('BEHAVIOR-051',r['unreviewed_due'])
  self.assertTrue(r['missing']);self.assertEqual(r['status'],'UNKNOWN')
 def test_all_six_fixture_rules_get_a_question_without_giving_fake_pass(self):
  self.assertTrue(all(row['questions'] for row in self.l['entries'].values()))
  self.assertEqual(self.l['question_count'],7)
  self.assertEqual(self.l['entries']['BEHAVIOR-051']['classification'],
                   'GENERIC_CHECK_REVIEW_PENDING')
 def test_generic_unreviewed_no_is_fail(self):
  q='BEHAVIOR-051:CONTROL_CHECK'
  r=assess(self.l,[answer(self.l,q,'NO')])
  self.assertIn(q,r['failed'])
  self.assertIn('BEHAVIOR-051',r['unreviewed_due'])
 def test_generic_unreviewed_yes_stays_unknown(self):
  q='BEHAVIOR-051:CONTROL_CHECK'
  r=assess(self.l,[answer(self.l,q,'YES')])
  self.assertEqual(r['status'],'UNKNOWN')
  self.assertFalse(r['advancement_authorized'])
 def test_fake_evidence_digest_rejected(self):
  x=answer(self.l,'Q-075:DEFECT','NO',
           refs=[{'ref':'looks fine','sha256':'fake'}])
  with self.assertRaisesRegex(s.Blocked,'ANSWER_UNTRUSTED_EVIDENCE_SCHEMA'):
   assess(self.l,[x])

class Reviewed758Regression(unittest.TestCase):
 def manifest(self):
  base=Path(s.__file__).resolve().parent
  a=json.loads((base/s.QUESTION_FILES[0]).read_text(encoding='utf-8'))['questions']
  b=json.loads((base/s.QUESTION_FILES[1]).read_text(encoding='utf-8'))['questions']
  for rid in set(a)&set(b):self.assertEqual(a[rid],b[rid])
  return {**a,**b}
 def inventory(self):
  manifest=self.manifest()
  rows={rid:{'requirement_sha256':v['requirement_sha256'],
             'source_sha256':v['source_sha256']} for rid,v in manifest.items()}
  for rid,(clause,_) in s.REVIEWED.items():
   rows[rid]={'requirement_sha256':sha(clause),'source_sha256':'a'*64}
  return {'canonical_master_sha256':s.QUESTION_MASTER_PIN,
          'rule_count':763,'rules':rows}
 def test_758_unique_source_bound_and_72_compound_pending(self):
  inv=self.inventory();wording=s._verified_wording(inv)
  self.assertEqual(len(wording),758)
  self.assertEqual(sum(x['compound_review'] for x in wording.values()),72)
  specs=s.questions_for(inv)
  self.assertEqual(sum(len(x['questions']) for x in specs.values()),764)
  self.assertEqual(sum(x['classification']=='YES_NO_WORDING_REVIEWED_PROOF_PENDING'
                       for x in specs.values()),758)
  self.assertEqual(specs['Q-061']['questions'][0]['type'],'REQUIREMENT_SATISFIED')
  self.assertIn('dimensioni',specs['Q-061']['questions'][0]['text'])
  self.assertFalse(any('Hai effettuato il controllo previsto dalla regola canonica' in q['text']
                       for x in specs.values() for q in x['questions']))
 def test_758_cannot_hide_missing_or_changed_rule(self):
  i=self.inventory()
  del i['rules']['Q-061']
  with self.assertRaisesRegex(s.Blocked,'ANSWER_758_MEMBERSHIP'):s._verified_wording(i)
  i=self.inventory();i['rules']['Q-061']['requirement_sha256']='0'*64
  with self.assertRaisesRegex(s.Blocked,'ANSWER_758_SOURCE_DRIFT:Q-061'):s._verified_wording(i)
 def test_old_master_blocks_758_reuse(self):
  i=self.inventory();i['canonical_master_sha256']='e'*64
  with self.assertRaisesRegex(s.Blocked,'ANSWER_758_LIBRARY_MASTER_DRIFT'):s._verified_wording(i)
 def test_yes_no_statement_is_still_not_a_work_pass(self):
  # The real source-bound manifest is also checked above; this unit fixture
  # deliberately binds one revised question to an isolated answer packet.
  i=fixture()
  wording={'BEHAVIOR-051':{'question':'Hai evitato di aggirare il controllo?',
             'compound_review':False}}
  with patch.object(s,'_verified_wording',return_value=wording):
   l=s.build(i)
  q='BEHAVIOR-051:REQUIREMENT'
  self.assertEqual(assess(l,[answer(l,q,'NO')])['status'],'FAIL')
  yes=assess(l,[answer(l,q,'YES',refs=[{'ref':'PR','sha256':'c'*64}])])
  self.assertEqual(yes['status'],'UNKNOWN')
  self.assertFalse(yes['advancement_authorized'])

if __name__=='__main__':unittest.main()
