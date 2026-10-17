"""R127: synthetic full 200 original audit proof aggregation tests."""
import copy
import unittest
from unittest.mock import patch
import c07_positive200_evidence as m
from real_work_intake import canonical, sha
from test_c07_positive200_evidence import R122PositiveBatchTest

P120=('AAA-200-A-004','AAA-200-A-005','AAA-200-B-011',
 'AAA-200-B-016','AAA-200-B-017','AAA-200-R-171','AAA-200-R-172',
 'AAA-200-R-175','AAA-200-R-176','AAA-200-R-177','AAA-200-R-178',
 'AAA-200-R-179','AAA-200-R-180')
P123=('AAA-200-R-172','AAA-200-R-178')
P124=tuple('AAA-200-R-'+str(n).zfill(3)
 for n in (171,173,174,175,176,177,179,180))

class Tests(unittest.TestCase):
 def setUp(self):
  f=R122PositiveBatchTest('test_all_200_original_rule_ids_unknown_not_pass')
  f.setUp();self.f=f;self.addCleanup(f.doCleanups)
  self.r122=f.run_engine();self.w=f.work
  b=dict(self.w)
  self.r120={**b,'complete_work_rule_passes':0,'individual_mg0_passes':0,
   'advancement_authorized':False,'results':{
   rid:{'rule_id':rid,'source_sha256':f.inv['rules'][rid]['source_sha256'],
    'requirement_sha256':f.inv['rules'][rid]['requirement_sha256'],
    'scope_criteria':{'original':True},'individual_mg0':'UNKNOWN',
    'work_pass':False} for rid in P120}}
  self.r123={**b,'rule_count':2,'full_work_rule_passes':0,
   'individual_mg0_passes':0,'advancement_authorized':False,
   'rules':{rid:{'source_sha256':'a'*64,
    'requirement_sha256':f.inv['rules'][rid]['requirement_sha256'],
    'criteria':{'bytes':True},'semantic_result':'SEMANTIC_OBSERVED',
    'individual_mg0':'UNKNOWN','advancement_authorized':False}
    for rid in P123}}
  self.r124={**b,'source_rules_evaluated':8,'individual_mg0_passes':0,
    'full_current_attempt_rule_passes':0,
    'full_native_semantic_certifications_new':0,
    'advancement_authorized':False,'rules':{
    rid:{'rule_id':rid,'source_sha256':'a'*64,
    'requirement_sha256':f.inv['rules'][rid]['requirement_sha256'],
    'machine_checks':{'verified':True,'owner':False},
    'positive_subpredicates':['verified'],'missing_subpredicates':['owner'],
    'full_rule_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
    'advancement_authorized':False} for rid in P124}}
  self.rows=[]
  self.add('INIT')
  self.r120['audit_tail']=self.rows[-1]['record_hash']
  self.add('SUPERVISOR_C07_R120_POSITIVE_PROCESS_BATCH',
    results=copy.deepcopy(self.r120['results']))
  self.r123['audit_tail_sha256']=self.rows[-1]['record_hash']
  self.r123['audit_sha256']=sha(self.audit())
  self.add('SUPERVISOR_C07_R123_NATIVE_POSITIVE_PROCESS',
    source_specific_semantic_observations=copy.deepcopy(self.r123['rules']))
  self.r124['real_controller_audit_tail']=self.rows[-1]['record_hash']
  self.r124['real_controller_audit_sha256']=sha(self.audit())
  self.add('SUPERVISOR_C07_R124_EIGHT_POSITIVE_PROCESS_SCOPES',
    exact_rule_source_evidence=copy.deepcopy(self.r124['rules']))
  self.r122['original_controller_audit_tail']=self.rows[-1]['record_hash']
  self.r122['original_controller_audit_sha256']=sha(self.audit())
  self.r122['report_sha256']=m.digest({
    k:v for k,v in self.r122.items() if k!='report_sha256'})
  self.add('SUPERVISOR_C07_R122_POSITIVE200_NATIVE_GAP_AUDIT',
    report_sha256=self.r122['report_sha256'])
  f.c._raw=self.audit()
  f.c._state['last_audit_hash']=self.rows[-1]['record_hash']
  self.mg={'rule_count':200,'attempt_id':self.w['attempt_id'],
   'audit_sha256':sha(f.c._raw),
   'audit_tail_sha256':self.rows[-1]['record_hash'],
   'counts':{'PASS':0,'UNKNOWN':200,'FAIL':0},
   'individual_mg0_passes':0,'advancement_authorized':False,
   'rules':{rid:{'verdict':'UNKNOWN'} for rid in f.ids}}
  f.patchers[3].stop()
  self.pm=patch('c07_mg0_individual.inspect_batch',return_value=self.mg)
  self.pm.start();self.addCleanup(self.pm.stop)
 def add(self,event,**kw):
  row={'asset':'GARDEN','event':event,
   'attempt_id':self.w['attempt_id'],
   'operation_sha256':self.w['operation_sha256'],
   'prev_hash':self.rows[-1]['record_hash'] if self.rows else 'GENESIS',**kw}
  row['record_hash']=sha(canonical(row));self.rows.append(row)
 def audit(self):return b''.join(canonical(r)+b'\n' for r in self.rows)
 def run(self):
  f=self.f
  return m.reconcile_current200(f.inv,f.plan,f.c,'GARDEN','STEP0100',
   self.w,r120=self.r120,r123=self.r123,r124=self.r124,r122=self.r122)
 def test_200_original_ids_each_scanned_not_pass(self):
  r=self.run()
  self.assertEqual(len(r['rules']),200)
  self.assertEqual(r['unknown_rule_count'],200)
  self.assertEqual(r['full_rule_passes'],0)
  self.assertEqual(r['individual_mg0_passes'],0)
  self.assertFalse(r['advancement_authorized'])
 def test_real_current_mg0_fail_remains_fail(self):
  rid=self.f.ids[0];self.mg['rules'][rid]['verdict']='FAIL'
  self.mg['counts'].update(FAIL=1,UNKNOWN=199)
  r=self.run();self.assertEqual(r['result'],'FAIL')
  self.assertIn(rid,r['mg0_failed_rule_ids'])
 def test_mg0_fake_pass_blocked(self):
  self.mg['counts']['PASS']=1
  with self.assertRaisesRegex(ValueError,'MG0_ORIGINAL_INDIVIDUAL'):
   self.run()
 def test_replayed_r123_attempt_blocked(self):
  self.r123['attempt_id']='e'*64
  with self.assertRaisesRegex(ValueError,'R123_EXACT_ATTEMPT'):
   self.run()
 def test_r124_receipt_changed_after_logging_blocked(self):
  self.r124['rules'][P124[0]]['positive_subpredicates']=['owner']
  with self.assertRaisesRegex(ValueError,'R124_RECEIPT_DIFFERENT'):
   self.run()
 def test_r120_false_pass_after_logging_blocked(self):
  self.r120['results'][P120[0]]['work_pass']=True
  with self.assertRaisesRegex(ValueError,'R120_RECEIPT_DIFFERENT'):
   self.run()

if __name__=='__main__':unittest.main()
