"""R131: synthetic 110 rule-record convergence into one immutable 200 receipt.

Fixture substitutes 110 existing synthetic IDs solely for exercising the
aggregation plumbing. It never grants real work, behavior, owner or MG0 PASS.
"""
import copy
import unittest
from unittest.mock import patch

import c07_behavior110_remediation as behavior
import c07_positive200_evidence as m
import test_c07_r127_exact200_readback as base
from real_work_intake import canonical,sha

class Tests(unittest.TestCase):
    def setUp(self):
        self.fixture=base.Tests('test_200_original_ids_each_scanned_not_pass')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture
        ids=tuple(self.f.f.ids[:110])
        patcher=patch.object(behavior,'IDS',ids)
        patcher.start();self.addCleanup(patcher.stop)
        w=self.f.w
        self.r130={**w,
           'schema':'gg-c07-r130-original-110-remediation-evidence-v1',
           'source_rules_examined':110,
           'rule_count_with_semantic_PASS':0,'individual_mg0_PASS':0,
           'advancement_authorized':False,'result':'UNKNOWN',
           'rules':{rid:{'rule_id':rid,
              'source_sha256':self.f.f.inv['rules'][rid]['source_sha256'],
              'requirement_sha256':self.f.f.inv['rules'][rid]['requirement_sha256'],
              'observed_failure_count':0,'observations':[],
              'semantic_result':'UNKNOWN','individual_mg0':'UNKNOWN',
              'independent_prevention_effectiveness':'UNKNOWN',
              'real_owner_identity':'UNKNOWN','new_full_rule_pass':False,
              'advancement_authorized':False} for rid in ids}}
        self.rebuild()

    def rebuild(self):
        f=self.f
        f.rows=[]
        f.add('INIT')
        self.r130['original_audit_tail']=f.rows[-1]['record_hash']
        self.r130['original_audit_sha256']=sha(f.audit())
        f.add('SUPERVISOR_C07_R130_BEHAVIOR110_REMEDIATION',
              per_rule_verdicts=copy.deepcopy(self.r130['rules']))
        f.r120['audit_tail']=f.rows[-1]['record_hash']
        f.add('SUPERVISOR_C07_R120_POSITIVE_PROCESS_BATCH',
              results=copy.deepcopy(f.r120['results']))
        f.r123['audit_tail_sha256']=f.rows[-1]['record_hash']
        f.r123['audit_sha256']=sha(f.audit())
        f.add('SUPERVISOR_C07_R123_NATIVE_POSITIVE_PROCESS',
              source_specific_semantic_observations=copy.deepcopy(f.r123['rules']))
        f.r124['real_controller_audit_tail']=f.rows[-1]['record_hash']
        f.r124['real_controller_audit_sha256']=sha(f.audit())
        f.add('SUPERVISOR_C07_R124_EIGHT_POSITIVE_PROCESS_SCOPES',
              exact_rule_source_evidence=copy.deepcopy(f.r124['rules']))
        f.r122['original_controller_audit_tail']=f.rows[-1]['record_hash']
        f.r122['original_controller_audit_sha256']=sha(f.audit())
        f.r122['report_sha256']=m.digest({k:v for k,v in f.r122.items()
                                         if k!='report_sha256'})
        f.add('SUPERVISOR_C07_R122_POSITIVE200_NATIVE_GAP_AUDIT',
              report_sha256=f.r122['report_sha256'])
        f.f.c._raw=f.audit()
        f.f.c._state['last_audit_hash']=f.rows[-1]['record_hash']
        f.mg['audit_sha256']=sha(f.audit())
        f.mg['audit_tail_sha256']=f.rows[-1]['record_hash']

    def review(self):
        f=self.f
        return m.reconcile_current200(f.f.inv,f.f.plan,f.f.c,'GARDEN',
          'STEP0100',f.w,r120=f.r120,r123=f.r123,r124=f.r124,
          r122=f.r122,r130=self.r130)

    def test_complete_110_source_evidence_converges_into_fixed_200_without_pass(self):
        report=self.review()
        self.assertEqual(report['source_rules_examined'],200)
        self.assertEqual(report['original_behavior110_individual_evidence_converged'],110)
        self.assertEqual(report['full_rule_passes'],0)
        self.assertEqual(report['individual_mg0_passes'],0)
        self.assertEqual(report['behavior110_failed_rule_ids'],[])
        self.assertFalse(report['advancement_authorized'])
        for rid in behavior.IDS:
            self.assertEqual(report['rules'][rid]['combined_result'],'UNKNOWN')
            self.assertFalse(report['rules'][rid]['full_rule_pass'])

    def test_behavior_failure_is_not_erased_by_unknown_mg0(self):
        rid=behavior.IDS[0]
        self.r130['rules'][rid]['semantic_result']='FAIL'
        self.r130['result']='FAIL'
        self.rebuild()
        report=self.review()
        self.assertIn(rid,report['behavior110_failed_rule_ids'])
        self.assertEqual(report['rules'][rid]['combined_result'],'FAIL')
        self.assertEqual(report['result'],'FAIL')
        self.assertEqual(report['full_rule_passes'],0)

    def test_fake_positive_full_rule_semantics_is_blocked(self):
        rid=behavior.IDS[0]
        self.r130['rules'][rid]['new_full_rule_pass']=True
        self.rebuild()
        with self.assertRaisesRegex(ValueError,'BEHAVIOR_RULE_SOURCE_MG0_OR_FALSE_PASS'):
            self.review()

    def test_fake_individual_mg0_pass_is_blocked(self):
        rid=behavior.IDS[4]
        self.r130['rules'][rid]['individual_mg0']='PASS'
        self.rebuild()
        with self.assertRaisesRegex(ValueError,'BEHAVIOR_RULE_SOURCE_MG0_OR_FALSE_PASS'):
            self.review()

    def test_changed_behavior_receipt_after_audit_is_blocked(self):
        rid=behavior.IDS[1]
        self.r130['rules'][rid]['semantic_result']='FAIL'
        with self.assertRaisesRegex(ValueError,'R130_RECEIPT_DIFFERENT_FROM_REAL_AUDIT'):
            self.review()

    def test_report_for_different_attempt_is_rejected(self):
        self.r130['attempt_id']='e'*64
        with self.assertRaisesRegex(ValueError,'R131_ORIGINAL_BEHAVIOR_110'):
            self.review()

    def test_109_instead_of_110_reported_ids_is_rejected(self):
        self.r130['rules'].pop(behavior.IDS[5])
        with self.assertRaisesRegex(ValueError,'R131_ORIGINAL_BEHAVIOR_110'):
            self.review()

if __name__=='__main__':unittest.main()