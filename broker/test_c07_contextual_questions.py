"""Owner-approved B scope: 300 remain visible, exclusions never PASS."""
import copy
import hashlib
import unittest
from unittest.mock import patch

import family_coverage as f
import c07_contextual_questions as q
import c07_operation_scope as scope
import c07_questions_300 as bank
import supervisor_judgment as j
from test_family_coverage import synthetic_sources
from test_supervisor_judgment import contexts, FixtureBackend, work
from test_supervisor_context import seal

class BScopeTests(unittest.TestCase):
    def setUp(self):
        raw=synthetic_sources()
        self.pin=patch.object(f,'AUX_PINS',{k:f.sha(raw[k]) for k in f.AUX_PINS})
        self.pin.start()
        self.addCleanup(self.pin.stop)
        self.inv=f.build_inventory(raw,f.sha(raw['master']))
        self.plan={'master_sha256':self.inv['canonical_master_sha256'],
                   'phase':'P8','asset_type':'architecture',
                   'profiles':['ARCHITECTURE_PROFILE'],
                   'enrolled':{},'mode':'DIAGNOSTIC_ONLY'}
    def owner_context(self, exclusions=('Q-109','Q-252')):
        rows={}
        for rid in exclusions:
            rows[rid]={'requirement_sha256':self.inv['rules'][rid]['requirement_sha256'],
                       'reason':'The owner-reviewed exact operation excludes this feature and the attached source describes why it is out of scope.',
                       'evidence_ref':'reviews/owner-approved-exact-scope.json',
                       'evidence_sha256':'e'*64,
                       'review_authority':'OWNER_APPROVED_CONTROLLER_STATUS'}
        return {'schema':q.SCHEMA,'master_sha256':self.plan['master_sha256'],
                'phase':self.plan['phase'],'asset_type':self.plan['asset_type'],
                'profiles':self.plan['profiles'],'exclusions':rows}
    def test_default_keeps_all_300_due_no_guessed_waivers(self):
        r=q.select(self.inv,self.plan)
        self.assertEqual(r['total_questions'],300)
        self.assertEqual(r['due_count'],300)
        self.assertEqual(r['excluded_count'],0)
        self.assertEqual(len(r['rows']),300)
        self.assertFalse(r['work_advancement_authorized'])
    def test_owner_reasons_but_never_semantic_or_mg0_pass(self):
        self.plan['question_context']=self.owner_context()
        r=q.select(self.inv,self.plan)
        self.assertEqual(r['due_count'],298)
        self.assertEqual(r['excluded_count'],2)
        self.assertEqual(len(r['rows']),300)
        self.assertTrue(set(r['dynamic_discovery_always_due'])<=set(r['due']))
        for rid in ('Q-109','Q-252'):
            item=r['rows'][rid]
            self.assertEqual(item['semantic_result'],'NOT_EVALUATED')
            self.assertEqual(item['individual_mg0'],'NOT_DUE_NO_PASS')
            self.assertFalse(item['advancement_authorized'])
            self.assertIn('owner-reviewed',item['reason'])
        scoped=scope.inspect(self.inv,self.plan)
        self.assertEqual(scoped['context_excluded'],['Q-109','Q-252'])
        self.assertEqual(len(scoped['due'])+len(scoped['future_phase'])+
                         len(scoped['not_applicable'])+len(scoped['context_excluded']),763)
        self.assertNotIn('Q-109',scoped['missing_due_validators'])
        self.assertIn('Q-108',scoped['missing_due_validators'])
        report=bank.inspect(self.inv,self.plan)
        self.assertEqual(report['owner_reviewed_context_exclusions'],2)
        self.assertEqual(report['context_due_count'],298)
        self.assertEqual(report['questions']['Q-252']['individual_mg0'],'UNKNOWN')
        self.assertFalse(report['advancement_authorized'])
    def test_prohibit_discovery_and_closure_waiver(self):
        for rid in ('Q-280','Q-284','Q-285','Q-286','Q-299','Q-300'):
            self.plan['question_context']=self.owner_context((rid,))
            with self.assertRaisesRegex(q.ContextBlocked,'CANNOT_BE_EXCLUDED'):
                q.select(self.inv,self.plan)
    def test_missing_non_specific_or_wrong_hash_rejected(self):
        for mutation in ('hash','generic','ref','master','phase','id'):
            ctx=self.owner_context(('Q-109',))
            if mutation=='hash':ctx['exclusions']['Q-109']['requirement_sha256']='0'*64
            if mutation=='generic':ctx['exclusions']['Q-109']['reason']='not applicable'
            if mutation=='ref':ctx['exclusions']['Q-109']['evidence_ref']='https://example.com/claim'
            if mutation=='master':ctx['master_sha256']='1'*64
            if mutation=='phase':ctx['phase']='P0'
            if mutation=='id':ctx['exclusions']['FAKE']=ctx['exclusions'].pop('Q-109')
            self.plan['question_context']=ctx
            with self.assertRaises(q.ContextBlocked):
                q.select(self.inv,self.plan)
    def test_both_proof_and_current_backend_keep_excluded_na_not_pass(self):
        self.plan['question_context']=self.owner_context(('Q-109',))
        w=work()
        w['master_sha256']=self.inv['canonical_master_sha256']
        w['phase']='P8';w['asset_type']='architecture'
        w['profiles']=['ARCHITECTURE_PROFILE']
        w['question_context']=copy.deepcopy(self.plan['question_context'])
        c=contexts()
        for role in c:
            c[role]['master']['sha256']=w['master_sha256']
            seal(c[role])
        backend=FixtureBackend()
        result=j.judge(self.inv,w,{},backend,current_contexts=c)
        skipped=result['families']['QUESTIONS_300']['Q-109']
        self.assertEqual(skipped['result'],'N_A')
        self.assertEqual(skipped['mg0'],'NOT_DUE_NO_CURRENT_RULE_PASS')
        self.assertEqual(skipped['expected_applicability'],'N_A_CONTEXT_OWNER_REVIEWED')
        self.assertIn('owner_scope_exclusion',skipped['applicability_basis'])
        self.assertEqual(result['rule_count'],763)
        self.assertFalse(result['advancement_authorized'])
    def test_no_producer_supplied_reply_controls_applicability(self):
        self.plan['question_context']=self.owner_context(('Q-109',))
        r=q.select(self.inv,self.plan)
        r['rows']['Q-109']['selection']='DUE'
        self.assertEqual(q.select(self.inv,self.plan)['rows']['Q-109']['selection'],
                         'CONTEXT_EXCLUDED_OWNER_REVIEWED_NOT_PASS')

if __name__=='__main__':unittest.main()
