"""C07 R128: fixed original 200 IDs as per authentic R122 immutable checkpoint.

The synthetic 763-item fixture mirrors canonical source structure but is
not production proof. These tests verify correct 200-rule batch advancement
without hiding already implemented reviewers or minting semantic/MG0 PASS.
"""
import hashlib
import unittest
from unittest.mock import patch
import c07_positive200_evidence as p
import test_c07_positive200_evidence as old


PIN='63f56366b9b4be5a491db3feccec99860110191474baf68aa6da7e86d226b355'
AAA_PIN='f9e7e0d11398c26095f5b3a83a2cf1e8a14ea459bc47dc09c4dfad891664fcf9'


class FrozenCohortTests(unittest.TestCase):
    def setUp(self):
        self.f=old.R122PositiveBatchTest('test_all_200_original_rule_ids_unknown_not_pass')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        ids=list(p.R122_FROZEN_IDS)
        original=self.f.inv
        original['source_digests']={'aaa_catalog':AAA_PIN}
        original['rules']={}
        self.f.ids=ids
        self.f.scoped['due']=ids
        self.f.scoped['by_rule']={}
        for rid in ids:
            req=('\\n'.join(f'{i:03}. Errore: e{i} → c{i}' for i in range(1,111))
                 if rid=='110_ERROR_REGISTRY' else 'source requirement '+rid)
            family=('AAA-200' if rid.startswith('AAA-200-') else
                    'BEHAVIOR_110' if rid.startswith('BEHAVIOR-') else
                    'EXECUTION' if rid.startswith('EXEC-') else 'GOVERNANCE')
            original['rules'][rid]={'requirement':req,
                'requirement_sha256':hashlib.sha256(req.encode()).hexdigest(),
                'source_sha256':'a'*64,'family':family}
            self.f.scoped['by_rule'][rid]={
                'family':family,
                'source_sha256':'a'*64,
                'requirement_sha256':original['rules'][rid]['requirement_sha256']}
        for i in range(563):
            rid=f'OTHER_{i:03}'
            original['rules'][rid]={'requirement':'other','requirement_sha256':
                hashlib.sha256(b'other').hexdigest(),'source_sha256':'a'*64,
                'family':'GOVERNANCE'}
        self.assertEqual(len(original['rules']),763)
        self.f.process['results']={
            rid:{'scoped_positive_observation':'OBSERVED_SCOPE_PASS'} for rid in ids[:13]}

    def test_frozen_canonical_ids_match_checkpoint_exactly(self):
        self.assertEqual(len(p.R122_FROZEN_IDS),200)
        self.assertEqual(p.digest(list(p.R122_FROZEN_IDS)),PIN)
        result=p.select(self.f.inv,self.f.plan)[0]
        self.assertEqual(result,self.f.ids)

    def test_implementing_first_ten_does_not_replace_them_with_other_rules(self):
        first=p.select(self.f.inv,self.f.plan)[0]
        for rid in first[:10]:p.REVIEWED[rid]=('NATIVE_REVIEWER',('A',))
        second=p.select(self.f.inv,self.f.plan)[0]
        self.assertEqual(first,second)
        self.assertEqual(len(second),200)
        self.assertEqual(sum(r in p.REVIEWED for r in second),10)
        self.assertEqual(len(set(second)),200)

    def test_progress_report_tracks_implementation_not_asset_pass(self):
        rid='BEHAVIOR-001'
        p.REVIEWED[rid]=('FULL_REVIEWED',('A',))
        report=self.f.run_engine()
        self.assertTrue(report['frozen_first200_ids'])
        self.assertEqual(report['cohort_reviewed_implementations'],1)
        self.assertEqual(report['cohort_missing_reviewed_implementations'],199)
        self.assertNotIn('RULE_SPECIFIC_FULL_NATIVE_REVIEWED_VERIFIER',
                         report['rules'][rid]['missing_evidence'])
        self.assertEqual(report['rules'][rid]['full_semantics'],'UNKNOWN')
        self.assertEqual(report['unknown_count'],200)
        self.assertEqual(report['full_semantic_passes_on_current_attempt'],0)
        self.assertEqual(report['individual_mg0_passes'],0)
        self.assertFalse(report['advancement_authorized'])

    def test_reviewed_rule_does_not_disappear_from_original_200(self):
        rid='AAA-200-R-172'
        p.REVIEWED[rid]=('FULL_REVIEWED',('A',))
        result=self.f.run_engine()
        self.assertIn(rid,result['rules'])
        self.assertEqual(result['source_rule_ids_sha256'],PIN)

    def test_no_reviewer_does_not_pretend_to_complete_cohort(self):
        report=self.f.run_engine()
        self.assertEqual(report['cohort_reviewed_implementations'],0)
        self.assertEqual(report['cohort_missing_reviewed_implementations'],200)
        self.assertEqual(report['full_native_positive_verified_new'],0)

    def test_missing_canonical_rule_fails_closed_not_replace_with_other(self):
        self.f.inv['rules'].pop('BEHAVIOR-050')
        self.f.inv['rules']['OTHER_REPLACEMENT']={
            'requirement':'other','requirement_sha256':hashlib.sha256(b'other').hexdigest(),
            'source_sha256':'a'*64,'family':'GOVERNANCE'}
        with self.assertRaises((p.PositiveBatchBlocked,KeyError)):
            p.select(self.f.inv,self.f.plan)

    def test_missing_due_rule_fails_closed(self):
        self.f.scoped['due'].remove('G0-01')
        with self.assertRaisesRegex(p.PositiveBatchBlocked,
                                    'R128_COHORT_NOT_ALL_DUE'):
            p.select(self.f.inv,self.f.plan)

    def test_mutated_rule_content_fails_even_for_reviewed_rule(self):
        rid='BEHAVIOR-052'
        p.REVIEWED[rid]=('FULL_REVIEWED',('A',))
        self.f.inv['rules'][rid]['requirement']='forged source text'
        with self.assertRaisesRegex(p.PositiveBatchBlocked,
                                    'R122_REQUIREMENT_SOURCE_DRIFT'):
            p.select(self.f.inv,self.f.plan)

    def test_fake_canonical_catalog_pin_is_rejected(self):
        self.f.inv['source_digests']['aaa_catalog']='0'*64
        with self.assertRaisesRegex(p.PositiveBatchBlocked,
                                    'R128_UNRECOGNIZED_CANONICAL_INVENTORY'):
            p.select(self.f.inv,self.f.plan)

    def test_no_producer_pass_from_reviewed_status_or_green_tests(self):
        for rid in self.f.ids[:10]:p.REVIEWED[rid]=('FULL_REVIEWED',('A',))
        report=self.f.run_engine()
        self.assertEqual(report['cohort_reviewed_implementations'],10)
        self.assertEqual(report['full_semantic_passes_on_current_attempt'],0)
        self.assertTrue(all(x['full_semantics']=='UNKNOWN'
                            and x['individual_mg0']=='UNKNOWN'
                            and x['work_pass'] is False
                            for x in report['rules'].values()))


if __name__=='__main__':unittest.main()
