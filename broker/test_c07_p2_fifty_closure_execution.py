"""One execution, 50 exact P2 source rules and their certification blockers.

All four asset categories are supplied with ORIGINAL current Controller
contexts. We test every source predicate across the 50, absent proof and
tampered operation; no synthetic positive counts as MG0/full artistic PASS.
"""
import copy
import unittest
from unittest.mock import patch
from test_c07_p2_fifty_native_macro import P2FiftyNativeMacroTests
from test_c07_p2_fifty_asset_type_domain import serialized
from c07_p2_fifty_closure_execution import (
    inspect, IDS50, ASSET_TYPES, EXPECTED_DUE,
    ENGINE_RULE, P2FiftyClosureBlocked)

class CompleteP2FiftyBatchTests(unittest.TestCase):
    def batch(self):
        fixture=P2FiftyNativeMacroTests(
            'test_all_fifty_exact_rule_ids_type_scoped_100_original_predicates')
        mapping={}
        fixtures={}
        for kind in ASSET_TYPES:
            fx=fixture.fixture(kind)
            # fixture owns teardown for every original temporary controller.
            mapping[kind]=fixture.ctx(fx)
            fixtures[kind]=fx
        self.addCleanup(fixture.doCleanups)
        return mapping,fixtures

    def test_entire_fifty_rule_batch_is_really_executed_in_one_call(self):
        contexts,_=self.batch()
        result=inspect(contexts)
        self.assertEqual(result['exact_original_rules_examined'],50)
        self.assertEqual(set(result['rules']),set(IDS50))
        self.assertEqual(len(result['current_original_contexts']),4)
        self.assertEqual(result['independent_original_source_checks'],100)
        self.assertEqual(result['original_source_positive_checks']+
                         result['original_source_missing_checks'],100)
        self.assertEqual(sum(EXPECTED_DUE.values()),50)
        for rid,entry in result['rules'].items():
            with self.subTest(rule=rid):
                self.assertEqual(entry['asset_type'],
                    contexts[entry['asset_type']]['work']['asset_type'])
                self.assertEqual(len(entry['source_checks']),2)
                self.assertFalse(entry['code_review_full'])
                self.assertEqual(entry['full_rule_semantics'],'UNKNOWN')
                self.assertEqual(entry['individual_mg0'],'UNKNOWN')
                self.assertFalse(entry['advancement_authorized'])
                self.assertEqual(entry['source_observations_complete'],
                                 all(entry['source_checks'].values()))
                self.assertEqual(set(entry['missing_original_source_checks']),
                    {k for k,v in entry['source_checks'].items() if not v})
                self.assertGreaterEqual(len(entry['independent_qa_missing']),2)
        self.assertIn('independent_fivem_wind_engine_execution',
                      result['rules'][ENGINE_RULE]['independent_qa_missing'])
        self.assertEqual(result['full_rule_certifications'],0)
        self.assertEqual(result['individual_mg0_passes'],0)
        self.assertFalse(result['advancement_authorized'])

    def test_every_one_of_fifty_must_be_due_once_not_misclassified(self):
        contexts,_=self.batch()
        baseline=inspect(contexts)
        self.assertEqual([x['asset_type'] for x in baseline['rules'].values()]
                         .count('architecture'),20)
        for kind in ASSET_TYPES:
            with self.subTest(asset_type=kind):
                omitted=dict(contexts);omitted.pop(kind)
                with self.assertRaisesRegex(P2FiftyClosureBlocked,
                        'EXACT_FOUR_ASSET_TYPE_CONTEXTS_REQUIRED'):
                    inspect(omitted)

    def test_wrong_asset_type_context_never_lets_na_rule_pass(self):
        contexts,_=self.batch()
        contexts['terrain']=contexts['architecture']
        with self.assertRaisesRegex(P2FiftyClosureBlocked,
                'WRONG_ASSET_OR_UNTRUSTED_CONTEXT'):
            inspect(contexts)

    def test_missing_original_vegetation_alpha_pin_reports_source_gap(self):
        contexts,fixtures=self.batch()
        t=fixtures['vegetation']
        t.f.plan['p2_evidence_contract'][
            'original_artifact_sha256'].pop('P2_LEAF_CARD_PNG')
        # Rebuild a *new authenticated plan* with intentionally absent
        # original evidence: tampering the enrolled plan is correctly blocked.
        t.f.rebuild()
        contexts['vegetation']=P2FiftyNativeMacroTests.ctx(t)
        result=inspect(contexts)
        entry=result['rules']['AAA-200-J-095']
        self.assertIn('original_leaf_card_R_G_B_A_PNG_bytes_decoded',
                       entry['missing_original_source_checks'])
        self.assertEqual(entry['full_rule_semantics'],'UNKNOWN')

    def test_terrain_elevation_without_numeric_source_stays_unverified(self):
        contexts,fixtures=self.batch()
        t=fixtures['terrain']
        t.f.plan['p2_evidence_contract'][
            'original_artifact_sha256'].pop('P2_SURVEY')
        t.f.rebuild()
        contexts['terrain']=P2FiftyNativeMacroTests.ctx(t)
        result=inspect(contexts)
        rule=result['rules']['AAA-200-K-101']
        self.assertFalse(rule['source_observations_complete'])
        self.assertEqual(rule['individual_mg0'],'UNKNOWN')

    def test_current_controller_operation_tampered_for_one_type_blocks_whole_fifty(self):
        contexts,_=self.batch()
        contexts['organic']=dict(contexts['organic'])
        contexts['organic']['work']=dict(contexts['organic']['work'],
                                      attempt_id='0'*64)
        with self.assertRaises(ValueError):
            inspect(contexts)

    def test_independent_runtime_and_owner_claims_never_confer_full(self):
        contexts,_=self.batch()
        result=inspect(contexts)
        self.assertEqual(result['independent_owner_approvals'],0)
        for rid,rule in result['rules'].items():
            self.assertEqual(rule['owner_approval'],'UNVERIFIED')
            self.assertNotEqual(rule['fivem_runtime'],'PASS')
            self.assertTrue(rule['independent_qa_missing'])
        self.assertNotIn('PASS',str([
            rule['full_rule_semantics'] for rule in result['rules'].values()]))

    def test_original_source_proofs_cannot_be_turned_into_full_by_whitelist_mutation(self):
        contexts,_=self.batch()
        with patch('c07_p2_fifty_closure_execution.FULL_LITERAL_REVIEWED',
                   frozenset(IDS50)):
            with self.assertRaisesRegex(P2FiftyClosureBlocked,
                'DUPLICATE_OR_PREMATURE_FULL'):
                inspect(contexts)

if __name__=='__main__':
    unittest.main()
