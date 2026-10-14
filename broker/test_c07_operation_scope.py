"""C07 source-bound applicability tests: never imply an asset or MG0 PASS."""
import copy
import unittest

import c07_operation_scope as scope
from test_supervisor_judgment import inventory


def plan(inv):
    return {'master_sha256': inv['canonical_master_sha256'],
            'phase': 'P0', 'asset_type': 'vegetation',
            'profiles': ['FOLIAGE_PROFILE'], 'enrolled': {},
            'mode': 'OPERATIONAL', 'asset_specific_extensions_verified': True}


class Tests(unittest.TestCase):
    def test_every_family_and_due_rule_remains_visible(self):
        inv = inventory()
        report = scope.inspect(inv, plan(inv))
        self.assertEqual(report['rule_count'], 2)
        self.assertEqual(report['family_count'], 2)
        self.assertEqual(set(report['by_rule']), set(inv['rules']))
        self.assertEqual(report['due'], ['EXEC-003', 'PROFILE_FOLIAGE'])
        self.assertEqual(report['missing_due_validators'], report['due'])
        self.assertFalse(report['work_advancement_authorized'])
        self.assertFalse(report['individual_rule_mg0_verified'])

    def test_operational_plan_cannot_enroll_omitted_due_rule(self):
        inv = inventory()
        p = plan(inv)
        p['enrolled']['EXEC-003'] = {'validator_id': 'some-reviewed-validator'}
        with self.assertRaisesRegex(scope.IncompleteOperationScope,
                                    'C07_SCOPE_MISSING_DUE_SEMANTIC_VALIDATORS:1:PROFILE_FOLIAGE'):
            scope.require_due_enrolled(inv, p)

    def test_full_due_coverage_is_not_semantic_or_mg0_pass(self):
        inv = inventory()
        p = plan(inv)
        p['enrolled'] = {rid: {'validator_id': 'fixture-not-approved'}
                         for rid in inv['rules']}
        result = scope.require_due_enrolled(inv, p)
        self.assertTrue(result['due_validators_complete'])
        self.assertFalse(result['individual_rule_mg0_verified'])
        self.assertFalse(result['work_advancement_authorized'])

    def test_phase_future_and_canonical_na_not_erased(self):
        inv = inventory()
        inv['rules']['EXEC-003'].update(catalog_phase='P8', asset_type='all')
        inv['rules']['PROFILE_FOLIAGE'].update(catalog_phase='P0', asset_type='terrain')
        report = scope.inspect(inv, plan(inv))
        self.assertEqual(report['due'], [])
        self.assertEqual(report['future_phase'], ['EXEC-003'])
        self.assertEqual(report['not_applicable'], ['PROFILE_FOLIAGE'])
        self.assertEqual(len(report['by_rule']), 2)

    def test_duplicate_and_missing_families_block(self):
        inv = inventory()
        inv['families']['EXECUTION'].append('PROFILE_FOLIAGE')
        with self.assertRaisesRegex(scope.IncompleteOperationScope,
                                    'INVENTORY_MISSING_DUPLICATED_IDS'):
            scope.inspect(inv, plan(inv))

    def test_source_drift_blocks(self):
        inv = inventory()
        p = plan(inv)
        p['master_sha256'] = 'f' * 64
        with self.assertRaisesRegex(scope.IncompleteOperationScope,
                                    'C07_SCOPE_MASTER_SOURCE_DRIFT'):
            scope.inspect(inv, p)

    def test_unverified_extensions_block_operational_not_diagnostic(self):
        inv = inventory()
        p = plan(inv)
        p['enrolled'] = {rid: {} for rid in inv['rules']}
        p['asset_specific_extensions_verified'] = False
        with self.assertRaisesRegex(scope.IncompleteOperationScope,
                                    'C07_SCOPE_ASSET_SPECIFIC_EXTENSIONS_UNVERIFIED'):
            scope.require_due_enrolled(inv, p)
        p['mode'] = 'DIAGNOSTIC_ONLY'
        self.assertFalse(scope.require_due_enrolled(inv, p)['work_advancement_authorized'])

    def test_missing_due_allows_diagnostic_only_never_authorizes(self):
        inv = inventory()
        p = plan(inv)
        p['mode'] = 'DIAGNOSTIC_ONLY'
        report = scope.require_due_enrolled(inv, p)
        self.assertEqual(len(report['missing_due_validators']), 2)
        self.assertFalse(report['work_advancement_authorized'])


if __name__ == '__main__':
    unittest.main()
