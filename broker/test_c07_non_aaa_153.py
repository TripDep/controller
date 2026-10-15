"""C07 153 source/MG0 adversarial tests: synthetic data never authorizes work."""
import hashlib
import sys
import types
import unittest
from unittest.mock import patch

import c07_non_aaa_153 as gate

SRC = {
    'master': 'governance/sources/GOLDEN_GARDEN_MASTER_RULES_AND_STATE.md',
    'developer_rules': 'governance/sources/ISTRUZIONI_V2_INTEGRALI_CON_110_ERRORI.txt',
    'error_registry': 'governance/sources/REGISTRO_110_ERRORI_E_PREVENZIONE.md',
    'behavior_rules': 'governance/sources/ISTRUZIONI_PROGETTO_GUARD_ASSISTENTE.txt',
    'professional_phases': 'governance/sources/GOLDEN_GARDEN_PROFESSIONAL_ENVIRONMENT_SYSTEM_R110.md',
    'aaa_catalog': 'governance/sources/AAA_200_CANONICAL_CATALOG.json',
}


def sha(v):
    return hashlib.sha256(v.encode()).hexdigest()


def example():
    sizes = {**gate.NON_AAA_FAMILY_COUNTS, **gate.OTHER_COUNTS}
    families, rules = {}, {}
    digests = {k: sha('source-' + k) for k in SRC}
    for family, size in sizes.items():
        group = [f'{family}-TEST-{index:03}' for index in range(size)]
        families[family] = group
        for rid in group:
            source = ('aaa_catalog' if family == 'AAA-200' else
                      'error_registry' if family == 'BEHAVIOR_110' else
                      'professional_phases' if family in
                      ('PROFESSIONAL_PHASES', 'ASSET_PROFILE_READINESS',
                       'PROFESSIONAL_SYSTEM') else 'master')
            requirement = 'Canonical clause for ' + rid
            rules[rid] = {
                'family': family, 'source': source,
                'source_path': SRC[source], 'source_sha256': digests[source],
                'requirement_sha256': sha(requirement),
                'requirement': requirement, 'required_mg0': True,
            }
    inv = {
        'schema': 'gg-effective-family-inventory-v1',
        'families': families, 'rules': rules,
        'source_digests': digests,
        'canonical_master_sha256': sha('master'),
        'rule_count': 763, 'family_count': 20,
    }
    plan = {
        'master_sha256': sha('master'), 'phase': 'P0',
        'asset_type': 'terrain', 'profiles': ['TERRAIN_PATH_PROFILE'],
        'mode': 'DIAGNOSTIC_ONLY', 'enrolled': {},
    }
    return inv, plan


COVERAGE = types.ModuleType('family_coverage')
COVERAGE.SOURCES = SRC
COVERAGE.expected_result = lambda *args: 'PASS'
APPROVED = types.ModuleType('approved_validators')
APPROVED.REVIEWED = {}
MG0 = types.ModuleType('c07_mg0_individual')
MG0.inspect = lambda *args: {'individual_rule_mg0': 'UNKNOWN'}


class SourceGateTests(unittest.TestCase):
    def setUp(self):
        self.inv, self.plan = example()
        self.modules = patch.dict(sys.modules, {
            'family_coverage': COVERAGE,
            'approved_validators': APPROVED,
            'c07_mg0_individual': MG0,
        })
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def test_153_ids_and_no_fabricated_pass(self):
        report = gate.inspect(self.inv, self.plan)
        self.assertEqual(report['evaluated_non_aaa_rules'], 153)
        self.assertEqual(report['registered_canonical_rules'], 763)
        self.assertEqual(report['semantic_passes'], 0)
        self.assertEqual(report['individual_mg0_passes'], 0)
        self.assertEqual(len(report['rules']), 153)
        self.assertEqual(len(report['missing_due_semantic_validators']), 153)
        self.assertFalse(report['advancement_authorized'])
        self.assertTrue(all(
            row['semantic_verdict'] == 'UNKNOWN' and
            row['canonical_source_integrity'] == 'PASS'
            for row in report['rules'].values()))

    def test_operational_missing_validators_fails_closed(self):
        self.plan['mode'] = 'OPERATIONAL'
        with self.assertRaisesRegex(
                gate.Blocked, 'C07_153_DUE_SEMANTIC_VALIDATORS_MISSING:153'):
            gate.require_operational_scope(self.inv, self.plan)

    def test_reviewed_without_controller_enrollment_is_not_enough(self):
        rid = self.inv['families']['META'][0]
        APPROVED.REVIEWED = {rid: ('REVIEWED_PREDICATE', ('check',))}
        self.addCleanup(setattr, APPROVED, 'REVIEWED', {})
        self.assertIn(rid, gate.inspect(self.inv, self.plan)['missing_due_semantic_validators'])
        self.plan['enrolled'][rid] = {'validator_id': 'REVIEWED_PREDICATE'}
        result = gate.inspect(self.inv, self.plan)
        self.assertNotIn(rid, result['missing_due_semantic_validators'])
        self.assertEqual(result['semantic_passes'], 0)
        self.assertEqual(result['rules'][rid]['semantic_verdict'], 'UNKNOWN')

    def test_omission_detected(self):
        self.inv['families']['EXECUTION'].pop()
        with self.assertRaisesRegex(gate.Blocked, 'C07_153_FAMILY_COUNT:EXECUTION'):
            gate.inspect(self.inv, self.plan)

    def test_duplicate_detected(self):
        self.inv['families']['EXECUTION'][0] = self.inv['families']['EXECUTION'][1]
        with self.assertRaisesRegex(gate.Blocked, 'C07_153_763_CANONICAL_MEMBERSHIP'):
            gate.inspect(self.inv, self.plan)

    def test_tampered_requirement_detected(self):
        rid = self.inv['families']['MASTER_CHAIN'][0]
        self.inv['rules'][rid]['requirement'] += ' manipulated'
        with self.assertRaisesRegex(gate.Blocked, 'C07_153_SOURCE_REQUIREMENT_DRIFT'):
            gate.inspect(self.inv, self.plan)

    def test_tampered_digest_detected(self):
        rid = self.inv['families']['DELIVERY'][0]
        self.inv['rules'][rid]['source_sha256'] = 'f' * 64
        with self.assertRaisesRegex(gate.Blocked, 'C07_153_SOURCE_REQUIREMENT_DRIFT'):
            gate.inspect(self.inv, self.plan)

    def test_wrong_rule_family_detected(self):
        rid = self.inv['families']['GOVERNANCE'][0]
        self.inv['rules'][rid]['family'] = 'MASTER_CHAIN'
        with self.assertRaisesRegex(gate.Blocked, 'C07_153_RULE_FAMILY'):
            gate.inspect(self.inv, self.plan)

    def test_wrong_master_detected(self):
        self.plan['master_sha256'] = 'f' * 64
        with self.assertRaisesRegex(gate.Blocked, 'C07_153_TRUSTED_PLAN_AND_MASTER'):
            gate.inspect(self.inv, self.plan)

    def test_partial_mg0_context_rejected(self):
        with self.assertRaisesRegex(
                gate.Blocked, 'C07_153_COMPLETE_REAL_AUDIT_BINDING_REQUIRED'):
            gate.inspect(self.inv, self.plan, audit=b'fixture')

    def test_mg0_failure_blocks_and_stays_fail(self):
        rid = self.inv['families']['META'][0]
        MG0.inspect = lambda _master, _audit, _asset, _sha, rule, _attempt: {
            'individual_rule_mg0': 'FAIL' if rule == rid else 'UNKNOWN'
        }
        self.addCleanup(setattr, MG0, 'inspect',
                        lambda *args: {'individual_rule_mg0': 'UNKNOWN'})
        self.plan['master_sha256'] = sha('actual master')
        self.inv['canonical_master_sha256'] = sha('actual master')
        ctx = {
            'audit': b'fixture', 'master_raw': b'actual master',
            'asset': 'TEST', 'attempt_id': 'a' * 64
        }
        report = gate.inspect(self.inv, self.plan, **ctx)
        self.assertEqual(report['due_observed_mg0_failures'], [rid])
        self.plan['mode'] = 'OPERATIONAL'
        with self.assertRaisesRegex(gate.Blocked, 'C07_153_DUE_SEMANTIC_VALIDATORS_MISSING'):
            gate.require_operational_scope(self.inv, self.plan, **ctx)

    def test_future_rule_is_not_fake_pass(self):
        rid = self.inv['families']['META'][0]
        COVERAGE.expected_result = lambda row, *args: (
            'FUTURE_PHASE' if row['requirement'].endswith(rid) else 'PASS')
        self.addCleanup(setattr, COVERAGE, 'expected_result', lambda *args: 'PASS')
        report = gate.inspect(self.inv, self.plan)
        self.assertEqual(report['rules'][rid]['semantic_verdict'], 'NOT_DUE')
        self.assertEqual(report['rules'][rid]['individual_mg0'], 'NOT_DUE')
        self.assertEqual(report['future_or_not_applicable_rules'], 1)


if __name__ == '__main__':
    unittest.main()
