"""Negative-first synthetic tests for the C07 110-rule error prevention gate.

Passing these tests never certifies that the assistant avoided any real error.
"""
import hashlib
import sys
import types
import unittest
from unittest.mock import patch

import c07_behavior_110 as gate


def sha(v):
    return hashlib.sha256(v).hexdigest()


def sample():
    raw = '# REGISTRO\n'
    headings = []
    clauses = []
    for group, marker, start, end in gate.SECTIONS:
        headings.append(f'## {group}. {marker} ({start:03}–{end:03})')
        for n in range(start, end + 1):
            clauses.append(f'{n:03}. Errore: synthetic error {n:03} → '
                           f'synthetic prevention {n:03}')
    raw += '\n'.join(headings + clauses) + '\n'
    reg = raw.encode()
    md = sha(b'master')
    ids = [f'BEHAVIOR-{i:03}' for i in range(1, 111)]
    req = [line.split('. ', 1)[1] for line in clauses]
    items = {
        rid: {
            'family': gate.FAMILY, 'source': gate.SOURCE,
            'source_path': gate.CANONICAL_PATH,
            'source_sha256': sha(reg),
            'requirement': text,
            'requirement_sha256': sha(text.encode()),
            'required_mg0': True,
        }
        for rid, text in zip(ids, req)
    }
    inv = {
        'schema': 'gg-effective-family-inventory-v1',
        'canonical_master_sha256': md,
        'families': {gate.FAMILY: ids, 'OTHER': [f'TEST-{n}' for n in range(653)]},
        'rules': items,
        'source_digests': {gate.SOURCE: sha(reg)},
        'rule_count': 763, 'family_count': 20,
    }
    plan = {
        'master_sha256': md, 'phase': 'P0', 'asset_type': 'terrain',
        'profiles': ['TERRAIN_PATH_PROFILE'],
        'mode': 'DIAGNOSTIC_ONLY', 'enrolled': {},
    }
    return inv, plan, reg


COVERAGE = types.ModuleType('family_coverage')
COVERAGE.expected_result = lambda *args: 'PASS'
APPROVED = types.ModuleType('approved_validators')
APPROVED.REVIEWED = {}
INTAKE = types.ModuleType('real_work_intake')
INTAKE.audit_check = lambda raw, asset: (
    [{'event': 'QUALITY_FINDING', 'rule_id': 'BEHAVIOR-055',
      'attempt_id': 'a' * 64, 'result': 'FAIL', 'record_hash': 'c' * 64,
      'asset': asset}], 'd' * 64)
MG0 = types.ModuleType('c07_mg0_individual')
MG0.inspect = lambda *args: {'individual_rule_mg0': 'UNKNOWN'}


class Tests(unittest.TestCase):
    def setUp(self):
        self.inv, self.plan, self.raw = sample()
        patcher = patch.dict(sys.modules, {
            'family_coverage': COVERAGE,
            'approved_validators': APPROVED,
            'real_work_intake': INTAKE,
            'c07_mg0_individual': MG0,
        })
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_exact_110_source_bound_error_prevention_entries(self):
        r = gate.inspect(self.inv, self.plan, registry_raw=self.raw)
        self.assertEqual(r['individual_error_rules'], 110)
        self.assertEqual(len(r['groups']), 11)
        self.assertEqual(r['source_integrity_passes'], 110)
        self.assertEqual(len(r['entries']), 110)
        self.assertEqual(len(r['missing_due_semantic_implementations']), 110)
        self.assertEqual(r['independently_verified_prevention_passes'], 0)
        self.assertEqual(r['individual_mg0_passes'], 0)
        self.assertFalse(r['advancement_authorized'])

    def test_operational_without_semantic_implementations_blocks(self):
        self.plan['mode'] = 'OPERATIONAL'
        with self.assertRaisesRegex(
                gate.BehaviorBlocked, 'C07_110_UNVERIFIED_DUE_PREVENTION_RULES:110'):
            gate.require_operational_scope(self.inv, self.plan, registry_raw=self.raw)

    def test_omission_of_error_id_blocked(self):
        self.inv['families'][gate.FAMILY].pop()
        with self.assertRaisesRegex(gate.BehaviorBlocked, 'C07_110_EXACT_CANONICAL_MEMBERSHIP'):
            gate.inspect(self.inv, self.plan, registry_raw=self.raw)

    def test_duplicate_error_id_blocked(self):
        self.inv['families'][gate.FAMILY][0] = 'BEHAVIOR-002'
        with self.assertRaisesRegex(gate.BehaviorBlocked, 'C07_110_EXACT_CANONICAL_MEMBERSHIP'):
            gate.inspect(self.inv, self.plan, registry_raw=self.raw)

    def test_tampered_prevention_blocked(self):
        self.inv['rules']['BEHAVIOR-042']['requirement'] += ' fake'
        with self.assertRaisesRegex(gate.BehaviorBlocked, 'C07_110_INDIVIDUAL_SOURCE_OR_PREVENTION_DRIFT'):
            gate.inspect(self.inv, self.plan, registry_raw=self.raw)

    def test_missing_prevention_clause_blocked(self):
        self.inv['rules']['BEHAVIOR-075']['requirement'] = 'Errore: no prevention'
        with self.assertRaisesRegex(gate.BehaviorBlocked, 'C07_110_INDIVIDUAL_SOURCE_OR_PREVENTION_DRIFT'):
            gate.inspect(self.inv, self.plan, registry_raw=self.raw)

    def test_registry_byte_tampering_blocked(self):
        with self.assertRaisesRegex(gate.BehaviorBlocked, 'C07_110_REGISTRY_DIGEST_DRIFT'):
            gate.inspect(self.inv, self.plan, registry_raw=self.raw + b'changed')

    def test_master_mismatch_blocked(self):
        self.plan['master_sha256'] = '0' * 64
        with self.assertRaisesRegex(gate.BehaviorBlocked, 'C07_110_TRUSTED_PLAN_AND_MASTER'):
            gate.inspect(self.inv, self.plan, registry_raw=self.raw)

    def test_partial_audit_context_blocked(self):
        with self.assertRaisesRegex(gate.BehaviorBlocked, 'C07_110_INCOMPLETE_TRUSTED_ATTEMPT'):
            gate.inspect(self.inv, self.plan, registry_raw=self.raw, audit_raw=b'broken')

    def test_synthetic_regression_detected_but_not_false_pass(self):
        r = gate.inspect(self.inv, self.plan, registry_raw=self.raw,
                         master_raw=b'master', audit_raw=b'audit',
                         asset='TEST', attempt_id='a'*64)
        self.assertEqual(r['recurrence_observed_rule_ids'], ['BEHAVIOR-055'])
        self.assertEqual(r['entries']['BEHAVIOR-055']['recurrence_record_hashes'], ['c'*64])
        self.assertFalse(r['entries']['BEHAVIOR-055']['prevention_verified'])
        self.assertEqual(r['independently_verified_prevention_passes'], 0)

    def test_legacy_attempt_is_not_replayed_as_current(self):
        r = gate.inspect(self.inv, self.plan, registry_raw=self.raw,
                         master_raw=b'master', audit_raw=b'audit',
                         asset='TEST', attempt_id='b'*64)
        self.assertEqual(r['recurrence_observed_rule_ids'], [])
        self.assertEqual(r['independently_verified_prevention_passes'], 0)

    def test_no_observed_regressions_does_not_prove_prevention(self):
        r = gate.inspect(self.inv, self.plan, registry_raw=self.raw)
        self.assertFalse(r['recurrence_observed_rule_ids'])
        self.assertTrue(all(x['semantic_result']=='UNKNOWN'
                            for x in r['entries'].values()))

    def test_future_rule_not_due_never_pass(self):
        previous = COVERAGE.expected_result
        COVERAGE.expected_result = lambda row, *args: (
            'FUTURE_PHASE' if row.get('requirement', '').startswith(
                'Errore: synthetic error 001') else 'PASS')
        self.addCleanup(setattr, COVERAGE, 'expected_result', previous)
        r = gate.inspect(self.inv, self.plan, registry_raw=self.raw)
        self.assertEqual(r['entries']['BEHAVIOR-001']['semantic_result'], 'NOT_DUE')
        self.assertEqual(r['future_or_not_applicable'], 1)
        self.assertEqual(r['independently_verified_prevention_passes'], 0)

    def test_reviewed_verifier_requires_explicit_plan_enrollment(self):
        previous = APPROVED.REVIEWED
        APPROVED.REVIEWED = {'BEHAVIOR-001': ('predicate', ('check',))}
        self.addCleanup(setattr, APPROVED, 'REVIEWED', previous)
        r = gate.inspect(self.inv, self.plan, registry_raw=self.raw)
        self.assertIn('BEHAVIOR-001', r['missing_due_semantic_implementations'])
        self.plan['enrolled']['BEHAVIOR-001'] = {'validator_id': 'predicate'}
        r = gate.inspect(self.inv, self.plan, registry_raw=self.raw)
        self.assertNotIn('BEHAVIOR-001', r['missing_due_semantic_implementations'])
        self.assertEqual(r['entries']['BEHAVIOR-001']['semantic_result'], 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
