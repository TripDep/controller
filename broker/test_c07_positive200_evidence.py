"""R122 independent negative/attack tests. SYNTHETIC_FIXTURES, not asset QA."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

import c07_positive200_evidence as p


def h(raw):
    return hashlib.sha256(raw).hexdigest()


class FakeController:
    def __init__(self, master):
        self.master = type('M', (), {'read_bytes': lambda _self: master})()
        self._raw = b'original-controller-audit-jsonl'
        self._state = {'last_audit_hash': 'b' * 64,
                       'active_step': {'step': 'STEP0100'}}

    def audit_path(self, asset):
        assert asset == 'GARDEN'
        return type('A', (), {'read_bytes': lambda _self: self._raw})()

    def asset_state(self, asset):
        assert asset == 'GARDEN'
        return self._state


class R122PositiveBatchTest(unittest.TestCase):
    def setUp(self):
        self.master = b'canonical-test-master'
        self.work = {'master_sha256': h(self.master), 'attempt_id': 'c' * 64,
                     'operation_sha256': 'd' * 64}
        self.plan = {'master_sha256': h(self.master), 'operation': {}}
        self.ids = ['AAA-200-%s-%03d' % (chr(65 + (i - 1) // 10), i)
                    for i in range(1, 201)]
        extra = ['ZZ_FAKE_%03d' % i for i in range(563)]
        self.inv = {'schema': 'gg-effective-family-inventory-v1',
                    'rule_count': 763, 'canonical_master_sha256': h(self.master),
                    'rules': {}}
        for rid in self.ids + extra:
            requirement = 'Rule content for ' + rid
            self.inv['rules'][rid] = {'requirement': requirement,
               'requirement_sha256': h(requirement.encode()),
               'source_sha256': 'a' * 64,
               'family': 'AAA-200' if rid.startswith('AAA') else 'GOVERNANCE'}
        self.c = FakeController(self.master)
        self.reserved = {'event': 'SUPERVISOR_OPERATION_RESERVED',
                         'record_hash': 'reserve', 'work': copy.deepcopy(self.work),
                         'plan_record_hash': 'plan'}
        self.opened = {'event': 'SUPERVISOR_OPERATION_OPENED',
                       'step': 'STEP0100', 'reservation_hash': 'reserve'}
        self.enrolled = {'event': 'SUPERVISOR_PLAN_ENROLLED',
                         'record_hash': 'plan', 'plan': copy.deepcopy(self.plan)}
        self.records = [self.enrolled, self.reserved, self.opened]
        self.scoped = {'master_sha256': self.work['master_sha256'],
                       'due': list(self.ids),
                       'by_rule': {rid: {'family': 'AAA-200',
                           'source_sha256': 'a'*64,
                           'requirement_sha256': self.inv['rules'][rid]['requirement_sha256']}
                           for rid in self.ids}}
        self.process = {'complete_work_rule_passes': 0,
                        'individual_mg0_passes': 0,
                        'advancement_authorized': False,
                        'results': {rid: {'scoped_positive_observation':
                                         'OBSERVED_SCOPE_PASS'}
                                    for rid in self.ids[:13]}}
        self.process['results'].update({self.ids[13]:
            {'scoped_positive_observation': 'UNKNOWN_OR_SCOPE_FAIL'}})
        # Exactly R120's 13 registered predicates, incl one unobserved.
        self.process['results'] = dict(list(self.process['results'].items())[:13])
        self.patchers = [
            patch.object(p, 'operation_scope', side_effect=lambda inv, plan: self.scoped),
            patch.object(p, 'composite_inspect', side_effect=lambda inv, ids:
                         {'due_composites': {}}),
            patch.object(p, 'process_inspect', side_effect=lambda *args, **kw: self.process),
            patch.object(p, 'audit_check', side_effect=lambda raw, asset:
                         (self.records, 'b'*64)),
            patch.object(p, 'REVIEWED', {}),
        ]
        for x in self.patchers:
            x.start()
            self.addCleanup(x.stop)

    def run_engine(self):
        return p.inspect(self.inv, self.plan, self.c, 'GARDEN', 'STEP0100',
                         self.work, source_loader=lambda path: b'bytes')

    def assert_blocked(self, token):
        with self.assertRaisesRegex(p.PositiveBatchBlocked, token):
            self.run_engine()

    def test_all_200_original_rule_ids_unknown_not_pass(self):
        output = self.run_engine()
        self.assertEqual(output['source_rule_count'], 200)
        self.assertEqual(output['unknown_count'], 200)
        self.assertEqual(output['full_native_positive_verified_new'], 0)
        self.assertEqual(output['individual_mg0_passes'], 0)
        self.assertFalse(output['advancement_authorized'])
        self.assertEqual(output['r120_scoped_machine_positive_in_target'], 13)
        self.assertEqual(set(output['rules']), set(self.ids))
        self.assertTrue(all(row['full_semantics'] == 'UNKNOWN'
                            and not row['work_pass'] for row in output['rules'].values()))
        self.assertEqual(output['report_sha256'], p.digest(
            {k: v for k, v in output.items() if k != 'report_sha256'}))

    def test_requirement_byte_change_is_not_a_positive(self):
        self.inv['rules'][self.ids[12]]['requirement'] = 'surreptitious rewrite'
        self.assert_blocked('R122_REQUIREMENT_SOURCE_DRIFT')

    def test_wrong_source_sha_rejected(self):
        self.inv['rules'][self.ids[0]]['source_sha256'] = 'not-a-sha'
        self.assert_blocked('R122_REQUIREMENT_SOURCE_DRIFT')

    def test_changed_actual_master_rejected(self):
        self.c.master = type('M', (), {'read_bytes': lambda _: b'tampered master'})()
        self.assert_blocked('R122_ORIGINAL_MASTER_CHANGED')

    def test_missing_controller_audit_tail_rejected(self):
        self.c._state['last_audit_hash'] = '0'*64
        self.assert_blocked('R122_AUDIT_STATE_CHANGED')

    def test_replayed_other_attempt_rejected(self):
        self.reserved['work']['attempt_id'] = 'f'*64
        self.assert_blocked('R122_CROSS_ATTEMPT_OR_OPERATION_REPLAY')

    def test_replayed_other_operation_rejected(self):
        self.reserved['work']['operation_sha256'] = 'e'*64
        self.assert_blocked('R122_CROSS_ATTEMPT_OR_OPERATION_REPLAY')

    def test_forged_enrolled_plan_rejected(self):
        self.enrolled['plan']['operation'] = {'category': 'UNAUTHORIZED'}
        self.assert_blocked('R122_NONCANONICAL_ENROLLED_PLAN')

    def test_duplicate_opens_rejected(self):
        self.records.append(copy.deepcopy(self.opened))
        self.assert_blocked('R122_ONE_OPEN_OPERATION_REQUIRED')

    def test_duplicate_reservations_rejected(self):
        self.records.append(copy.deepcopy(self.reserved))
        self.assert_blocked('R122_CROSS_ATTEMPT_OR_OPERATION_REPLAY')

    def test_active_step_changed_rejected(self):
        self.c._state['active_step']['step'] = 'STEP9999'
        self.assert_blocked('R122_ACTIVE_OPERATION_CHANGED')

    def test_scope_source_sha_mismatch_rejected(self):
        self.scoped['by_rule'][self.ids[0]]['source_sha256'] = 'e'*64
        self.assert_blocked('R122_RULE_SCOPE_PROVENANCE_CHANGED')

    def test_r120_cannot_elevate_positive_pass(self):
        self.process['complete_work_rule_passes'] = 1
        self.assert_blocked('R122_PROCESS_OBSERVATION_PRIVILEGE_ESCALATION')

    def test_r120_cannot_forge_mg0(self):
        self.process['individual_mg0_passes'] = 1
        self.assert_blocked('R122_PROCESS_OBSERVATION_PRIVILEGE_ESCALATION')

    def test_r120_cannot_authorize(self):
        self.process['advancement_authorized'] = True
        self.assert_blocked('R122_PROCESS_OBSERVATION_PRIVILEGE_ESCALATION')

    def test_duplicate_composite_clause_rejected(self):
        clause = {'subcheck_id': self.ids[0] + ':SC001',
                  'canonical_clause': 'test clause',
                  'clause_sha256': h(b'test clause'),
                  'provenance_requirement_sha256':
                      self.inv['rules'][self.ids[0]]['requirement_sha256']}
        with patch.object(p, 'composite_inspect', return_value={'due_composites':
              {self.ids[0]: {'subchecks': [clause, clause],
                             'source_decomposition': 'UNREVIEWED'}}}):
            self.assert_blocked('R122_DUPLICATE_CANONICAL_CLAUSE')

    def test_forged_clause_sha_rejected(self):
        clause = {'subcheck_id': self.ids[0] + ':SC001',
                  'canonical_clause': 'test clause',
                  'clause_sha256': 'f'*64,
                  'provenance_requirement_sha256':
                      self.inv['rules'][self.ids[0]]['requirement_sha256']}
        with patch.object(p, 'composite_inspect', return_value={'due_composites':
              {self.ids[0]: {'subchecks': [clause],
                             'source_decomposition': 'UNREVIEWED'}}}):
            self.assert_blocked('R122_CHANGED_COMPOSITE_CLAUSE')

    def test_unreviewed_composite_needs_decomposition_and_mg0(self):
        clause = {'subcheck_id': self.ids[0] + ':SC001',
                  'canonical_clause': 'test clause',
                  'clause_sha256': h(b'test clause'),
                  'provenance_requirement_sha256':
                      self.inv['rules'][self.ids[0]]['requirement_sha256']}
        with patch.object(p, 'composite_inspect', return_value={'due_composites':
              {self.ids[0]: {'subchecks': [clause],
                             'source_decomposition': 'SOURCE_LIST_CANDIDATES_REVIEW_PENDING'}}}):
            r = self.run_engine()['rules'][self.ids[0]]
        self.assertEqual(r['canonical_clause_count'], 1)
        self.assertIn('INDEPENDENT_REVIEW_OF_EXHAUSTIVE_COMPOSITE_DECOMPOSITION',
                      r['missing_evidence'])
        self.assertEqual(r['individual_mg0'], 'UNKNOWN')

    def test_producer_yes_cannot_satisfy_any_rule(self):
        r = self.run_engine()
        self.assertEqual(r['full_semantic_passes_on_current_attempt'], 0)
        self.assertTrue(all('REAL_INDEPENDENT_CLAUSE_PROOFS_ON_SAME_ATTEMPT'
                            in row['missing_evidence'] for row in r['rules'].values()))

    def test_110_regression_registry_numbered_source(self):
        source = '\n'.join(f'{n:03d}. test error {n}' for n in range(1, 111))
        obj = {'requirement': source, 'requirement_sha256': h(source.encode())}
        clauses, completeness = p._source_clauses('110_ERROR_REGISTRY', obj, None)
        self.assertEqual(len(clauses), 110)
        self.assertEqual(clauses[-1]['subcheck_id'], '110_ERROR_REGISTRY:SC110')
        self.assertIn('NOT_YET_REVIEWED', completeness)
        obj['requirement'] = source.replace('055.', '054.')
        with self.assertRaisesRegex(p.PositiveBatchBlocked, 'REGRESSION_110'):
            p._source_clauses('110_ERROR_REGISTRY', obj, None)


if __name__ == '__main__':
    unittest.main()