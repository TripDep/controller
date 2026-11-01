"""Adversarial tests for the *documentary-only* native replay allowlist.

Synthetic fixtures test the dispatch, not the truth of real asset or MG0 PASS.
Original private bytes are independently reopened in the two existing readers'
own tests; this suite cannot replace those tests or owner evidence.
"""
import copy
import json
import unittest
from unittest.mock import patch

import approved_validators as approved
import c07_native_replayer_dispatch as d
import supervisor_judgment as judgment


RID = 'AAA-200-B-012'
R173 = 'AAA-200-B-018'


def fixture(rid=RID):
    expected = {
        'work_item_sha256': 'a'*64,
        'attempt_id': 'b'*64,
        'operation_sha256': 'c'*64,
        'attempt_number': 1,
        'previous_attempt_id': None,
        'phase': 'P0',
        'family': 'AAA-200',
        'rule_id': rid,
        'master_sha256': 'd'*64,
        'source_sha256': 'e'*64,
        'requirement_sha256': 'f'*64,
        'work_dependencies': {'1'*64: '2'*64},
    }
    validator, criteria = approved.REVIEWED[rid]
    spec = {
        'validator_id': validator,
        'criteria': list(criteria),
        'requirement_sha256': expected['requirement_sha256'],
        'source_ref': '3'*40,
        'issuer': {'workflow_blob': '4'*40, 'public_sha': '5'*40},
    }
    packet = {
        'schema': 'gg-semantic-rule-v1',
        'scope': judgment.SEMANTIC_SCOPE,
        'validator_id': validator,
        'binding': copy.deepcopy(expected),
        'rule': {'result': 'PASS', 'checks': {k: True for k in criteria},
                 'proof_digest': '6'*64},
        'mg0': {'binding': copy.deepcopy(expected), 'triggered': None,
                'result': 'UNKNOWN',
                'checks': {'canonical_triggers_checked': False},
                'proof_digest': '7'*64},
    }
    return expected, spec, packet


def result(rid, status='PASS'):
    return {'rule_id': rid, 'documentary_result': status,
            'individual_rule_mg0': 'UNKNOWN',
            'advancement_authorized': False}


class Tests(unittest.TestCase):
    def test_explicit_whitelist_exactly_reviewed_native_implementations(self):
        self.assertEqual(set(d.REPLAYERS), set(approved.REVIEWED))
        self.assertEqual(len(d.REPLAYERS), 34)
        self.assertNotIn('AAA-200-B-010', d.REPLAYERS)

    def test_b012_dispatch_to_actual_source_replayer(self):
        expected, spec, packet = fixture()
        with patch('planning_semantics.native_rule_readback',
                   return_value=result(RID)) as source:
            observed = d.replay(object(), packet, expected, spec)
            self.assertEqual(observed['individual_rule_mg0'], 'UNKNOWN')
            source.assert_called_once()

    def test_r173_dispatch_to_different_source_replayer(self):
        expected, spec, packet = fixture(R173)
        with patch('r173_rule_semantics.native_rule_readback',
                   return_value=result(R173)) as source:
            self.assertEqual(d.replay(object(), packet, expected, spec),
                             result(R173))
            source.assert_called_once()

    def test_unknown_id_cannot_use_r173_as_generic_fallback(self):
        expected, spec, packet = fixture(R173)
        expected['rule_id'] = 'AAA-200-B-010'
        packet['binding']['rule_id'] = expected['rule_id']
        packet['mg0']['binding']['rule_id'] = expected['rule_id']
        with patch('r173_rule_semantics.native_rule_readback') as source:
            with self.assertRaisesRegex(d.SourceReplayBlocked, 'NOT_WHITELISTED'):
                d.replay(object(), packet, expected, spec)
            source.assert_not_called()

    def test_wrong_validator_and_criteria_rejected(self):
        for change in ({'validator_id': 'fake'},
                       {'criteria': []},
                       {'requirement_sha256': '0'*64},
                       {'source_ref': 'main'}):
            expected, spec, packet = fixture()
            spec.update(change)
            with self.subTest(change=change):
                with self.assertRaises(d.SourceReplayBlocked):
                    d.replay(object(), packet, expected, spec)

    def test_cross_attempt_operation_master_source_and_work_item(self):
        for key in ('attempt_id', 'operation_sha256', 'master_sha256',
                    'source_sha256', 'work_item_sha256'):
            expected, spec, packet = fixture()
            packet['binding'][key] = '0'*64
            with self.subTest(key=key):
                with self.assertRaisesRegex(d.SourceReplayBlocked,
                                            'CROSS_ATTEMPT_OR_OPERATION'):
                    d.replay(object(), packet, expected, spec)

    def test_mg0_binding_must_match_current_attempt(self):
        expected, spec, packet = fixture()
        packet['mg0']['binding']['operation_sha256'] = '0'*64
        with self.assertRaisesRegex(d.SourceReplayBlocked,
                                    'CROSS_ATTEMPT_OR_OPERATION'):
            d.replay(object(), packet, expected, spec)

    def test_malformed_expected_sha_and_dependencies(self):
        for key in ('attempt_id', 'operation_sha256', 'source_sha256',
                    'requirement_sha256'):
            expected, spec, packet = fixture()
            expected[key] = 'not-a-digest'
            if key == 'requirement_sha256':
                spec['requirement_sha256'] = expected[key]
            with self.subTest(key=key):
                with self.assertRaisesRegex(d.SourceReplayBlocked,
                                            'ATTEMPT_OPERATION_SOURCE_SHA'):
                    d.replay(object(), packet, expected, spec)
        expected, spec, packet = fixture()
        expected['work_dependencies'] = {'not-sha': '2'*64}
        with self.assertRaisesRegex(d.SourceReplayBlocked,
                                    'ATTEMPT_OPERATION_SOURCE_SHA'):
            d.replay(object(), packet, expected, spec)

    def test_previous_attempt_requires_valid_distinct_hash(self):
        for previous in (None, 'b'*64, 'main', '0'*40):
            expected, spec, packet = fixture()
            expected['attempt_number'] = 2
            expected['previous_attempt_id'] = previous
            with self.subTest(previous=previous):
                with self.assertRaisesRegex(d.SourceReplayBlocked,
                                            'ATTEMPT_OPERATION_SOURCE_SHA'):
                    d.replay(object(), packet, expected, spec)

    def test_replayer_must_not_return_owner_or_mg0_pass(self):
        for value in (
            dict(result(RID), individual_rule_mg0='PASS'),
            dict(result(RID), advancement_authorized=True),
            dict(result(RID), asset_advancement_authorized=True),
            dict(result(RID), rule_id=R173),
            dict(result(RID), documentary_result='UNKNOWN'),
        ):
            expected, spec, packet = fixture()
            with self.subTest(value=value):
                with patch('planning_semantics.native_rule_readback',
                           return_value=value):
                    with self.assertRaisesRegex(d.SourceReplayBlocked,
                                                'SCOPED_RESULT_CANNOT_AUTHORIZE'):
                        d.replay(object(), packet, expected, spec)

    def test_signed_packet_cannot_claim_mg0_pass(self):
        expected, spec, packet = fixture()
        packet['mg0']['result'] = 'PASS'
        with patch('planning_semantics.native_rule_readback',
                   return_value=result(RID)):
            with self.assertRaisesRegex(d.SourceReplayBlocked,
                                        'SCOPED_RESULT_CANNOT_AUTHORIZE'):
                d.replay(object(), packet, expected, spec)

    def test_documentary_result_mismatch_rejected(self):
        expected, spec, packet = fixture()
        with patch('planning_semantics.native_rule_readback',
                   return_value=result(RID, 'FAIL')):
            with self.assertRaisesRegex(d.SourceReplayBlocked,
                                        'SCOPED_RESULT_CANNOT_AUTHORIZE'):
                d.replay(object(), packet, expected, spec)

    def test_native_backend_uses_whitelisted_source_then_remains_unknown(self):
        expected, spec, packet = fixture(R173)
        origin = {'run_id': 1, 'job_id': 2, 'run_attempt': 1,
                  'head_sha': '8'*40}
        offer = {'native_origin': origin,
                 'expected_packet_sha256': judgment.digest(packet)}
        signed = '2026-11-01T05:00:00Z ' + judgment.PREFIX + json.dumps(packet)
        backend = judgment.NativeRuleBackend(object(), {R173: spec})
        with patch.object(judgment.evidence, 'native', return_value=signed), \
             patch('r173_rule_semantics.native_rule_readback',
                   return_value=result(R173)) as source:
            observed = backend.rule(R173, expected, offer)
            self.assertEqual(observed['result'], 'UNKNOWN')
            self.assertEqual(observed['mg0'], 'UNKNOWN')
            source.assert_called_once()

    def test_native_backend_cross_operation_replay_denied(self):
        expected, spec, packet = fixture(R173)
        origin = {'run_id': 1, 'job_id': 2, 'run_attempt': 1,
                  'head_sha': '8'*40}
        offer = {'native_origin': origin,
                 'expected_packet_sha256': judgment.digest(packet)}
        signed = '2026-11-01T05:00:00Z ' + judgment.PREFIX + json.dumps(packet)
        backend = judgment.NativeRuleBackend(object(), {R173: spec})
        wrong = copy.deepcopy(expected)
        wrong['operation_sha256'] = '9'*64
        with patch.object(judgment.evidence, 'native', return_value=signed), \
             patch('r173_rule_semantics.native_rule_readback') as source:
            observed = backend.rule(R173, wrong, offer)
            self.assertEqual(observed['result'], 'UNKNOWN')
            source.assert_not_called()


if __name__ == '__main__':
    unittest.main()
