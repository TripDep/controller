"""C07 R126: a native Git receipt is never native rule implementation approval.

These are synthetic adversarial backend checks. They do not certify any asset,
MG0, owner decision or work PASS.
"""
import hashlib
import unittest
from unittest.mock import Mock
import approved_validators as reviewed
import supervisor_judgment as judgment


def sha(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


class NativeReviewEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.api=Mock()
        self.rid='AAA-200-A-008'
        self.requirement='Riconoscere la differenza tra un fatto verificato e una supposizione.'
        self.expected={'rule_id':self.rid,'requirement_sha256':sha(self.requirement)}
        self.good={
            'validator_id':reviewed.R173_VALIDATOR,
            'criteria':list(reviewed.R173_CRITERIA[self.rid]),
            'requirement_sha256':self.expected['requirement_sha256'],
            'issuer':{'workflow_blob':'a'*40,'public_sha':'b'*40},
            'source_ref':'c'*40
        }
        self.fake_offer={'native_origin':{'run_id':1111},
                         'expected_packet_sha256':'d'*64}

    def verify_unknown(self,rid,spec,expected=None,offer=None,reason=None):
        got=judgment.NativeRuleBackend(self.api,{rid:spec}).rule(
            rid,expected if expected is not None else
            {'rule_id':rid,'requirement_sha256':spec['requirement_sha256']},
            offer if offer is not None else self.fake_offer)
        self.assertEqual(got['result'],'UNKNOWN')
        if reason is not None:self.assertEqual(got['reason'],reason)
        self.assertEqual(self.api.mock_calls, [])
        return got

    def test_forged_unreviewed_validator_cannot_be_pass(self):
        custom={**self.good,'validator_id':'FRAUDULENT_FULL_RULE_AUDITOR'}
        self.verify_unknown('EXEC-003',custom,reason=
            'NO_REVIEWED_SOURCE_SPECIFIC_NATIVE_IMPLEMENTATION')

    def test_pretending_to_be_real_reviewed_validator_on_other_id_blocked(self):
        self.verify_unknown('BEHAVIOR-001',self.good,reason=
            'NO_REVIEWED_SOURCE_SPECIFIC_NATIVE_IMPLEMENTATION')

    def test_forged_second_200_producer_passes_never_reach_native_api(self):
        for n in range(1,111):
            self.verify_unknown('BEHAVIOR-'+str(n).zfill(3),self.good,
                reason='NO_REVIEWED_SOURCE_SPECIFIC_NATIVE_IMPLEMENTATION')

    def test_known_reviewed_id_missing_issuer_rejected(self):
        spec={**self.good,'issuer':{}}
        self.verify_unknown(self.rid,spec,self.expected,
            reason='REVIEWED_NATIVE_ENROLLMENT_REPLAY_REJECTED')

    def test_known_reviewed_id_missing_immutable_source_ref_rejected(self):
        spec={**self.good,'source_ref':'main'}
        self.verify_unknown(self.rid,spec,self.expected,
            reason='REVIEWED_NATIVE_ENROLLMENT_REPLAY_REJECTED')

    def test_known_reviewed_id_wrong_criteria_rejected(self):
        spec={**self.good,'criteria':self.good['criteria'][:1]}
        self.verify_unknown(self.rid,spec,self.expected,
            reason='REVIEWED_NATIVE_ENROLLMENT_REPLAY_REJECTED')

    def test_known_reviewed_id_wrong_validator_id_rejected(self):
        spec={**self.good,'validator_id':'WRONG_REPLAY'}
        self.verify_unknown(self.rid,spec,self.expected,
            reason='REVIEWED_NATIVE_ENROLLMENT_REPLAY_REJECTED')

    def test_known_reviewed_id_wrong_requirement_sha_rejected(self):
        spec={**self.good,'requirement_sha256':'f'*64}
        self.verify_unknown(self.rid,spec,self.expected,
            reason='REVIEWED_NATIVE_ENROLLMENT_REPLAY_REJECTED')

    def test_known_reviewed_id_attempt_binding_mismatch_rejected(self):
        expected={**self.expected,'rule_id':'ANOTHER'}
        self.verify_unknown(self.rid,self.good,expected,
            reason='NATIVE_RULE_ENROLLMENT_OR_BINDING_INVALID')

    def test_known_reviewed_id_without_native_log_proof_is_unknown(self):
        got=judgment.NativeRuleBackend(self.api,{self.rid:self.good}).rule(
            self.rid,self.expected,{})
        self.assertEqual(got['result'],'UNKNOWN')
        self.assertEqual(got['reason'],'NATIVE_RULE_PROOF_MISSING')
        self.assertEqual(self.api.mock_calls, [])

    def test_unreviewed_missing_offer_remains_unknown(self):
        got=judgment.NativeRuleBackend(self.api,{
            'EXEC-003':{**self.good,'validator_id':'CUSTOM'}}).rule(
            'EXEC-003',{'rule_id':'EXEC-003',
                        'requirement_sha256':self.expected['requirement_sha256']},
            None)
        self.assertEqual(got['result'],'UNKNOWN')
        self.assertEqual(self.api.mock_calls, [])


if __name__=='__main__':unittest.main()
