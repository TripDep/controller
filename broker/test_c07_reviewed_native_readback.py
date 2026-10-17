"""Fail-closed native proof consumption across 12 approved documentary rules.

CI fixtures prove routing and rejection, not 3D asset quality or MG0 PASS.
"""
import copy
import json
import unittest
from unittest.mock import patch

import approved_validators as approved
import supervisor_judgment as j
from test_rule_evidence import API


class ReviewedNativeReadbackTests(unittest.TestCase):
    def attempt(self, rid, *, result='PASS'):
        validator, criteria = approved.REVIEWED[rid]
        binding = {
            'work_item_sha256':'a'*64,'attempt_id':'b'*64,
            'operation_sha256':'e'*64,'attempt_number':1,'previous_attempt_id':None,
            'phase':'P0','family':'AAA-200','rule_id':rid,
            'master_sha256':'f'*64,'source_sha256':'c'*64,
            'requirement_sha256':'d'*64,'work_dependencies':{'a'*64:'b'*64}
        }
        packet = {
            'schema':'gg-semantic-rule-v1','scope':j.SEMANTIC_SCOPE,
            'validator_id':validator,'binding':binding,
            'rule':{'result':result,'checks':{key:True for key in criteria},
                    'proof_digest':'1'*64},
            'mg0':{'binding':copy.deepcopy(binding),'triggered':None,
                   'result':'UNKNOWN','checks':{'canonical_triggers_checked':False},
                   'proof_digest':'2'*64},
        }
        spec = {'validator_id':validator,'criteria':list(criteria),
                'requirement_sha256':binding['requirement_sha256'],
                'source_ref':'0'*40,
                'issuer':{'workflow_blob':'a'*40,'public_sha':'b'*40}}
        offer = {'native_origin':{'run_id':1},'expected_packet_sha256':j.digest(packet)}
        log = '2026-10-16T00:00:00Z '+j.PREFIX+json.dumps(packet)
        return binding, packet, spec, offer, log

    def test_each_approved_validator_requires_independent_readback(self):
        self.assertEqual(len(approved.REVIEWED),12)
        self.assertIn('AAA-200-B-013',approved.REVIEWED)
        self.assertIn('AAA-200-B-019',approved.REVIEWED)
        for rid in approved.REVIEWED:
            with self.subTest(rule=rid):
                binding, packet, spec, offer, log = self.attempt(rid)
                reader = ('planning_semantics.native_rule_readback'
                          if rid == 'AAA-200-B-012'
                          else 'r173_rule_semantics.native_rule_readback')
                with patch.object(j.evidence,'native',return_value=log), patch(
                        reader, side_effect=ValueError('INDEPENDENT_SOURCE_BYTES_MISMATCH')) as native:
                    answer = j.NativeRuleBackend(API(),{rid:spec}).rule(rid,binding,offer)
                    native.assert_called_once()
                    self.assertEqual(answer['result'],'UNKNOWN')
                    self.assertIn('INDEPENDENT_SOURCE_BYTES_MISMATCH',answer['reason'])

    def test_replayed_friendly_pass_cannot_replace_real_native_check(self):
        for rid in approved.REVIEWED:
            with self.subTest(rule=rid):
                binding, packet, spec, offer, log = self.attempt(rid)
                reader = ('planning_semantics.native_rule_readback'
                          if rid == 'AAA-200-B-012'
                          else 'r173_rule_semantics.native_rule_readback')
                with patch.object(j.evidence,'native',return_value=log), patch(
                        reader, return_value={'documentary_result':'PASS',
                                              'individual_rule_mg0':'UNKNOWN'}) as native:
                    answer = j.NativeRuleBackend(API(),{rid:spec}).rule(rid,binding,offer)
                    native.assert_called_once()
                    self.assertEqual(answer['result'],'UNKNOWN')
                    self.assertEqual(answer['mg0'],'UNKNOWN')

    def test_validator_id_swap_is_never_accepted(self):
        rid = 'AAA-200-B-012'
        binding, packet, spec, offer, log = self.attempt(rid)
        spec['validator_id']=approved.R173_VALIDATOR
        with patch.object(j.evidence,'native',return_value=log):
            result = j.NativeRuleBackend(API(),{rid:spec}).rule(rid,binding,offer)
        self.assertEqual(result['result'],'UNKNOWN')
        self.assertIn('REVIEWED_NATIVE_ENROLLMENT_REPLAY_REJECTED',result['reason'])

    def test_source_pin_required_at_plan_enrollment(self):
        rid = 'AAA-200-B-012'
        binding, packet, spec, offer, log = self.attempt(rid)
        with self.assertRaisesRegex(approved.InvalidEnrollment,
                                    'VALIDATOR_PLANNING_EVIDENCE_IMMUTABLE_REF'):
            approved.validate({rid:{k:v for k,v in spec.items()
                                    if k != 'source_ref'}},
                              {'rules':{rid:{'requirement_sha256':
                                              binding['requirement_sha256']}}})
        self.assertEqual(approved.validate(
             {rid:spec},{'rules':{rid:{'requirement_sha256':
                                      binding['requirement_sha256']}}})['reviewed_enrolled_count'],1)


if __name__=='__main__':
    unittest.main()
