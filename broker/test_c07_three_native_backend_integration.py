"""Real consuming-side NativeRuleBackend integration for three new literal rules."""
import copy
import json
import unittest
from unittest.mock import patch

import supervisor_judgment as judgment
from c07_native_source_rule_replayers import NATIVE_RULES, VALIDATORS, build_packet
from test_c07_p1_spatial_full_review import P1SpatialNativeTests
from test_c07_p5_full_review import P5FullNativeReviewTests

class ThreeNewBackendTests(unittest.TestCase):
    def test_three_original_byte_replayers_are_not_producer_self_certifications(self):
        p1 = P1SpatialNativeTests.context(self)[1]
        p5 = P5FullNativeReviewTests.context(self)[1]
        for rid, ctx in (
            ('AAA-200-E-043', p1),
            ('AAA-200-O-144', p5),
            ('AAA-200-O-146', p5),
        ):
            with self.subTest(rule=rid):
                packet = build_packet(ctx, rid)
                self.assertEqual(packet['rule']['result'], 'PASS')
                expected = judgment.binding(
                    ctx['work'], ctx['inventory']['rules'][rid], rid)
                spec = {'validator_id': VALIDATORS[rid],
                        'criteria': list(NATIVE_RULES[rid][1]),
                        'requirement_sha256': expected['requirement_sha256'],
                        'source_ref': '1'*40}
                origin = {'run_id':41,'job_id':42,'run_attempt':1,
                          'head_sha':'8'*40}
                def run(candidate):
                    signed = ('2026-11-01T07:00:00Z ' + judgment.PREFIX +
                              json.dumps(candidate, separators=(',', ':')))
                    backend = judgment.NativeRuleBackend(
                        object(), {rid:spec}, source_context=lambda _:ctx)
                    offer = {'native_origin':origin,
                             'expected_packet_sha256':judgment.digest(candidate)}
                    with patch.object(judgment.evidence, 'native', return_value=signed):
                        return backend.rule(rid, expected, offer)
                real = run(packet)
                self.assertEqual(real['result'], 'UNKNOWN')
                self.assertEqual(real['mg0'], 'UNKNOWN')
                forged = copy.deepcopy(packet)
                forged['rule']['proof_digest'] = 'f'*64
                answer = run(forged)
                self.assertEqual(answer['result'], 'UNKNOWN')
                self.assertIn('PRODUCER_PACKET_NOT_RECOMPUTED',
                              answer['reason'])

if __name__ == '__main__':
    unittest.main()
