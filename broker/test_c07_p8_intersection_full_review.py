"""S183 original component separation, duplicate and ambiguous-overlap tests."""
import copy
import unittest

from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p678_forty_native_domain import P678Forty,encode
from test_c07_native_output_oracle import two_triangles
from c07_p8_intersection_full_review import RULE,inspect
from c07_native_source_rule_replayers import (
    NATIVE_RULES,FULL_LITERAL_REVIEWED,VALIDATORS,build_packet,
    native_rule_readback,NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding,semantic_packet

POSE={'translation_xyz':[0,0,0],'yaw_deg':0,'scale_xyz':[1,1,1]}
OTHER={'translation_xyz':[3,0,0],'yaw_deg':0,'scale_xyz':[1,1,1]}
POLICY={'component_roles':['NATIVE_EXPORT','SECONDARY_EXPORT'],
        'min_clearance_m':0.1,
        'max_pairwise_triangle_tests':100000,
        'unintended_overlap_forbidden':True,
        'allowed_contact_pairs':[]}

class IntersectionFullReviewTests(unittest.TestCase):
    def context(self):
        test,ctx=NativeOriginalReplayerTests.context(
            self,P678Forty,'test_phase_P6_10_rules_due_P7_20_P8_40')
        test.f.plan['phase']=test.f.work['phase']='P8'
        test.add('SECONDARY_EXPORT','secondary.glb',two_triangles())
        test.add('P8_INTERSECTION_POLICY','p8_intersection_policy.json',
                 encode(POLICY))
        test.add('P8_COMPONENT_PLACEMENTS','p8_component_placements.json',
                 encode({'placements':{'NATIVE_EXPORT':POSE,
                                       'SECONDARY_EXPORT':OTHER}}))
        test.sync()
        ctx['controller']=test.f.controller
        return test,ctx

    def packet(self,ctx):
        expected=binding(ctx['work'],ctx['inventory']['rules'][RULE],RULE)
        packet=build_packet(ctx,RULE,expected=expected)
        spec={'validator_id':VALIDATORS[RULE],
              'criteria':list(NATIVE_RULES[RULE][1]),
              'requirement_sha256':expected['requirement_sha256'],
              'source_ref':'1'*40,
              'issuer':{'workflow_blob':'a'*40,'public_sha':'b'*40}}
        return packet,expected,spec

    def test_actual_source_triangle_separation_positive_unknown_mg0(self):
        _,ctx=self.context()
        packet,expected,spec=self.packet(ctx)
        self.assertIn(RULE,FULL_LITERAL_REVIEWED)
        self.assertEqual(packet['rule']['result'],'PASS')
        self.assertTrue(all(packet['rule']['checks'].values()))
        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
        self.assertEqual(replay(None,packet,expected,spec,
            source_context=lambda _:ctx)['documentary_result'],'PASS')
        self.assertEqual(semantic_packet(packet,expected,spec)['result'],
                         'UNKNOWN')

    def test_exact_original_duplicate_triangles_are_negative(self):
        test,ctx=self.context()
        test.add('P8_COMPONENT_PLACEMENTS','p8_component_placements.json',
                 encode({'placements':{'NATIVE_EXPORT':POSE,
                                       'SECONDARY_EXPORT':POSE}}))
        test.sync()
        ctx['controller']=test.f.controller
        packet,_,_=self.packet(ctx)
        self.assertEqual(packet['rule']['result'],'FAIL')
        self.assertFalse(packet['rule']['checks'][NATIVE_RULES[RULE][1][2]])

    def test_ambiguous_aabb_overlap_remains_unknown_not_fake_collision(self):
        test,ctx=self.context()
        near={'translation_xyz':[0.5,0,0],'yaw_deg':0,'scale_xyz':[1,1,1]}
        test.add('P8_COMPONENT_PLACEMENTS','p8_component_placements.json',
                 encode({'placements':{'NATIVE_EXPORT':POSE,
                                       'SECONDARY_EXPORT':near}}))
        test.sync()
        ctx['controller']=test.f.controller
        packet,_,_=self.packet(ctx)
        self.assertEqual(packet['rule']['result'],'UNKNOWN')

    def test_pairwise_budget_prevents_unbounded_geometry_work(self):
        test,ctx=self.context()
        test.add('P8_INTERSECTION_POLICY','p8_intersection_policy.json',
                 encode(dict(POLICY,max_pairwise_triangle_tests=1)))
        test.sync()
        ctx['controller']=test.f.controller
        packet,_,_=self.packet(ctx)
        self.assertEqual(packet['rule']['result'],'UNKNOWN')

    def test_missing_original_source_pin_and_forgery_fail_closed(self):
        test,ctx=self.context()
        packet,expected,spec=self.packet(ctx)
        forged=copy.deepcopy(packet)
        forged['rule']['proof_digest']='f'*64
        with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                    'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None,forged,expected,spec,
                                 source_context=lambda _:ctx)
        test.f.plan['p678_evidence_contract']['original_artifact_sha256'].pop(
            'SECONDARY_EXPORT')
        test.f.rebuild()
        ctx['controller']=test.f.controller
        packet,_,_=self.packet(ctx)
        self.assertNotEqual(packet['rule']['result'],'PASS')

if __name__=='__main__':
    unittest.main()
