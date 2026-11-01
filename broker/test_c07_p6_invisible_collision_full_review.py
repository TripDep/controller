"""P-156: original collision-vs-visible triangle geometry adversarial tests."""
import copy
import unittest

import supervisor_judgment as judgment
from c07_native_source_rule_replayers import (
    NATIVE_RULES, VALIDATORS, build_packet, native_rule_readback)
from c07_native_replayer_dispatch import replay
from c07_p678_forty_native_domain import TEXT
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p6_collision_semantics import Tests as CollisionFixture, POLICY
from test_c07_p3_geometry_semantics import glb
from test_c07_positive_native_process import sha

RID='AAA-200-P-156'

class InvisibleCollisionFullReviewTests(unittest.TestCase):
    def context(self):
        test,ctx=NativeOriginalReplayerTests.context(
            self,CollisionFixture,
            'test_four_real_collision_oracles_not_fivem_or_mg0')
        requirement,phase=TEXT['156']
        test.f.inv['rules'][RID]={
            'family':'AAA-200','catalog_number':156,
            'catalog_section':'P','catalog_phase':phase,
            'requirement':requirement,
            'requirement_sha256':sha(requirement.encode()),
            'source_sha256':'c'*64}
        policy=dict(POLICY,max_invisible_collision_distance_m=0.02,
                    invisible_collision_exemptions=[])
        test.put(policy=policy)
        ctx['controller']=test.f.controller
        return test,ctx,policy

    def spec(self,ctx):
        expected=judgment.binding(ctx['work'],ctx['inventory']['rules'][RID],RID)
        return expected,{'validator_id':VALIDATORS[RID],
            'criteria':list(NATIVE_RULES[RID][1]),
            'requirement_sha256':expected['requirement_sha256'],
            'source_ref':'1'*40}

    def test_original_visible_collision_all_faces_match_and_replay(self):
        _,ctx,_=self.context()
        packet=build_packet(ctx,RID)
        self.assertEqual(packet['rule']['result'],'PASS')
        self.assertTrue(all(packet['rule']['checks'].values()))
        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
        expected,spec=self.spec(ctx)
        observed=replay(None,packet,expected,spec,
                        source_context=lambda _:ctx)
        self.assertEqual(observed['documentary_result'],'PASS')
        self.assertFalse(observed['advancement_authorized'])
        forged=copy.deepcopy(packet)
        forged['rule']['checks'][NATIVE_RULES[RID][1][2]]=False
        with self.assertRaisesRegex(ValueError,'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None,forged,expected,spec,
                                 source_context=lambda _:ctx)

    def test_real_collision_offset_from_visual_is_negative(self):
        test,ctx,policy=self.context()
        lifted=glb([(0,0,0.3),(1,0,0.3),(0,1,0.3)],
                   [(0,1,2)],[(0,0,1)]*3)
        test.put(policy=policy,collision=lifted)
        ctx['controller']=test.f.controller
        packet=build_packet(ctx,RID)
        self.assertEqual(packet['rule']['result'],'FAIL')
        self.assertFalse(packet['rule']['checks'][NATIVE_RULES[RID][1][2]])

    def test_real_perpendicular_collision_normal_is_negative(self):
        test,ctx,policy=self.context()
        wall=glb([(0,0,0),(1,0,0),(0,0,1)],
                 [(0,1,2)],[(0,-1,0)]*3)
        test.put(policy=policy,collision=wall)
        ctx['controller']=test.f.controller
        packet=build_packet(ctx,RID)
        self.assertEqual(packet['rule']['result'],'FAIL')
        self.assertFalse(packet['rule']['checks'][NATIVE_RULES[RID][1][1]])

    def test_absent_original_pre_d_collision_pin_is_unknown(self):
        test,ctx,_=self.context()
        test.f.plan['p678_evidence_contract']['original_artifact_sha256'].pop(
            'COLLISION_EXPORT')
        test.f.rebuild()
        ctx['controller']=test.f.controller
        self.assertEqual(build_packet(ctx,RID)['rule']['result'],'UNKNOWN')

    def test_original_collision_tamper_and_cross_attempt_blocked(self):
        test,ctx,_=self.context()
        (test.f.root/'collision.glb').write_bytes(b'forged')
        with self.assertRaises(ValueError):
            build_packet(ctx,RID)
        _,ctx,_=self.context()
        ctx['work']['attempt_id']='f'*64
        with self.assertRaises(ValueError):
            build_packet(ctx,RID)

    def test_unbounded_pre_d_tolerance_cannot_authorize(self):
        test,ctx,policy=self.context()
        policy['max_invisible_collision_distance_m']=10.0
        test.put(policy=policy)
        ctx['controller']=test.f.controller
        self.assertEqual(build_packet(ctx,RID)['rule']['result'],'FAIL')


if __name__=='__main__':
    unittest.main()
