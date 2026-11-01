"""Adversarial original-byte P-154 access geometry replay; never a FiveM PASS."""
import copy
import unittest
from pathlib import Path

import supervisor_judgment as judgment
from c07_native_source_rule_replayers import NATIVE_RULES, VALIDATORS, build_packet, native_rule_readback
from c07_native_replayer_dispatch import replay
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p6_collision_semantics import Tests as CollisionFixture, POLICY
from test_c07_p3_geometry_semantics import glb

RID = 'AAA-200-P-154'
POINTS = [
    (-2,-2,0),(-1,-2,0),(-2,-1,0),
    (2,0,0),(2.5,0,0),(2,1,0),
    (2.5,0,0.2),(3,0,0.2),(2.5,1,0.2),
    (2,1.2,0),(3,1.2,0),(3,1.2,1.2),
]
FACES = [(0,1,2),(3,4,5),(6,7,8),(9,10,11)]
MODEL = glb(POINTS,FACES)
ACCESS = dict(POLICY, openings=[
    {'name':'door_a','kind':'door','min_xyz':[5,0,0],'max_xyz':[6,0.7,2]},
    {'name':'passage_a','kind':'passage','min_xyz':[7,0,0],'max_xyz':[8,0.7,2]},
    {'name':'stair_a','kind':'stair','min_xyz':[1.9,-0.1,-0.1],
     'max_xyz':[3.1,1.1,0.4]},
    {'name':'rail_a','kind':'railing','min_xyz':[1.9,1.15,-0.1],
     'max_xyz':[3.1,1.25,1.3]},
], player_clear_width_m=0.6, player_clear_height_m=1.8,
    max_stair_riser_m=0.25, min_rail_height_m=0.9,
    max_stair_rail_gap_m=0.6)

class P154FullReviewTests(unittest.TestCase):
    def context(self):
        fixture, ctx = NativeOriginalReplayerTests.context(
            self, CollisionFixture,
            'test_four_real_collision_oracles_not_fivem_or_mg0')
        self.put(fixture, ctx)
        return fixture, ctx

    def put(self, fixture, ctx, policy=None, collision=None):
        fixture.put(policy=ACCESS if policy is None else policy,
                    collision=MODEL if collision is None else collision,
                    visual=MODEL)
        ctx['controller'] = fixture.f.controller

    def test_all_four_original_access_classes_positive_and_replayed(self):
        _, ctx = self.context()
        packet = build_packet(ctx, RID)
        self.assertEqual(packet['rule']['result'], 'PASS')
        self.assertTrue(all(packet['rule']['checks'].values()))
        self.assertEqual(packet['mg0']['result'], 'UNKNOWN')
        expected = judgment.binding(ctx['work'],ctx['inventory']['rules'][RID],RID)
        spec = {'validator_id':VALIDATORS[RID],
                'criteria':list(NATIVE_RULES[RID][1]),
                'requirement_sha256':expected['requirement_sha256'],
                'source_ref':'1'*40}
        result = replay(None,packet,expected,spec,source_context=lambda _:ctx)
        self.assertEqual(result['documentary_result'],'PASS')
        self.assertFalse(result['advancement_authorized'])
        forged = copy.deepcopy(packet)
        forged['rule']['checks'][NATIVE_RULES[RID][1][2]] = False
        with self.assertRaisesRegex(ValueError,'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None,forged,expected,spec,
                                 source_context=lambda _:ctx)

    def test_actual_door_collision_and_missing_stair_tread_fail(self):
        fixture,ctx = self.context()
        bad = copy.deepcopy(ACCESS)
        bad['openings'][0]['min_xyz'] = [2,0,-0.1]
        bad['openings'][0]['max_xyz'] = [3,1,2]
        self.put(fixture,ctx,policy=bad)
        self.assertEqual(build_packet(ctx,RID)['rule']['result'],'FAIL')
        fixture,ctx = self.context()
        self.put(fixture,ctx,collision=glb(POINTS,[(0,1,2),(3,4,5),(9,10,11)]))
        self.assertEqual(build_packet(ctx,RID)['rule']['result'],'FAIL')

    def test_missing_rail_and_wrong_riser_fail(self):
        fixture,ctx = self.context()
        self.put(fixture,ctx,collision=glb(POINTS,[(0,1,2),(3,4,5),(6,7,8)]))
        self.assertEqual(build_packet(ctx,RID)['rule']['result'],'FAIL')
        fixture,ctx = self.context()
        bad = dict(ACCESS,max_stair_riser_m=0.1)
        self.put(fixture,ctx,policy=bad)
        self.assertEqual(build_packet(ctx,RID)['rule']['result'],'FAIL')

    def test_missing_original_pre_d_pin_unknown(self):
        fixture,ctx = self.context()
        fixture.f.plan['p678_evidence_contract']['original_artifact_sha256'].pop(
            'COLLISION_EXPORT')
        fixture.f.rebuild()
        ctx['controller']=fixture.f.controller
        self.assertEqual(build_packet(ctx,RID)['rule']['result'],'UNKNOWN')

    def test_original_tamper_cross_attempt_and_forged_policy(self):
        fixture,ctx = self.context()
        (fixture.f.root/'collision.glb').write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            build_packet(ctx,RID)
        _,ctx = self.context()
        ctx['work']['attempt_id']='f'*64
        with self.assertRaises(ValueError):
            build_packet(ctx,RID)
        fixture,ctx = self.context()
        bad = copy.deepcopy(ACCESS)
        bad['openings'].append(copy.deepcopy(bad['openings'][0]))
        self.put(fixture,ctx,policy=bad)
        self.assertEqual(build_packet(ctx,RID)['rule']['result'],'FAIL')

if __name__=='__main__':
    unittest.main()
