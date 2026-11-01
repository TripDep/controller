"""Original-source E-043 measured clearance and dimensions; no MG0 PASS."""
import copy
import json
import unittest

from c07_native_source_rule_replayers import build_packet, native_rule_readback
from c07_native_replayer_dispatch import replay
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p1_thirty_native_domain import P1Thirty, encode
import supervisor_judgment as judgment

RID = 'AAA-200-E-043'

class P1SpatialNativeTests(unittest.TestCase):
    def context(self):
        test, ctx = NativeOriginalReplayerTests.context(
            self, P1Thirty, 'test_exact_30_individual_P1_and_90_unique_predicates')
        scene = json.loads(test.contents['P1_SCENE_CONTRACT'][1])
        scene.update(
            building_world_placements={
                'primary': {'translation_xyz':[0,0,0], 'yaw_deg':0,
                            'scale_xyz':[1,1,1]},
                'secondary': {'translation_xyz':[5,0,0], 'yaw_deg':0,
                              'scale_xyz':[1,1,1]}},
            building_footprint_area_ratio_range=[0.9,1.1],
            building_height_ratio_range=[0.9,1.1])
        test.put('P1_SCENE_CONTRACT', 'p1_scene.json', encode(scene))
        test.rebuild()
        ctx['controller'] = test.f.controller
        return test, ctx, scene

    def test_positive_native_world_distance_and_independent_readback(self):
        _, ctx, _ = self.context()
        packet = build_packet(ctx, RID)
        self.assertEqual(packet['rule']['result'], 'PASS')
        self.assertEqual(packet['mg0']['result'], 'UNKNOWN')
        expected = judgment.binding(ctx['work'], ctx['inventory']['rules'][RID], RID)
        from c07_native_source_rule_replayers import NATIVE_RULES, VALIDATORS
        spec = {'validator_id': VALIDATORS[RID],
                'criteria': list(NATIVE_RULES[RID][1]),
                'requirement_sha256': expected['requirement_sha256'],
                'source_ref':'1'*40}
        self.assertEqual(replay(None, packet, expected, spec,
                                source_context=lambda _:ctx)[
                                    'documentary_result'], 'PASS')
        forged = copy.deepcopy(packet)
        forged['rule']['checks'][NATIVE_RULES[RID][1][2]] = False
        with self.assertRaisesRegex(ValueError, 'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None, forged, expected, spec,
                                 source_context=lambda _:ctx)

    def test_real_building_overlap_fails(self):
        test, ctx, scene = self.context()
        scene['building_world_placements']['secondary']['translation_xyz'] = [0.2,0,0]
        test.put('P1_SCENE_CONTRACT', 'p1_scene.json', encode(scene))
        test.rebuild()
        ctx['controller'] = test.f.controller
        self.assertEqual(build_packet(ctx, RID)['rule']['result'], 'FAIL')

    def test_wrong_dimension_ratio_fails(self):
        test, ctx, scene = self.context()
        scene['building_world_placements']['secondary']['scale_xyz'] = [2,2,2]
        test.put('P1_SCENE_CONTRACT', 'p1_scene.json', encode(scene))
        test.rebuild()
        ctx['controller'] = test.f.controller
        self.assertEqual(build_packet(ctx, RID)['rule']['result'], 'FAIL')

    def test_missing_pre_d_secondary_sha_is_unknown(self):
        test, ctx, _ = self.context()
        test.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop(
            'SECONDARY_EXPORT')
        test.f.rebuild()
        ctx['controller'] = test.f.controller
        self.assertEqual(build_packet(ctx, RID)['rule']['result'], 'UNKNOWN')

    def test_tampered_registered_glb_and_cross_attempt_fail_closed(self):
        test, ctx, _ = self.context()
        (test.f.root/'other.glb').write_bytes(b'forged')
        with self.assertRaises(ValueError):
            build_packet(ctx, RID)
        _, ctx, _ = self.context()
        ctx['work']['attempt_id'] = 'f'*64
        with self.assertRaises(ValueError):
            build_packet(ctx, RID)


    def alignment_context(self):
        test, ctx, scene = P1SpatialNativeTests.context(self)
        scene['building_world_placements']['secondary']['translation_xyz'] = [1,0,0]
        scene['module_alignment_pairs'] = [{
            'primary_vertex_xyz':[1,0,0],
            'secondary_vertex_xyz':[0,0,0],
            'max_gap_m':0.01}]
        test.put('P1_SCENE_CONTRACT', 'p1_scene.json', encode(scene))
        test.rebuild()
        ctx['controller'] = test.f.controller
        return test, ctx, scene

    def test_f054_original_glb_alignment_positive_and_mg0_unknown(self):
        _, ctx, _ = self.alignment_context()
        packet = build_packet(ctx, 'AAA-200-F-054')
        self.assertEqual(packet['rule']['result'], 'PASS')
        self.assertEqual(packet['mg0']['result'], 'UNKNOWN')
        rid = 'AAA-200-F-054'
        expected = judgment.binding(ctx['work'], ctx['inventory']['rules'][rid], rid)
        from c07_native_source_rule_replayers import NATIVE_RULES, VALIDATORS
        spec = {'validator_id': VALIDATORS[rid],
                'criteria': list(NATIVE_RULES[rid][1]),
                'requirement_sha256': expected['requirement_sha256'],
                'source_ref': '1'*40}
        self.assertEqual(replay(None, packet, expected, spec,
                                source_context=lambda _:ctx)['documentary_result'],
                         'PASS')

    def test_f054_real_gap_and_forged_anchor_are_not_accepted(self):
        test, ctx, scene = self.alignment_context()
        scene['building_world_placements']['secondary']['translation_xyz'] = [1.4,0,0]
        test.put('P1_SCENE_CONTRACT', 'p1_scene.json', encode(scene))
        test.rebuild()
        ctx['controller'] = test.f.controller
        self.assertEqual(build_packet(ctx, 'AAA-200-F-054')['rule']['result'],
                         'FAIL')
        scene['building_world_placements']['secondary']['translation_xyz'] = [1,0,0]
        scene['module_alignment_pairs'][0]['secondary_vertex_xyz'] = [0.25,0,0]
        test.put('P1_SCENE_CONTRACT', 'p1_scene.json', encode(scene))
        test.rebuild()
        ctx['controller'] = test.f.controller
        self.assertEqual(build_packet(ctx, 'AAA-200-F-054')['rule']['result'],
                         'FAIL')

    def test_f054_missing_original_source_pin_unknown(self):
        test, ctx, _ = self.alignment_context()
        test.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop(
            'NATIVE_EXPORT')
        test.f.rebuild()
        ctx['controller'] = test.f.controller
        self.assertEqual(build_packet(ctx, 'AAA-200-F-054')['rule']['result'],
                         'UNKNOWN')

if __name__ == '__main__':
    unittest.main()
