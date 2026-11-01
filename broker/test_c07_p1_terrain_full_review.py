"""Adversarial source-byte P1 terrain and swept player corridor tests."""
import copy
import json
import unittest
from test_c07_p1_thirty_native_domain import P1Thirty, encode
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_native_output_oracle import two_triangles
from c07_p1_terrain_full_review import RULES, inspect
from c07_native_source_rule_replayers import (
    NATIVE_RULES, FULL_LITERAL_REVIEWED, VALIDATORS, build_packet,
    native_rule_readback, NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding, semantic_packet

POSE = {'translation_xyz':[0,0,0], 'yaw_deg':0, 'scale_xyz':[1,1,1]}
OTHER = {'translation_xyz':[3,0,0], 'yaw_deg':0, 'scale_xyz':[1,1,1]}

class TerrainFullReviewTests(unittest.TestCase):
    def context(self):
        test, ctx = NativeOriginalReplayerTests.context(
            self, P1Thirty, 'test_exact_30_individual_P1_and_90_unique_predicates')
        flat = bytearray(two_triangles())
        flat[-4:] = bytes(4)
        test.put('NATIVE_EXPORT', 'scene.glb', bytes(flat))
        test.put('P1_TERRAIN_EXPORT', 'terrain.glb', bytes(flat))
        placement = {'placements':{'NATIVE_EXPORT':POSE,
                                    'SECONDARY_EXPORT':OTHER}}
        test.put('P1_WORLD_PLACEMENTS', 'p1_placements.json', encode(placement))
        paths = {'features':[{'id':'path-1','class':'walkable',
            'geometry':{'type':'LineString',
                        'coordinates':[[0,0],[0.4,0.4]]}}]}
        test.put('P1_PATHS_GEOJSON', 'paths.json', encode(paths))
        scene = json.loads(test.contents['P1_SCENE_CONTRACT'][1])
        scene.update(
            terrain_scope='single_planar_support_triangle',
            terrain_reference_z_m=0,
            terrain_support_contact_tolerance_m=0.01,
            terrain_min_support_vertices=3,
            expected_world_placements=placement['placements'],
            existing_asset_roles=['SECONDARY_EXPORT'],
            walkable_path_ids=['path-1'])
        test.put('P1_SCENE_CONTRACT', 'p1_scene.json', encode(scene))
        test.rebuild()
        ctx['controller'] = test.f.controller
        return test, ctx

    def packet(self, ctx, rid):
        expected = binding(ctx['work'], ctx['inventory']['rules'][rid], rid)
        packet = build_packet(ctx, rid, expected=expected)
        spec = {'validator_id':VALIDATORS[rid],
                'criteria':list(NATIVE_RULES[rid][1]),
                'requirement_sha256':expected['requirement_sha256'],
                'source_ref':'1'*40,
                'issuer':{'workflow_blob':'a'*40,'public_sha':'b'*40}}
        return packet, expected, spec

    def test_both_full_source_replayers_positive_without_mg0_pass(self):
        for rid in RULES:
            with self.subTest(rule=rid):
                _, ctx = self.context()
                packet, expected, spec = self.packet(ctx, rid)
                self.assertIn(rid, FULL_LITERAL_REVIEWED)
                self.assertEqual(packet['rule']['result'], 'PASS')
                self.assertTrue(all(packet['rule']['checks'].values()))
                self.assertEqual(packet['mg0']['result'], 'UNKNOWN')
                self.assertEqual(replay(None, packet, expected, spec,
                    source_context=lambda _:ctx)['documentary_result'], 'PASS')
                self.assertEqual(semantic_packet(packet, expected, spec)['result'],
                                 'UNKNOWN')

    def test_terrain_original_floating_native_vertices_fail(self):
        test, ctx = self.context()
        import struct
        elevated = bytearray(two_triangles())
        for index in (2, 5, 8, 11, 14, 17):
            struct.pack_into('<f', elevated, len(elevated)-72+4*index, 0.2)
        test.put('NATIVE_EXPORT', 'scene.glb', bytes(elevated))
        test.rebuild()
        ctx['controller'] = test.f.controller
        packet, _, _ = self.packet(ctx, 'AAA-200-E-048')
        self.assertEqual(packet['rule']['result'], 'FAIL')
        self.assertFalse(packet['rule']['checks'][
            'all_original_native_vertices_above_ground_and_measured_contacts_within_tolerance'])

    def test_original_blocking_native_geometry_intersects_player_corridor(self):
        test, ctx = self.context()
        test.put('NATIVE_EXPORT', 'scene.glb', two_triangles())
        test.rebuild()
        ctx['controller'] = test.f.controller
        packet, _, _ = self.packet(ctx, 'AAA-200-F-055')
        self.assertEqual(packet['rule']['result'], 'FAIL')
        self.assertFalse(packet['rule']['checks'][
            'all_measured_player_swept_corridors_clear_of_original_blocking_triangles'])

    def test_missing_terrain_sha_pin_never_positive(self):
        test, ctx = self.context()
        test.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop(
            'P1_TERRAIN_EXPORT')
        test.f.rebuild()
        ctx['controller'] = test.f.controller
        for rid in RULES:
            with self.subTest(rule=rid):
                packet, _, _ = self.packet(ctx, rid)
                self.assertNotEqual(packet['rule']['result'], 'PASS')

    def test_path_omission_cannot_pass_with_correct_geometry(self):
        test, ctx = self.context()
        test.put('P1_PATHS_GEOJSON', 'paths.json',
                 encode({'features':[]}))
        test.rebuild()
        ctx['controller'] = test.f.controller
        packet, _, _ = self.packet(ctx, 'AAA-200-F-055')
        self.assertNotEqual(packet['rule']['result'], 'PASS')

    def test_original_tamper_and_packet_forgery_fail_closed(self):
        test, ctx = self.context()
        packet, expected, spec = self.packet(ctx, 'AAA-200-E-048')
        forged = copy.deepcopy(packet)
        forged['rule']['proof_digest'] = 'f'*64
        with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                    'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None, forged, expected, spec,
                                 source_context=lambda _:ctx)
        (test.f.root / 'terrain.glb').write_bytes(b'forged')
        with self.assertRaises(ValueError):
            inspect(ctx, 'AAA-200-E-048')

if __name__ == '__main__':
    unittest.main()
