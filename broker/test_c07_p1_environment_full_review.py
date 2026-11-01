"""Adversarial original-byte tests for E049/E050/F053 complete P1 predicates."""
import copy
import json
import unittest
from pathlib import Path

from test_c07_p1_thirty_native_domain import P1Thirty, encode
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from c07_native_source_rule_replayers import (
    NATIVE_RULES, FULL_LITERAL_REVIEWED, VALIDATORS, build_packet,
    native_rule_readback, NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from c07_p1_environment_full_review import inspect, RULES
from supervisor_judgment import binding, semantic_packet

POSE = {'translation_xyz': [0, 0, 0], 'yaw_deg': 0,
        'scale_xyz': [1, 1, 1]}
OTHER = {'translation_xyz': [3, 0, 0], 'yaw_deg': 0,
         'scale_xyz': [1, 1, 1]}

class EnvironmentFullReviewTests(unittest.TestCase):
    def context(self):
        test, ctx = NativeOriginalReplayerTests.context(
            self, P1Thirty, 'test_exact_30_individual_P1_and_90_unique_predicates')
        placements = {'placements': {'NATIVE_EXPORT': POSE,
                                     'SECONDARY_EXPORT': OTHER}}
        native = test.contents['NATIVE_EXPORT'][1]
        scene = json.loads(test.contents['P1_SCENE_CONTRACT'][1])
        scene.update(
            expected_world_placements=placements['placements'],
            existing_asset_roles=['SECONDARY_EXPORT'],
            existing_asset_clearance_m=1.0,
            locked_scope='entire_asset',
            locked_native_export_sha256=__import__('hashlib').sha256(native).hexdigest(),
            orientation_anchor_local=[[0, 0, 0], [1, 0, 0]],
            expected_forward_world=[1, 0, 0],
            expected_up_world=[0, 0, 1])
        test.put('P1_SCENE_CONTRACT', 'p1_scene.json', encode(scene))
        test.put('P1_WORLD_PLACEMENTS', 'p1_placements.json', encode(placements))
        test.put('BASELINE_WORLD_PLACEMENTS', 'baseline_placements.json', encode(placements))
        test.rebuild()
        ctx['controller'] = test.f.controller
        return test, ctx

    def packet(self, ctx, rid):
        expected = binding(ctx['work'], ctx['inventory']['rules'][rid], rid)
        packet = build_packet(ctx, rid, expected=expected)
        spec = {'validator_id': VALIDATORS[rid],
                'criteria': list(NATIVE_RULES[rid][1]),
                'requirement_sha256': expected['requirement_sha256'],
                'source_ref': '1' * 40,
                'issuer': {'workflow_blob': 'a' * 40, 'public_sha': 'b' * 40}}
        return packet, expected, spec

    def test_three_original_source_specific_positive_and_independent_readback(self):
        for rid in sorted(RULES):
            with self.subTest(rid=rid):
                _, ctx = self.context()
                packet, expected, spec = self.packet(ctx, rid)
                self.assertIn(rid, FULL_LITERAL_REVIEWED)
                self.assertEqual(packet['rule']['result'], 'PASS')
                self.assertEqual(packet['mg0']['result'], 'UNKNOWN')
                self.assertTrue(all(packet['rule']['checks'].values()))
                self.assertEqual(replay(None, packet, expected, spec,
                    source_context=lambda _: ctx)['documentary_result'], 'PASS')
                self.assertEqual(semantic_packet(packet, expected, spec)['result'],
                                 'UNKNOWN')

    def test_overlap_rejects_actual_existing_asset_intersection(self):
        test, ctx = self.context()
        test.put('P1_WORLD_PLACEMENTS', 'p1_placements.json',
                 encode({'placements': {'NATIVE_EXPORT': POSE,
                                        'SECONDARY_EXPORT': POSE}}))
        test.rebuild()
        ctx['controller'] = test.f.controller
        packet, _, _ = self.packet(ctx, 'AAA-200-E-049')
        self.assertEqual(packet['rule']['result'], 'FAIL')
        self.assertFalse(packet['rule']['checks'][
            'original_native_and_every_existing_asset_world_bounds_independently_recomputed'])

    def test_lock_rejects_modified_original_native_even_with_rebound_plan(self):
        test, ctx = self.context()
        from test_c07_native_output_oracle import two_triangles
        native = bytearray(two_triangles())
        native[-4:] = b'\\x00\\x00\\x00\\x00'
        test.put('NATIVE_EXPORT', 'scene.glb', bytes(native))
        test.rebuild()
        ctx['controller'] = test.f.controller
        packet, _, _ = self.packet(ctx, 'AAA-200-E-050')
        self.assertEqual(packet['rule']['result'], 'FAIL')
        self.assertFalse(packet['rule']['checks'][
            'current_native_and_baseline_original_export_bytes_identical'])

    def test_lock_rejects_world_placement_movement_even_if_mesh_unchanged(self):
        test, ctx = self.context()
        test.put('P1_WORLD_PLACEMENTS', 'p1_placements.json',
                 encode({'placements': {'NATIVE_EXPORT': OTHER,
                                        'SECONDARY_EXPORT': POSE}}))
        test.rebuild()
        ctx['controller'] = test.f.controller
        packet, _, _ = self.packet(ctx, 'AAA-200-E-050')
        self.assertEqual(packet['rule']['result'], 'FAIL')
        self.assertFalse(packet['rule']['checks'][
            'current_and_baseline_original_world_placements_identical'])

    def test_orientation_rejects_reverse_forward_vector(self):
        test, ctx = self.context()
        scene = json.loads(test.contents['P1_SCENE_CONTRACT'][1])
        scene['expected_forward_world'] = [-1, 0, 0]
        test.put('P1_SCENE_CONTRACT', 'p1_scene.json', encode(scene))
        test.rebuild()
        ctx['controller'] = test.f.controller
        packet, _, _ = self.packet(ctx, 'AAA-200-F-053')
        self.assertEqual(packet['rule']['result'], 'FAIL')
        self.assertFalse(packet['rule']['checks'][
            'measured_native_world_forward_and_up_match_source_target'])

    def test_unpinned_world_placement_cannot_be_full_positive(self):
        test, ctx = self.context()
        test.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop(
            'P1_WORLD_PLACEMENTS')
        test.f.rebuild()
        ctx['controller'] = test.f.controller
        for rid in RULES:
            with self.subTest(rid=rid):
                packet, _, _ = self.packet(ctx, rid)
                self.assertNotEqual(packet['rule']['result'], 'PASS')

    def test_current_attempt_mismatch_and_producer_forgery_fail_closed(self):
        _, ctx = self.context()
        packet, expected, spec = self.packet(ctx, 'AAA-200-E-049')
        forged = copy.deepcopy(packet)
        forged['rule']['proof_digest'] = 'f' * 64
        with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                    'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None, forged, expected, spec,
                                 source_context=lambda _: ctx)
        wrong = dict(expected, attempt_id='f' * 64)
        with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                    'ATTEMPT_OPERATION_SOURCE_MISMATCH'):
            native_rule_readback(None, packet, wrong, spec,
                                 source_context=lambda _: ctx)

    def test_modified_original_bytes_without_audit_rebinding_are_rejected(self):
        test, ctx = self.context()
        path = test.f.root / 'p1_placements.json'
        path.write_bytes(b'{"placements":{}}')
        with self.assertRaises(ValueError):
            inspect(ctx, 'AAA-200-E-049')

if __name__ == '__main__':
    unittest.main()
