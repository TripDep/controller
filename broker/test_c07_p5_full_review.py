"""Independent positive/negative original-byte tests for O-144 and O-146."""
import copy
import json
import struct
import unittest

from c07_native_source_rule_replayers import build_packet, native_rule_readback
from c07_native_replayer_dispatch import replay
from c07_p5_full_review import inspect as inspect_p5
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p5_budget_semantics import Tests as BudgetFixture, BUDGET
import supervisor_judgment as judgment

PROFILES = {
    'hero': {'min_far_m': 100, 'max_lod_triangle_ratio': 0.6},
    'primary': {'min_far_m': 60, 'max_lod_triangle_ratio': 0.6},
    'secondary': {'min_far_m': 30, 'max_lod_triangle_ratio': 0.6},
    'background': {'min_far_m': 10, 'max_lod_triangle_ratio': 0.6},
}

def two_material_bindings(raw):
    jsz = struct.unpack_from('<I', raw, 12)[0]
    doc = json.loads(raw[20:20+jsz])
    binary = raw[28+jsz:]
    doc['materials'].append(copy.deepcopy(doc['materials'][0]))
    primitive = copy.deepcopy(doc['meshes'][0]['primitives'][0])
    primitive['material'] = 1
    doc['meshes'][0]['primitives'].append(primitive)
    encoded = json.dumps(doc, separators=(',', ':')).encode()
    encoded += b' ' * (-len(encoded) % 4)
    return (struct.pack('<4sII', b'glTF', 2, 28+len(encoded)+len(binary))
            + struct.pack('<I4s', len(encoded), b'JSON') + encoded
            + struct.pack('<I4s', len(binary), b'BIN\\x00') + binary)

class P5FullNativeReviewTests(unittest.TestCase):
    def context(self):
        fixture, ctx = NativeOriginalReplayerTests.context(
            self, BudgetFixture,
            'test_five_original_quantitative_oracles_no_mg0')
        policy = dict(BUDGET, asset_importance='hero',
                      importance_lod_profiles=copy.deepcopy(PROFILES),
                      min_material_binding_reduction_pct=40)
        baseline = two_material_bindings(fixture.native)
        policy['material_cost_baseline_sha256'] = __import__('hashlib').sha256(
            baseline).hexdigest()
        fixture.put(budget=policy)
        fixture.f.add_item('BASELINE_SNAPSHOT', 'baseline.glb', baseline)
        fixture.f.plan['p345_evidence_contract']['original_artifact_sha256'][
            'BASELINE_SNAPSHOT'] = fixture.f.items['BASELINE_SNAPSHOT']['sha256']
        fixture.f.rebuild()
        ctx['controller'] = fixture.f.controller
        return fixture, ctx, policy, baseline

    def test_two_distinct_native_full_reviews_with_original_readback(self):
        _, ctx, _, _ = self.context()
        for rid in ('AAA-200-O-144', 'AAA-200-O-146'):
            with self.subTest(rule=rid):
                packet = build_packet(ctx, rid)
                self.assertEqual(packet['rule']['result'], 'PASS')
                self.assertEqual(packet['mg0']['result'], 'UNKNOWN')
                self.assertEqual(len(packet['rule']['checks']), 3)
                expected = judgment.binding(
                    ctx['work'], ctx['inventory']['rules'][rid], rid)
                from c07_native_source_rule_replayers import NATIVE_RULES, VALIDATORS
                spec = {'validator_id': VALIDATORS[rid],
                        'criteria': list(NATIVE_RULES[rid][1]),
                        'requirement_sha256': expected['requirement_sha256'],
                        'source_ref': '1'*40}
                self.assertEqual(replay(None, packet, expected, spec,
                                        source_context=lambda _: ctx)[
                                            'documentary_result'], 'PASS')
                forged = copy.deepcopy(packet)
                forged['rule']['proof_digest'] = 'f'*64
                with self.assertRaisesRegex(ValueError, 'PRODUCER_PACKET_NOT_RECOMPUTED'):
                    native_rule_readback(None, forged, expected, spec,
                                         source_context=lambda _: ctx)

    def test_lod_distance_importance_and_geometry_defects_are_real_failures(self):
        fixture, ctx, policy, _ = self.context()
        bad = copy.deepcopy(policy)
        bad['importance_lod_profiles']['hero']['min_far_m'] = 110
        fixture.put(budget=bad)
        self.assertEqual(build_packet(ctx, 'AAA-200-O-144')['rule']['result'],
                         'FAIL')
        fixture.put(budget=policy, lod=fixture.native)
        self.assertEqual(build_packet(ctx, 'AAA-200-O-144')['rule']['result'],
                         'FAIL')

    def test_missing_pre_d_lod_pin_is_unknown_not_pass(self):
        fixture, ctx, _, _ = self.context()
        fixture.f.plan['p345_evidence_contract']['original_artifact_sha256'].pop(
            'LOD_EXPORT')
        fixture.f.rebuild()
        self.assertEqual(build_packet(ctx, 'AAA-200-O-144')['rule']['result'],
                         'UNKNOWN')

    def test_material_baseline_no_real_reduction_is_fail(self):
        fixture, ctx, policy, _ = self.context()
        fixture.f.add_item('BASELINE_SNAPSHOT', 'baseline.glb', fixture.native)
        policy['material_cost_baseline_sha256'] = __import__('hashlib').sha256(
            fixture.native).hexdigest()
        fixture.put(budget=policy)
        fixture.f.plan['p345_evidence_contract']['original_artifact_sha256'][
            'BASELINE_SNAPSHOT'] = fixture.f.items['BASELINE_SNAPSHOT']['sha256']
        fixture.f.rebuild()
        self.assertEqual(build_packet(ctx, 'AAA-200-O-146')['rule']['result'],
                         'FAIL')

    def test_missing_pre_d_material_baseline_pin_is_unknown(self):
        fixture, ctx, _, _ = self.context()
        fixture.f.plan['p345_evidence_contract']['original_artifact_sha256'].pop(
            'BASELINE_SNAPSHOT')
        fixture.f.rebuild()
        self.assertEqual(build_packet(ctx, 'AAA-200-O-146')['rule']['result'],
                         'UNKNOWN')

    def test_tampered_original_budget_and_cross_attempt_rejected(self):
        fixture, ctx, _, _ = self.context()
        (fixture.f.root/'budget.json').write_bytes(b'{"fake":true}')
        with self.assertRaises(ValueError):
            build_packet(ctx, 'AAA-200-O-144')
        fixture, ctx, _, _ = self.context()
        ctx['work']['attempt_id'] = 'f'*64
        with self.assertRaises(ValueError):
            build_packet(ctx, 'AAA-200-O-146')

if __name__ == '__main__':
    unittest.main()
