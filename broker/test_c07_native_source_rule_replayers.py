"""Adversarial source-byte tests for eight NEW native per-rule replayers.

Synthetic fixtures prove the consumer recomputes actual original bytes and
cannot turn UNKNOWN individual MG0 into a production PASS.
"""
import copy
import unittest
from pathlib import Path

import supervisor_judgment as j
import c07_mg0_individual as mg0
from c07_native_source_rule_replayers import (
    NATIVE_RULES, VALIDATORS, build_packet, native_rule_readback,
    NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from test_c07_p3_geometry_semantics import Tests as GeometryFixture, glb, TRI, UP
from test_c07_p1_thirty_native_domain import P1Thirty
from test_c07_p3_uv_semantics import Tests as UVFixture
from test_c07_p4_texture_semantics import Tests as TextureFixture
from test_c07_p8_final_qa_semantics import Tests as FinalFixture
from test_c07_p8_closure_semantics import Tests as ClosureFixture
from test_c07_p5_budget_semantics import Tests as BudgetFixture, BUDGET
from test_c07_p8_delivery_semantics import Tests as DeliveryFixture, plan, package

CASES = (
    (P1Thirty, 'AAA-200-E-044', 'test_exact_30_individual_P1_and_90_unique_predicates'),
    (UVFixture, 'AAA-200-L-117', 'test_three_actual_uv_oracles_are_not_full_rule_or_mg0'),
    (TextureFixture, 'AAA-200-M-128', 'test_six_original_pixel_oracles_observed_not_approved'),
    (FinalFixture, 'AAA-200-S-189', 'test_ten_distinct_original_scoped_observations_not_full_review'),
    (ClosureFixture, 'AAA-200-T-196', 'test_five_scoped_observations_and_final_rule_unknown'),
    (P1Thirty, 'AAA-200-E-042', 'test_exact_30_individual_P1_and_90_unique_predicates'),
    (P1Thirty, 'AAA-200-E-047', 'test_exact_30_individual_P1_and_90_unique_predicates'),
    (P1Thirty, 'AAA-200-F-052', 'test_exact_30_individual_P1_and_90_unique_predicates'),
    (GeometryFixture, 'AAA-200-L-111',
     'test_four_real_per_rule_triangle_oracles_without_mg0_or_owner_pass'),
    (GeometryFixture, 'AAA-200-L-112',
     'test_four_real_per_rule_triangle_oracles_without_mg0_or_owner_pass'),
    (BudgetFixture, 'AAA-200-O-142',
     'test_five_original_quantitative_oracles_no_mg0'),
    (BudgetFixture, 'AAA-200-O-148',
     'test_five_original_quantitative_oracles_no_mg0'),
    (DeliveryFixture, 'AAA-200-T-194',
     'test_four_original_delivery_oracles_no_false_fivem_pass'),
)

class NativeOriginalReplayerTests(unittest.TestCase):
    def context(self, fixture_class, method):
        test = fixture_class(method)
        test.setUp()
        self.addCleanup(test.doCleanups)
        f = test.f
        master = ('## MG0 — PROCESS FALSIFICATION\n' +
            ''.join('- ' + trigger + '\n' for trigger in mg0.TRIGGERS) +
            'The response is not limited to fixing the asset.\n' +
            'invalidate affected states and reapply the corrected process\n').encode()
        f.master = master
        f.controller.master.write_bytes(master)
        f.work.update(work_item_sha256='e'*64, attempt_number=1,
                      previous_attempt_id=None)
        f.work['master_sha256'] = f.plan['master_sha256'] = f.inv[
            'canonical_master_sha256'] = j.evidence.sha256(master) if hasattr(
                j.evidence, 'sha256') else __import__('hashlib').sha256(master).hexdigest()
        f.rebuild()
        if isinstance(test, FinalFixture):
            test.add_critical()
        return test, {
            'inventory': f.inv, 'plan': f.plan,
            'controller': f.controller, 'asset': f.asset,
            'step': f.step, 'work': f.work,
            'source_loader': lambda path: Path(path).read_bytes(),
        }

    def spec(self, ctx, rid):
        row = ctx['inventory']['rules'][rid]
        return {'validator_id': VALIDATORS[rid],
                'criteria': list(NATIVE_RULES[rid][1]),
                'requirement_sha256': row['requirement_sha256'],
                'source_ref': '1'*40,
                'issuer': {'workflow_blob': 'a'*40, 'public_sha': 'b'*40}}

    def test_thirteen_independent_source_specific_replayers_positive_source_unknown_mg0(self):
        self.assertEqual(len(CASES), 13)
        self.assertEqual(len(set(x[1] for x in CASES)), 13)
        for fixture_class, rid, method in CASES:
            with self.subTest(rule=rid):
                _, ctx = self.context(fixture_class, method)
                expected = j.binding(ctx['work'], ctx['inventory']['rules'][rid], rid)
                packet = build_packet(ctx, rid, expected=expected)
                self.assertEqual(packet['rule']['result'], 'PASS')
                self.assertEqual(packet['mg0']['result'], 'UNKNOWN')
                self.assertEqual(packet['mg0']['triggered'], None)
                self.assertEqual(set(packet['rule']['checks']),
                                 set(NATIVE_RULES[rid][1]))
                spec = self.spec(ctx, rid)
                result = replay(None, packet, expected, spec,
                                source_context=lambda binding: ctx)
                self.assertEqual(result['documentary_result'], 'PASS')
                self.assertEqual(result['individual_rule_mg0'], 'UNKNOWN')
                self.assertFalse(result['advancement_authorized'])
                self.assertEqual(j.semantic_packet(packet, expected, spec)['result'],
                                 'UNKNOWN')

    def test_per_rule_adversarial_mutation_cannot_become_positive(self):
        for fixture_class, rid, method in CASES:
            with self.subTest(rule=rid):
                test, ctx = self.context(fixture_class, method)
                expected = j.binding(ctx['work'], ctx['inventory']['rules'][rid], rid)
                packet = build_packet(ctx, rid, expected=expected)
                spec = self.spec(ctx, rid)
                forged = copy.deepcopy(packet)
                forged['rule']['proof_digest'] = 'f'*64
                with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                            'PRODUCER_PACKET_NOT_RECOMPUTED'):
                    native_rule_readback(None, forged, expected, spec,
                                         source_context=lambda _: ctx)
                wrong = dict(expected, attempt_id='f'*64)
                with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                            'ATTEMPT_OPERATION_SOURCE_MISMATCH'):
                    native_rule_readback(None, packet, wrong, spec,
                                         source_context=lambda _: ctx)
                with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                            'NO_INDEPENDENT_ORIGINAL_SOURCE_READER'):
                    native_rule_readback(None, packet, expected, spec)
                # Tampering the registered original bytes without an audit
                # update must fail even when the producer packet is unchanged.
                if rid == 'AAA-200-L-117':
                    p = ctx['controller'].root / 'uv_policy.json'
                elif rid == 'AAA-200-M-128':
                    p = ctx['controller'].root / 'p4_policy.json'
                elif rid == 'AAA-200-S-189':
                    p = ctx['controller'].root / 'scene.glb'
                elif rid == 'AAA-200-T-196':
                    p = ctx['controller'].root / 'p8_test_matrix.json'
                elif rid.startswith('AAA-200-E') or rid.startswith('AAA-200-F'):
                    p = ctx['controller'].root / 'p1_scene.json'
                elif rid.startswith('AAA-200-L'):
                    p = ctx['controller'].root / 'scene.glb'
                elif rid.startswith('AAA-200-O'):
                    p = ctx['controller'].root / 'budget.json'
                else:
                    p = ctx['controller'].root / 'scene.zip'
                p.write_bytes(p.read_bytes() + b'forged')
                with self.assertRaises(ValueError):
                    native_rule_readback(None, packet, expected, spec,
                                         source_context=lambda _: ctx)

    def test_native_rule_negative_originals_not_reinterpreted_as_pass(self):
        test, ctx = self.context(GeometryFixture,
            'test_four_real_per_rule_triangle_oracles_without_mg0_or_owner_pass')
        test.put(glb(TRI, [(0,1,2), (2,1,0)], UP))
        ctx['controller'] = test.f.controller
        self.assertEqual(build_packet(ctx, 'AAA-200-L-112')['rule']['result'], 'FAIL')

        test, ctx = self.context(BudgetFixture,
            'test_five_original_quantitative_oracles_no_mg0')
        test.put(budget=dict(BUDGET, max_triangles=1))
        ctx['controller'] = test.f.controller
        self.assertEqual(build_packet(ctx, 'AAA-200-O-142')['rule']['result'], 'FAIL')

        test, ctx = self.context(DeliveryFixture,
            'test_four_original_delivery_oracles_no_false_fivem_pass')
        test.put(archive=package(plan(), wrong_version=True))
        ctx['controller'] = test.f.controller
        self.assertEqual(build_packet(ctx, 'AAA-200-T-194')['rule']['result'], 'FAIL')

if __name__ == '__main__':
    unittest.main()
