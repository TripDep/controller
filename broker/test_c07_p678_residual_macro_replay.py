"""P6/P7/P8 seven residual original-source candidates, never FULL by fixture."""
import unittest
from pathlib import Path

from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p6_walkability_semantics import Tests as WalkFixture, TRI, NORMALS
from test_c07_p8_final_qa_semantics import Tests as FinalFixture
from test_c07_p3_geometry_semantics import glb
from c07_native_source_rule_replayers import (
    NATIVE_RULES, FULL_LITERAL_REVIEWED, P678_RESIDUAL_CANDIDATES,
    build_packet, native_rule_readback, NativeRuleEvidenceBlocked)
from c07_p678_residual_macro_replay import IDS, SOURCE_CANDIDATES
from c07_native_replayer_dispatch import REPLAYERS
from approved_validators import REVIEWED
from supervisor_judgment import binding

CASES = (
    ('AAA-200-P-155', WalkFixture,
     'test_five_source_geometry_observations_runtime_unattested'),
    ('AAA-200-P-160', WalkFixture,
     'test_five_source_geometry_observations_runtime_unattested'),
    ('AAA-200-S-190', FinalFixture,
     'test_ten_distinct_original_scoped_observations_not_full_review'),
)

def modified_fixture(kind):
    # Local fixture classes are not collected as unrelated inherited test
    # suites by unittest discovery. Their source is changed BEFORE binding
    # the current master/attempt, never inside an already-open audit.
    if kind == 'log':
        class WalkWithUntrustedLog(WalkFixture):
            def setUp(self):
                super().setUp()
                self.f.add_item('FIVEM_COLLISION_RUNTIME_LOG',
                                'fivem_collision.log',
                                b'producer labelled FiveM test - untrusted')
                self.f.plan['p678_evidence_contract'][
                    'original_artifact_sha256'][
                    'FIVEM_COLLISION_RUNTIME_LOG'] = (
                    self.f.items['FIVEM_COLLISION_RUNTIME_LOG']['sha256'])
                self.f.rebuild()
        return WalkWithUntrustedLog
    if kind == 'solid':
        class WalkBadOriginalSolid(WalkFixture):
            def setUp(self):
                super().setUp()
                self.collision = glb(
                    [(0.1,0.1,0),(0.9,0.1,0),(0.0,0.8,0)],
                    [(0,1,2)], NORMALS)
                self.put()
        return WalkBadOriginalSolid
    if kind == 'owner':
        class FinalForgedOwnerClaim(FinalFixture):
            def setUp(self):
                super().setUp()
                self.docs['P8_INTERNAL_QA']['owner_approved'] = True
                self.put()
        return FinalForgedOwnerClaim
    raise ValueError('unknown source mutation')

class P678ResidualSourceReplayTests(unittest.TestCase):
    def context(self, fixture, method):
        return NativeOriginalReplayerTests.context(self, fixture, method)

    def test_seven_original_residuals_have_source_readers_no_full(self):
        self.assertEqual(len(IDS), 7)
        self.assertEqual(len(set(IDS)), 7)
        self.assertEqual(SOURCE_CANDIDATES, {
            'AAA-200-P-155', 'AAA-200-P-160', 'AAA-200-S-190'})
        self.assertEqual(set(IDS) - SOURCE_CANDIDATES, {
            'AAA-200-Q-167','AAA-200-Q-168',
            'AAA-200-Q-169','AAA-200-Q-170'})
        self.assertTrue(set(IDS) <= set(NATIVE_RULES))
        self.assertFalse(set(IDS) & set(FULL_LITERAL_REVIEWED))
        self.assertFalse(set(IDS) & set(REVIEWED))
        self.assertFalse(set(IDS) & set(REPLAYERS))
        self.assertEqual(len(P678_RESIDUAL_CANDIDATES), 3)

    def test_each_new_original_rule_has_source_checks_and_unknown_result(self):
        for rid, fixture, method in CASES:
            with self.subTest(rule=rid):
                positive_fixture = (modified_fixture('log')
                                    if rid.endswith('160') else fixture)
                _, ctx = self.context(positive_fixture, method)
                packet = build_packet(ctx, rid)
                self.assertEqual(set(packet['rule']['checks']),
                                 set(NATIVE_RULES[rid][1]))
                self.assertEqual(len(packet['rule']['checks']), 3)
                self.assertEqual(packet['rule']['result'], 'UNKNOWN')
                self.assertIn(packet['mg0']['result'], ('UNKNOWN', 'FAIL'))
                self.assertTrue(any(packet['rule']['checks'].values()))
                self.assertFalse(packet['rule']['checks'][
                    NATIVE_RULES[rid][1][-1]] if rid.endswith(('160','190'))
                    else packet['rule']['result'] == 'PASS')

    def test_rule_specific_negative_sources_and_no_dispatch(self):
        for rid, fixture, method in CASES:
            with self.subTest(rule=rid):
                _, ctx = self.context(fixture, method)
                before = build_packet(ctx, rid)
                # Rebuild the changed ORIGINAL in a fresh fixture before the
                # trusted MG0 master and current operation are bound. Editing
                # an already-open audited operation would correctly fail SHA.
                changed_fixture = (
                    modified_fixture('solid') if rid.endswith('155') else
                    modified_fixture('log') if rid.endswith('160') else
                    modified_fixture('owner'))
                _, changed_ctx = self.context(changed_fixture, method)
                after = build_packet(changed_ctx, rid)
                self.assertEqual(after['rule']['result'], 'UNKNOWN')
                self.assertNotEqual(before['rule']['checks'],
                                    after['rule']['checks'])
                row = changed_ctx['inventory']['rules'][rid]
                expected = binding(changed_ctx['work'], row, rid)
                spec = {'validator_id': after['validator_id'],
                        'criteria': list(NATIVE_RULES[rid][1]),
                        'requirement_sha256': expected['requirement_sha256'],
                        'source_ref': '1'*40}
                with self.assertRaisesRegex(
                        NativeRuleEvidenceBlocked,
                        'C07_REPLAYER_UNREVIEWED_OR_WRONG_LITERAL'):
                    native_rule_readback(None, after, expected, spec,
                                         source_context=lambda _: changed_ctx)
