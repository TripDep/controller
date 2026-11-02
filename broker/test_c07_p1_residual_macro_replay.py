"""Ten original P1 D031-D040 replay candidates: 8 per-rule checks.

Actual original-byte fixture positives, individual source mutations and
negative dispatch. Fixture PASS is never artistic, MG0 or owner approval.
"""
import copy
import hashlib
import unittest
from pathlib import Path
import c07_mg0_individual as mg0

from test_c07_p1_design_source_review import P1DesignSourceTests
from c07_native_source_rule_replayers import (
    NATIVE_RULES, P1_RESIDUAL_CANDIDATES, FULL_LITERAL_REVIEWED,
    build_packet, native_rule_readback, NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import REPLAYERS
from approved_validators import REVIEWED
from supervisor_judgment import binding

IDS = tuple('AAA-200-D-%03d' % n for n in range(31, 41))
ATTACKS = {
    31: ('scene', 'style_quadrant_tolerance', 0),
    32: ('scene', 'peer_quadrant_tolerance', 0),
    33: ('palette', 'colors', ['#000000', '#000001']),
    34: ('scene', 'void_zones', []),
    35: ('scene', 'silhouette_quadrant_tolerance', 0),
    36: ('scene', 'min_focal_luminance_delta', 250),
    37: ('scene', 'max_repeated_quadrants', 0),
    38: ('scene', 'min_material_unique_rgb', 100),
    39: ('scene', 'player_camera', {
        'eye_xyz': [0, 0, 99], 'target_xyz': [0.5, 0.5, 0.5]}),
    40: ('scene', 'component_role_mesh_map', {'primary': 'forged'}),
}

class P1ResidualSourceReplayTests(unittest.TestCase):
    def fixture(self):
        t = P1DesignSourceTests(
            'test_thirteen_real_original_pixel_and_geometry_predicates')
        t.setUp()
        self.addCleanup(t.doCleanups)
        # The P1 design fixture tests source bytes only. The consuming-side
        # native replayer also requires a current MG0 master and complete
        # immutable work-item/attempt binding, exactly as the canonical
        # native-replayer fixture does.
        f = t.fixture.f
        master = ('## MG0 — PROCESS FALSIFICATION\n' +
                  ''.join('- ' + trigger + '\n' for trigger in mg0.TRIGGERS) +
                  'The response is not limited to fixing the asset.\n' +
                  'invalidate affected states and reapply the corrected process\n').encode()
        f.master = master
        f.controller.master.write_bytes(master)
        f.work.update(work_item_sha256='e'*64, attempt_number=1,
                      previous_attempt_id=None)
        digest = hashlib.sha256(master).hexdigest()
        f.work['master_sha256'] = f.plan['master_sha256'] = (
            f.inv['canonical_master_sha256']) = digest
        f.rebuild()
        return t

    @staticmethod
    def context(t):
        f = t.fixture.f
        return {'inventory': f.inv, 'plan': f.plan,
                'controller': f.controller, 'asset': f.asset,
                'step': f.step, 'work': f.work,
                'source_loader': lambda p: Path(p).read_bytes()}

    def test_whole_ten_literal_original_eight_check_macro(self):
        self.assertEqual(set(P1_RESIDUAL_CANDIDATES), set(IDS))
        self.assertEqual(len({k for rid in IDS
                              for k in NATIVE_RULES[rid][1]}), 62)
        t = self.fixture()
        ctx = self.context(t)
        for rid in IDS:
            with self.subTest(rule=rid):
                packet = build_packet(ctx, rid)
                checks = packet['rule']['checks']
                self.assertEqual(set(checks), set(NATIVE_RULES[rid][1]))
                self.assertEqual(len(checks), 8)
                self.assertTrue(all(checks[k] for k in
                    list(NATIVE_RULES[rid][1])[:3]))
                self.assertEqual(packet['rule']['result'], 'UNKNOWN')
                self.assertIn(packet['mg0']['result'], ('UNKNOWN', 'FAIL'))
                self.assertNotIn(rid, FULL_LITERAL_REVIEWED)
                self.assertNotIn(rid, REVIEWED)
                self.assertNotIn(rid, REPLAYERS)

    def test_ten_distinct_original_source_attacks(self):
        for n, (group, key, bad) in ATTACKS.items():
            with self.subTest(number=n):
                t = self.fixture()
                rid = 'AAA-200-D-%03d' % n
                before = build_packet(self.context(t), rid)['rule']['checks']
                getattr(t, group)[key] = copy.deepcopy(bad)
                t.install()
                after = build_packet(self.context(t), rid)['rule']['checks']
                relevant = NATIVE_RULES[rid][1][:3]
                self.assertTrue(any(before[k] and not after[k]
                                    for k in relevant), (rid, before, after))
                self.assertEqual(
                    build_packet(self.context(t), rid)['rule']['result'],
                    'UNKNOWN')

    def test_all_ten_cannot_be_promoted_or_dispatched_by_fixture(self):
        t = self.fixture()
        ctx = self.context(t)
        for rid in IDS:
            with self.subTest(rule=rid):
                row = ctx['inventory']['rules'][rid]
                expected = binding(ctx['work'], row, rid)
                packet = build_packet(ctx, rid, expected=expected)
                spec = {'validator_id': packet['validator_id'],
                        'criteria': list(NATIVE_RULES[rid][1]),
                        'requirement_sha256': expected['requirement_sha256'],
                        'source_ref': '1'*40}
                with self.assertRaisesRegex(
                        NativeRuleEvidenceBlocked,
                        'C07_REPLAYER_UNREVIEWED_OR_WRONG_LITERAL'):
                    native_rule_readback(
                        None, packet, expected, spec,
                        source_context=lambda _: ctx)
