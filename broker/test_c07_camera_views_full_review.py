"""Adversarial independent original camera audit and raster view replayers."""
import copy
import json
import unittest

from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p1_thirty_native_domain import P1Thirty, encode
from test_c07_p345_forty_native_evidence import P345Forty, encoded
from test_c07_positive_native_process import canonical, sha
from c07_camera_views_full_review import P1, P4, VIEWS, RULES, inspect
from c07_native_source_rule_replayers import (
    NATIVE_RULES, FULL_LITERAL_REVIEWED, VALIDATORS, build_packet,
    native_rule_readback, NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding, semantic_packet

POSITIONS = {
    'FRONT':([0.5,-3,0.5],[0,1,0]),
    'LEFT':([-3,0.5,0.5],[1,0,0]),
    'SIDE':([-3,0.5,0.5],[1,0,0]),
    'RIGHT':([3,0.5,0.5],[-1,0,0]),
    'REAR':([0.5,3,0.5],[0,-1,0]),
    'TOP':([0.5,0.5,4],[0,0,-1]),
}

class CameraViewsFullReviewTests(unittest.TestCase):
    def context(self, rid):
        klass = P1Thirty if rid == P1 else P345Forty
        method = ('test_exact_30_individual_P1_and_90_unique_predicates'
                  if rid == P1 else 'test_p4_30_due_and_p5_40_due')
        test, ctx = NativeOriginalReplayerTests.context(self, klass, method)
        if rid == P4:
            test.f.work['phase'] = test.f.plan['phase'] = 'P4'
        return test, ctx

    def refresh(self, test, ctx, rid, *, alter=None):
        roles = VIEWS[rid]
        frames = []
        for role in roles:
            name = role.rsplit('_',1)[-1]
            pos, direction = POSITIONS[name]
            frame = {'role':role,'position_xyz':list(pos),
                     'forward_xyz':list(direction),
                     'image_sha256':test.f.items[role]['sha256']}
            if alter and role in alter:
                frame.update(alter[role])
            frames.append(frame)
        trace = {'schema':'gg-c07-native-camera-capture-v1',
                 'attempt_id':test.f.work['attempt_id'],
                 'operation_sha256':test.f.work['operation_sha256'],
                 'frames':frames}
        if rid == P1:
            test.put('P1_CAMERA_CAPTURE_TRACE', 'p1_camera_trace.json',
                     encode(trace))
            test.rebuild()
        else:
            test.add('P4_CAMERA_CAPTURE_TRACE', 'p4_camera_trace.json',
                     encoded(trace))
            test.sync()
        f = test.f
        for frame in frames:
            previous = f.records[-1]['record_hash']
            event = {'asset':f.asset,'event':'RENDER_CAPTURED',
                     'prev_hash':previous,'step':f.step,
                     'attempt_id':f.work['attempt_id'],
                     'operation_sha256':f.work['operation_sha256'],
                     'source_role':frame['role'],
                     'image_sha256':frame['image_sha256']}
            event['record_hash'] = sha(canonical(event))
            f.records.append(event)
        f.controller.audit_path(f.asset).write_bytes(
            b''.join(canonical(row)+bytes([10]) for row in f.records))
        f.controller._state['last_audit_hash'] = f.records[-1]['record_hash']
        ctx['controller'] = f.controller

    def packet(self, ctx, rid):
        expected = binding(ctx['work'], ctx['inventory']['rules'][rid], rid)
        packet = build_packet(ctx, rid, expected=expected)
        spec = {'validator_id':VALIDATORS[rid],
                'criteria':list(NATIVE_RULES[rid][1]),
                'requirement_sha256':expected['requirement_sha256'],
                'source_ref':'1'*40,
                'issuer':{'workflow_blob':'a'*40,'public_sha':'b'*40}}
        return packet, expected, spec

    def test_two_independent_current_operation_four_view_positive_readbacks(self):
        for rid in (P1, P4):
            with self.subTest(rule=rid):
                test, ctx = self.context(rid)
                self.refresh(test, ctx, rid)
                packet, expected, spec = self.packet(ctx, rid)
                self.assertNotIn(rid, FULL_LITERAL_REVIEWED)
                self.assertEqual(packet['rule']['result'], 'UNKNOWN')
                self.assertTrue(all(packet['rule']['checks'].values()))
                self.assertEqual(packet['mg0']['result'], 'UNKNOWN')
                with self.assertRaisesRegex(ValueError, 'NOT_WHITELISTED'):
                    replay(None, packet, expected, spec,
                           source_context=lambda _:ctx)
                self.assertEqual(semantic_packet(packet, expected, spec)['result'],
                                 'UNKNOWN')

    def test_reused_pixels_with_different_original_names_never_pass(self):
        for rid in (P1, P4):
            with self.subTest(rule=rid):
                test, ctx = self.context(rid)
                roles = VIEWS[rid]
                raw = test.f.items[roles[0]]['path']
                from pathlib import Path
                duplicated = Path(raw).read_bytes()
                if rid == P1:
                    test.put(roles[1], roles[1].lower()+'.png', duplicated)
                else:
                    test.add(roles[1], roles[1].lower()+'.png', duplicated)
                self.refresh(test, ctx, rid)
                packet, _, _ = self.packet(ctx, rid)
                self.assertEqual(packet['rule']['result'], 'UNKNOWN')
                self.assertFalse(packet['rule']['checks'][
                    'four_distinct_original_png_pixel_arrays_and_native_geometry_reopened'])

    def test_top_camera_direction_mismatch_is_real_negative(self):
        for rid in (P1, P4):
            with self.subTest(rule=rid):
                test, ctx = self.context(rid)
                self.refresh(test, ctx, rid, alter={
                    'VISUAL_VIEW_TOP':{'forward_xyz':[0,0,1]}})
                packet, _, _ = self.packet(ctx, rid)
                self.assertEqual(packet['rule']['result'], 'UNKNOWN')
                self.assertFalse(packet['rule']['checks'][NATIVE_RULES[rid][1][2]])

    def test_missing_source_pin_never_grants_reviewed_positive(self):
        for rid in (P1, P4):
            with self.subTest(rule=rid):
                test, ctx = self.context(rid)
                self.refresh(test, ctx, rid)
                key = ('p1_evidence_contract' if rid == P1
                       else 'p345_evidence_contract')
                test.f.plan[key]['original_artifact_sha256'].pop(
                    'VISUAL_VIEW_TOP')
                test.f.rebuild()
                ctx['controller'] = test.f.controller
                packet, _, _ = self.packet(ctx, rid)
                self.assertNotEqual(packet['rule']['result'], 'PASS')

    def test_producer_packet_and_cross_attempt_forgery_rejected(self):
        test, ctx = self.context(P1)
        self.refresh(test, ctx, P1)
        packet, expected, spec = self.packet(ctx, P1)
        forged = copy.deepcopy(packet)
        forged['rule']['proof_digest'] = 'f'*64
        with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                    'UNREVIEWED_OR_WRONG_LITERAL'):
            native_rule_readback(None, forged, expected, spec,
                                 source_context=lambda _:ctx)
        wrong = dict(expected, operation_sha256='f'*64)
        with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                    'ATTEMPT_OPERATION_SOURCE_MISMATCH'):
            native_rule_readback(None, packet, wrong, spec,
                                 source_context=lambda _:ctx)

if __name__ == '__main__':
    unittest.main()
