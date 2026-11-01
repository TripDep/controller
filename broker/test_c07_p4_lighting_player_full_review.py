"""P4 N131/N132/N137 original-byte lighting and player camera adversarial tests."""
import copy
import json
import unittest

from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p345_forty_native_evidence import P345Forty, encoded
from test_c07_a10_c10_original_evidence import png
from test_c07_positive_native_process import canonical, sha
from c07_p4_lighting_player_full_review import RULES, NEUTRAL, SEPARATE, PLAYER, inspect
from c07_native_source_rule_replayers import (
    NATIVE_RULES, FULL_LITERAL_REVIEWED, VALIDATORS, build_packet,
    native_rule_readback, NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding, semantic_packet

class P4LightingPlayerFullReviewTests(unittest.TestCase):
    def context(self):
        test,ctx=NativeOriginalReplayerTests.context(
            self,P345Forty,'test_p4_30_due_and_p5_40_due')
        test.f.plan['phase']=test.f.work['phase']='P4'
        test.add('LIGHT_NEUTRAL_VIEW','light_neutral_view.png',png(100))
        test.add('LIGHT_CINEMATIC_VIEW','light_cinematic_view.png',png(170))
        test.add('VISUAL_PLAYER_VIEW','visual_player_view.png',png(90))
        camera={'camera_xyz':[0.5,-3,1.7],'forward_xyz':[0,1,0]}
        test.add('P4_PLAYER_CAMERA','p4_player_camera.json',encoded(camera))
        self.refresh(test,ctx)
        return test,ctx

    def refresh(self,test,ctx):
        test.sync()
        f=test.f
        events=(
            ('LIGHT_CAPTURED','LIGHT_NEUTRAL_VIEW','neutral'),
            ('LIGHT_CAPTURED','LIGHT_CINEMATIC_VIEW','cinematic'),
            ('RENDER_CAPTURED','VISUAL_PLAYER_VIEW','player'))
        for event_name,role,mode in events:
            row={'asset':f.asset,'event':event_name,
                 'prev_hash':f.records[-1]['record_hash'],
                 'step':f.step,'attempt_id':f.work['attempt_id'],
                 'operation_sha256':f.work['operation_sha256'],
                 'source_role':role,'mode':mode,
                 'image_sha256':f.items[role]['sha256']}
            row['record_hash']=sha(canonical(row))
            f.records.append(row)
        f.controller.audit_path(f.asset).write_bytes(
            b''.join(canonical(row)+bytes([10]) for row in f.records))
        f.controller._state['last_audit_hash']=f.records[-1]['record_hash']
        ctx['controller']=f.controller

    def packet(self,ctx,rid):
        expected=binding(ctx['work'],ctx['inventory']['rules'][rid],rid)
        packet=build_packet(ctx,rid,expected=expected)
        spec={'validator_id':VALIDATORS[rid],
              'criteria':list(NATIVE_RULES[rid][1]),
              'requirement_sha256':expected['requirement_sha256'],
              'source_ref':'1'*40,
              'issuer':{'workflow_blob':'a'*40,'public_sha':'b'*40}}
        return packet,expected,spec

    def test_three_source_specific_positive_capture_replays_unknown_mg0(self):
        for rid in RULES:
            with self.subTest(rule=rid):
                _,ctx=self.context()
                packet,expected,spec=self.packet(ctx,rid)
                self.assertNotIn(rid,FULL_LITERAL_REVIEWED)
                self.assertEqual(packet['rule']['result'],'UNKNOWN')
                self.assertTrue(all(packet['rule']['checks'].values()))
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                with self.assertRaisesRegex(ValueError,'NOT_WHITELISTED'):
                    replay(None,packet,expected,spec,source_context=lambda _:ctx)
                self.assertEqual(semantic_packet(packet,expected,spec)['result'],
                                 'UNKNOWN')

    def test_neutral_original_pixel_luminance_not_only_label(self):
        test,ctx=self.context()
        test.add('LIGHT_NEUTRAL_VIEW','light_neutral_view.png',png(20))
        self.refresh(test,ctx)
        packet,_,_=self.packet(ctx,NEUTRAL)
        self.assertEqual(packet['rule']['result'],'UNKNOWN')
        self.assertFalse(packet['rule']['checks'][NATIVE_RULES[NEUTRAL][1][2]])

    def test_identical_original_pixels_not_two_lighting_modes(self):
        test,ctx=self.context()
        test.add('LIGHT_CINEMATIC_VIEW','light_cinematic_view.png',png(100))
        self.refresh(test,ctx)
        packet,_,_=self.packet(ctx,SEPARATE)
        self.assertEqual(packet['rule']['result'],'UNKNOWN')
        self.assertFalse(packet['rule']['checks'][NATIVE_RULES[SEPARATE][1][1]])

    def test_player_camera_wrong_height_and_direction_fails(self):
        test,ctx=self.context()
        test.add('P4_PLAYER_CAMERA','p4_player_camera.json',
                 encoded({'camera_xyz':[0.5,-3,4.5],
                          'forward_xyz':[0,-1,0]}))
        self.refresh(test,ctx)
        packet,_,_=self.packet(ctx,PLAYER)
        self.assertEqual(packet['rule']['result'],'UNKNOWN')
        self.assertFalse(packet['rule']['checks'][NATIVE_RULES[PLAYER][1][2]])

    def test_missing_original_camera_pin_never_positive(self):
        test,ctx=self.context()
        test.f.plan['p345_evidence_contract']['original_artifact_sha256'].pop(
            'P4_PLAYER_CAMERA')
        test.f.rebuild()
        ctx['controller']=test.f.controller
        packet,_,_=self.packet(ctx,PLAYER)
        self.assertNotEqual(packet['rule']['result'],'PASS')

    def test_original_source_mutation_and_producer_forgery_fail_closed(self):
        test,ctx=self.context()
        packet,expected,spec=self.packet(ctx,NEUTRAL)
        forged=copy.deepcopy(packet)
        forged['rule']['proof_digest']='f'*64
        with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                    'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None,forged,expected,spec,
                                 source_context=lambda _:ctx)
        (test.f.root/'light_neutral_view.png').write_bytes(b'corrupt')
        with self.assertRaises(ValueError):
            inspect(ctx,NEUTRAL)

if __name__=='__main__':
    unittest.main()
