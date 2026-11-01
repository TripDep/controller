"""S181 six independently reopened P8 QA views and original capture events."""
import copy
import unittest

from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p678_forty_native_domain import P678Forty, encode
from test_c07_positive_native_process import canonical, sha
from c07_camera_views_full_review import P8, VIEWS, inspect
from c07_native_source_rule_replayers import (
    NATIVE_RULES, FULL_LITERAL_REVIEWED, VALIDATORS, build_packet,
    native_rule_readback, NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding, semantic_packet

CAMERAS = {
    'FRONT':([0.5,-3,0.5],[0,1,0]),
    'LEFT':([-3,0.5,0.5],[1,0,0]),
    'RIGHT':([3,0.5,0.5],[-1,0,0]),
    'REAR':([0.5,3,0.5],[0,-1,0]),
    'TOP':([0.5,0.5,4],[0,0,-1]),
    'UNDERSIDE':([0.5,0.5,-3],[0,0,1]),
}

class P8SixViewsTests(unittest.TestCase):
    def context(self):
        test,ctx=NativeOriginalReplayerTests.context(
            self,P678Forty,'test_phase_P6_10_rules_due_P7_20_P8_40')
        test.f.plan['phase']=test.f.work['phase']='P8'
        self.refresh(test,ctx)
        return test,ctx

    def refresh(self,test,ctx,*,top_override=None,missing_qa=None):
        roles=VIEWS[P8]
        frames=[]
        for role in roles:
            pos,direction=CAMERAS[role.rsplit('_',1)[-1]]
            if role=='VISUAL_VIEW_TOP' and top_override is not None:
                direction=top_override
            frames.append({'role':role,'position_xyz':list(pos),
                'forward_xyz':list(direction),
                'image_sha256':test.f.items[role]['sha256']})
        trace={'schema':'gg-c07-native-camera-capture-v1',
               'attempt_id':test.f.work['attempt_id'],
               'operation_sha256':test.f.work['operation_sha256'],
               'frames':frames}
        qa={'checked_roles':list(roles),
            'defect_counts':{role:0 for role in roles}}
        if missing_qa is not None:
            qa['defect_counts'].pop(missing_qa)
        test.add('P8_CAMERA_CAPTURE_TRACE','p8_camera_trace.json',encode(trace))
        test.add('P8_VIEW_QA','p8_view_qa.json',encode(qa))
        test.sync()
        f=test.f
        for frame in frames:
            row={'asset':f.asset,'event':'RENDER_CAPTURED',
                 'prev_hash':f.records[-1]['record_hash'],
                 'step':f.step,'attempt_id':f.work['attempt_id'],
                 'operation_sha256':f.work['operation_sha256'],
                 'source_role':frame['role'],
                 'image_sha256':frame['image_sha256']}
            row['record_hash']=sha(canonical(row))
            f.records.append(row)
        f.controller.audit_path(f.asset).write_bytes(
            b''.join(canonical(row)+bytes([10]) for row in f.records))
        f.controller._state['last_audit_hash']=f.records[-1]['record_hash']
        ctx['controller']=f.controller

    def packet(self,ctx):
        expected=binding(ctx['work'],ctx['inventory']['rules'][P8],P8)
        packet=build_packet(ctx,P8,expected=expected)
        spec={'validator_id':VALIDATORS[P8],
              'criteria':list(NATIVE_RULES[P8][1]),
              'requirement_sha256':expected['requirement_sha256'],
              'source_ref':'1'*40,
              'issuer':{'workflow_blob':'a'*40,'public_sha':'b'*40}}
        return packet,expected,spec

    def test_six_original_views_qa_and_controller_events_positive_unknown_mg0(self):
        _,ctx=self.context()
        packet,expected,spec=self.packet(ctx)
        self.assertIn(P8,FULL_LITERAL_REVIEWED)
        self.assertEqual(packet['rule']['result'],'PASS')
        self.assertTrue(all(packet['rule']['checks'].values()))
        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
        self.assertFalse(packet['mg0']['result']=='PASS')
        self.assertEqual(semantic_packet(packet,expected,spec)['result'],
                         'UNKNOWN')

    def test_missing_one_original_view_qa_fails_full_literal(self):
        test,ctx=self.context()
        self.refresh(test,ctx,missing_qa='VISUAL_VIEW_TOP')
        packet,_,_=self.packet(ctx)
        self.assertEqual(packet['rule']['result'],'FAIL')
        self.assertFalse(packet['rule']['checks'][NATIVE_RULES[P8][1][2]])

    def test_top_camera_reversed_is_not_multiview_pass(self):
        test,ctx=self.context()
        self.refresh(test,ctx,top_override=[0,0,1])
        packet,_,_=self.packet(ctx)
        self.assertEqual(packet['rule']['result'],'FAIL')
        self.assertFalse(packet['rule']['checks'][NATIVE_RULES[P8][1][2]])

    def test_duplicate_original_view_pixels_rejected(self):
        test,ctx=self.context()
        from pathlib import Path
        raw=Path(test.f.items['VISUAL_VIEW_FRONT']['path']).read_bytes()
        test.add('VISUAL_VIEW_REAR','visual_view_rear.png',raw)
        self.refresh(test,ctx)
        packet,_,_=self.packet(ctx)
        self.assertEqual(packet['rule']['result'],'FAIL')
        self.assertFalse(packet['rule']['checks'][NATIVE_RULES[P8][1][1]])

    def test_producer_packet_tamper_cannot_replace_original_replay(self):
        _,ctx=self.context()
        packet,expected,spec=self.packet(ctx)
        forged=copy.deepcopy(packet)
        forged['rule']['proof_digest']='f'*64
        with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                    'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None,forged,expected,spec,
                                 source_context=lambda _:ctx)

if __name__=='__main__':
    unittest.main()
