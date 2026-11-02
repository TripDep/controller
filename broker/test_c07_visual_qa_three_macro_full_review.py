"""C07 three source-specific P3/P4/P8 original multi-angle QA full replayers.

Synthetic fixtures only: source documentary PASS does not confer MG0,
runtime FiveM success, or owner approval.
"""
import copy
import json
import unittest

from c07_visual_qa_three_macro_full_review import inspect,L,N,S
from c07_camera_views_full_review import VIEWS
from c07_native_source_rule_replayers import (
    build_packet,FULL_LITERAL_REVIEWED,NATIVE_RULES,VALIDATORS,
    native_rule_readback,NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding
from test_c07_p345_remaining_original_review import RemainingP345Tests
from test_c07_camera_views_full_review import CameraViewsFullReviewTests,POSITIONS
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p678_forty_native_domain import P678Forty,encode
from test_c07_p3_geometry_semantics import glb
from test_c07_positive_native_process import canonical,sha

def solid_tetra():
    return glb([(0,0,0),(1,0,0),(0,1,0),(0,0,1)],
        [(0,2,1),(0,1,3),(0,3,2),(1,2,3)],[(0,0,1)]*4)

def audit_captures(test,ctx,frames):
    f=test.f
    for frame in frames:
        entry={'asset':f.asset,'event':'RENDER_CAPTURED',
               'prev_hash':f.records[-1]['record_hash'],
               'step':f.step,'attempt_id':f.work['attempt_id'],
               'operation_sha256':f.work['operation_sha256'],
               'source_role':frame['role'],
               'image_sha256':frame['image_sha256']}
        entry['record_hash']=sha(canonical(entry))
        f.records.append(entry)
    f.controller.audit_path(f.asset).write_bytes(
        b''.join(canonical(e)+bytes([10]) for e in f.records))
    f.controller._state['last_audit_hash']=f.records[-1]['record_hash']
    ctx['controller']=f.controller

class SourceVisualQAMacro(unittest.TestCase):
    def source(self,rid):
        if rid==L:
            h=RemainingP345Tests('test_positive_source_benefits_measured_not_promoted_to_full')
            h.setUp()
            self.addCleanup(h.doCleanups)
            return h.context()
        if rid==N:
            h=CameraViewsFullReviewTests('test_two_independent_current_operation_four_view_positive_readbacks')
            h.setUp()
            self.addCleanup(h.doCleanups)
            test,ctx=h.context(N)
            test.add('NATIVE_EXPORT','scene.glb',solid_tetra())
            test.sync()
            ctx['controller']=test.f.controller
            h.refresh(test,ctx,N)
            return test,ctx
        h=NativeOriginalReplayerTests(
            'test_twenty_six_independent_source_specific_replayers_positive_source_unknown_mg0')
        h.setUp()
        self.addCleanup(h.doCleanups)
        test,ctx=h.context(P678Forty,
            'test_phase_P6_10_rules_due_P7_20_P8_40')
        test.f.plan['phase']=test.f.work['phase']='P8'
        test.add('NATIVE_EXPORT','scene.glb',solid_tetra())
        roles=VIEWS[S]
        frames=[]
        for role in roles:
            view=role.rsplit('_',1)[-1]
            if view=='UNDERSIDE':
                pos,look=([.5,.5,-3],[0,0,1])
            else:
                pos,look=POSITIONS[view]
            frames.append({'role':role,'position_xyz':pos,
                'forward_xyz':look,
                'image_sha256':test.f.items[role]['sha256']})
        test.add('P8_CAMERA_CAPTURE_TRACE','p8_camera_trace.json',
            encode({'schema':'gg-c07-native-camera-capture-v1',
                'attempt_id':test.f.work['attempt_id'],
                'operation_sha256':test.f.work['operation_sha256'],
                'frames':frames}))
        test.add('P8_VIEW_QA','p8_view_qa.json',encode({
            'checked_roles':list(roles),
            'defect_counts':{role:0 for role in roles}}))
        test.sync()
        ctx['controller']=test.f.controller
        audit_captures(test,ctx,frames)
        return test,ctx

    def spec(self,ctx,rid):
        expected=binding(ctx['work'],ctx['inventory']['rules'][rid],rid)
        spec={'validator_id':VALIDATORS[rid],
              'criteria':list(NATIVE_RULES[rid][1]),
              'requirement_sha256':expected['requirement_sha256'],
              'source_ref':'1'*40}
        return expected,spec

    def test_all_three_original_source_replays_and_source_only_pass(self):
        self.assertTrue({L,N,S}<=FULL_LITERAL_REVIEWED)
        for rid in (L,N,S):
            with self.subTest(rule=rid):
                _,ctx=self.source(rid)
                original=inspect(ctx,rid)
                self.assertTrue(original['evidence_complete'],original)
                self.assertTrue(all(original['checks'].values()),original)
                packet=build_packet(ctx,rid)
                self.assertEqual(packet['rule']['result'],'PASS')
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                expected,spec=self.spec(ctx,rid)
                result=replay(None,packet,expected,spec,
                              source_context=lambda _:ctx)
                self.assertEqual(result['documentary_result'],'PASS')
                self.assertFalse(result['advancement_authorized'])
                forged=copy.deepcopy(packet)
                forged['rule']['proof_digest']='f'*64
                with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                        'PRODUCER_PACKET_NOT_RECOMPUTED'):
                    native_rule_readback(None,forged,expected,spec,
                                         source_context=lambda _:ctx)

    def test_approved_geometry_with_same_bbox_but_different_faces_fails(self):
        test,ctx=self.source(L)
        test.add('P3_APPROVED_EXPORT','approved_export.glb',
             glb([(0,0,0),(1,0,0),(0,1,0),(1,1,0)],
                 [(0,1,3),(0,3,2)],[(0,0,1)]*4))
        test.sync();ctx['controller']=test.f.controller
        self.assertEqual(build_packet(ctx,L)['rule']['result'],'FAIL')

    def test_four_view_camera_with_flat_native_mesh_does_not_pass(self):
        test,ctx=self.source(N)
        test.add('NATIVE_EXPORT','scene.glb',
            glb([(0,0,0),(1,0,0),(0,1,0)],[(0,1,2)],[(0,0,1)]*3))
        test.sync();ctx['controller']=test.f.controller
        self.assertEqual(build_packet(ctx,N)['rule']['result'],'FAIL')

    def test_six_view_qa_with_unresolved_defect_is_not_clean(self):
        test,ctx=self.source(S)
        roles=VIEWS[S]
        test.add('P8_VIEW_QA','p8_view_qa.json',encode({
            'checked_roles':list(roles),
            'defect_counts':{role:(1 if role=='VISUAL_VIEW_TOP' else 0)
                             for role in roles}}))
        test.sync();ctx['controller']=test.f.controller
        self.assertEqual(build_packet(ctx,S)['rule']['result'],'FAIL')

    def test_camera_native_origin_source_mutation_blocks(self):
        for rid in (L,N,S):
            with self.subTest(rule=rid):
                test,ctx=self.source(rid)
                (test.f.root/'scene.glb').write_bytes(b'forged')
                with self.assertRaises(ValueError):
                    build_packet(ctx,rid)

if __name__=='__main__':
    unittest.main()
