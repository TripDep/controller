"""Adversarial F-051/F-060 original P1 geometry and detail-gate tests."""
import copy
import json
import unittest

import supervisor_judgment as judgment
from c07_native_source_rule_replayers import NATIVE_RULES, VALIDATORS, build_packet, native_rule_readback
from c07_native_replayer_dispatch import replay
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p1_thirty_native_domain import P1Thirty, encode
from test_c07_native_output_oracle import two_triangles
from test_c07_p3_geometry_semantics import glb

RULES=('AAA-200-F-051','AAA-200-F-060')
CHECKS=['geometry_within_envelope','triangle_budget','major_faces']

class BlockoutFullReviewTests(unittest.TestCase):
    def context(self):
        fixture,ctx=NativeOriginalReplayerTests.context(
            self,P1Thirty,'test_exact_30_individual_P1_and_90_unique_predicates')
        scene=json.loads(fixture.contents['P1_SCENE_CONTRACT'][1])
        scene['blockout_min_major_face_fraction']=0.4
        scene['blockout_acceptance_criteria']=CHECKS
        fixture.put('P1_SCENE_CONTRACT','p1_scene.json',encode(scene))
        fixture.put('P1_QA_REPORT','qa.json',encode({
            'open_findings':[],'passed_checks':CHECKS}))
        fixture.rebuild()
        ctx['controller']=fixture.f.controller
        return fixture,ctx,scene

    def put(self,fixture,ctx,scene=None,qa=None,mesh=None):
        if scene is not None:
            fixture.put('P1_SCENE_CONTRACT','p1_scene.json',encode(scene))
        if qa is not None:
            fixture.put('P1_QA_REPORT','qa.json',encode(qa))
        if mesh is not None:
            fixture.put('NATIVE_EXPORT','scene.glb',mesh)
        fixture.rebuild()
        ctx['controller']=fixture.f.controller

    def test_two_full_original_blockout_positive_readbacks(self):
        _,ctx,_=self.context()
        for rid in RULES:
            with self.subTest(rule=rid):
                packet=build_packet(ctx,rid)
                self.assertEqual(packet['rule']['result'],'PASS')
                self.assertTrue(all(packet['rule']['checks'].values()))
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                expected=judgment.binding(
                    ctx['work'],ctx['inventory']['rules'][rid],rid)
                spec={'validator_id':VALIDATORS[rid],
                      'criteria':list(NATIVE_RULES[rid][1]),
                      'requirement_sha256':expected['requirement_sha256'],
                      'source_ref':'1'*40}
                result=replay(None,packet,expected,spec,
                              source_context=lambda _:ctx)
                self.assertEqual(result['documentary_result'],'PASS')
                forged=copy.deepcopy(packet)
                forged['rule']['proof_digest']='f'*64
                with self.assertRaisesRegex(ValueError,'PRODUCER_PACKET_NOT_RECOMPUTED'):
                    native_rule_readback(None,forged,expected,spec,
                                         source_context=lambda _:ctx)

    def test_real_triangle_budget_and_major_face_defects(self):
        fixture,ctx,scene=self.context()
        scene['blockout_triangle_budget']=1
        self.put(fixture,ctx,scene=scene)
        for rid in RULES:
            self.assertEqual(build_packet(ctx,rid)['rule']['result'],'FAIL')
        fixture,ctx,scene=self.context()
        scene['blockout_min_major_face_fraction']=0.95
        self.put(fixture,ctx,scene=scene)
        self.assertEqual(build_packet(ctx,RULES[0])['rule']['result'],'FAIL')

    def test_original_open_findings_and_missing_acceptance_fail(self):
        fixture,ctx,_=self.context()
        self.put(fixture,ctx,qa={'open_findings':['BAD_ALIGNMENT'],
                                  'passed_checks':CHECKS})
        self.assertEqual(build_packet(ctx,RULES[1])['rule']['result'],'FAIL')
        fixture,ctx,scene=self.context()
        scene['blockout_acceptance_criteria']=['triangle_budget']
        self.put(fixture,ctx,scene=scene)
        self.assertEqual(build_packet(ctx,RULES[1])['rule']['result'],'FAIL')

    def test_missing_original_pre_d_pin_is_unknown(self):
        fixture,ctx,_=self.context()
        fixture.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop(
            'P1_SCENE_CONTRACT')
        fixture.f.rebuild()
        ctx['controller']=fixture.f.controller
        for rid in RULES:
            self.assertEqual(build_packet(ctx,rid)['rule']['result'],'UNKNOWN')

    def test_original_tamper_and_cross_attempt_blocked(self):
        fixture,ctx,_=self.context()
        (fixture.f.root/'scene.glb').write_bytes(b'not original')
        with self.assertRaises(ValueError):
            build_packet(ctx,RULES[0])
        _,ctx,_=self.context()
        ctx['work']['attempt_id']='f'*64
        with self.assertRaises(ValueError):
            build_packet(ctx,RULES[1])

if __name__=='__main__':
    unittest.main()
