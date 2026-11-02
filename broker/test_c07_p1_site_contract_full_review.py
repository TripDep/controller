"""Positive/adversarial original-byte site and metric-coordinate rule tests."""
import copy
import json
import unittest

from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p1_thirty_native_domain import P1Thirty, encode
from c07_native_source_rule_replayers import (
    build_packet, NATIVE_RULES, VALIDATORS, native_rule_readback)
import supervisor_judgment as judgment

SITE='AAA-200-E-041'
COORD='AAA-200-E-042'

class SiteContractTests(unittest.TestCase):
    def context(self):
        fixture,ctx=NativeOriginalReplayerTests.context(
            self,P1Thirty,'test_exact_30_individual_P1_and_90_unique_predicates')
        scene=json.loads(fixture.contents['P1_SCENE_CONTRACT'][1])
        scene.update(
            available_site_dimensions_m=[1,1],
            meters_per_unit=1,
            native_to_world_axis_matrix=[[1,0,0],[0,1,0],[0,0,1]])
        fixture.put('P1_SCENE_CONTRACT','p1_scene.json',encode(scene))
        terrain={'samples_z':[0,1,2],
                 'survey_boundary_xy_m':[[0,0],[1,0],[1,1],[0,1]]}
        fixture.put('P1_TERRAIN_SAMPLES','terrain.json',encode(terrain))
        fixture.rebuild()
        ctx['controller']=fixture.f.controller
        return fixture,ctx,scene,terrain

    def replace(self,fixture,ctx,role,name,obj):
        fixture.put(role,name,encode(obj))
        fixture.rebuild()
        ctx['controller']=fixture.f.controller

    def check_positive(self,ctx,rid):
        packet=build_packet(ctx,rid)
        self.assertEqual(packet['rule']['result'],'PASS')
        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
        self.assertFalse(packet['mg0']['checks'].get('canonical_triggers_checked',True))
        expected=judgment.binding(ctx['work'],ctx['inventory']['rules'][rid],rid)
        spec={'validator_id':VALIDATORS[rid], 'criteria':list(NATIVE_RULES[rid][1]),
              'requirement_sha256':expected['requirement_sha256'],'source_ref':'1'*40}
        result=native_rule_readback(None,packet,expected,spec,
                                  source_context=lambda _:ctx)
        self.assertEqual(result['documentary_result'],'PASS')
        self.assertEqual(result['individual_rule_mg0'],'UNKNOWN')
        self.assertFalse(result['asset_advancement_authorized'])
        bad=copy.deepcopy(packet)
        bad['rule']['checks'][NATIVE_RULES[rid][1][0]]=False
        with self.assertRaisesRegex(ValueError,'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None,bad,expected,spec,source_context=lambda _:ctx)

    def test_positive_both_original_rule_replayers(self):
        _,ctx,_,_=self.context()
        for rid in (SITE,COORD):
            with self.subTest(rid=rid):self.check_positive(ctx,rid)

    def test_site_declared_dimensions_do_not_override_survey(self):
        f,ctx,scene,terrain=self.context()
        scene['available_site_dimensions_m']=[2,1]
        self.replace(f,ctx,'P1_SCENE_CONTRACT','p1_scene.json',scene)
        self.assertEqual(build_packet(ctx,SITE)['rule']['result'],'FAIL')
        scene['available_site_dimensions_m']=[1,1]
        self.replace(f,ctx,'P1_SCENE_CONTRACT','p1_scene.json',scene)
        terrain['survey_boundary_xy_m']=[[0,0],[0.5,0],[0.5,1],[0,1]]
        self.replace(f,ctx,'P1_TERRAIN_SAMPLES','terrain.json',terrain)
        self.assertEqual(build_packet(ctx,SITE)['rule']['result'],'FAIL')

    def test_site_self_crossing_or_missing_original_sha_is_not_pass(self):
        f,ctx,_,terrain=self.context()
        terrain['survey_boundary_xy_m']=[[0,0],[1,1],[0,1],[1,0]]
        self.replace(f,ctx,'P1_TERRAIN_SAMPLES','terrain.json',terrain)
        self.assertEqual(build_packet(ctx,SITE)['rule']['result'],'FAIL')
        f,ctx,_,_=self.context()
        f.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop(
            'P1_TERRAIN_SAMPLES')
        f.f.rebuild();ctx['controller']=f.f.controller
        self.assertEqual(build_packet(ctx,SITE)['rule']['result'],'UNKNOWN')

    def test_coordinate_mirror_or_invalid_origin_is_rejected(self):
        f,ctx,scene,_=self.context()
        scene['native_to_world_axis_matrix']=[[-1,0,0],[0,1,0],[0,0,1]]
        self.replace(f,ctx,'P1_SCENE_CONTRACT','p1_scene.json',scene)
        self.assertEqual(build_packet(ctx,COORD)['rule']['result'],'FAIL')
        scene['native_to_world_axis_matrix']=[[1,0,0],[0,1,0],[0,0,1]]
        scene['origin_xyz']=[0,'not-a-coordinate',0]
        self.replace(f,ctx,'P1_SCENE_CONTRACT','p1_scene.json',scene)
        self.assertEqual(build_packet(ctx,COORD)['rule']['result'],'FAIL')

    def test_original_geometry_and_attempt_integrity(self):
        f,ctx,_,_=self.context()
        (f.f.root/'scene.glb').write_bytes(b'forged native')
        with self.assertRaises(ValueError):
            build_packet(ctx,SITE)
        f,ctx,_,_=self.context()
        ctx['work']['attempt_id']='f'*64
        with self.assertRaises(ValueError):
            build_packet(ctx,COORD)

if __name__=='__main__':
    unittest.main()
