"""C07 E-046 complete P1 circulation original-byte semantic adversarial tests.

Measured site/route/access/camera geometry only; never an engine or MG0 PASS.
"""
import copy
import json
import unittest

import supervisor_judgment as judgment
from c07_p1_circulation_full_review import (
    inspect as inspect_circulation, RULE, CRITERIA)
from c07_native_source_rule_replayers import (
    build_packet, native_rule_readback, NATIVE_RULES, VALIDATORS)
from c07_native_replayer_dispatch import replay
from test_c07_p1_paths_access_full_review import PathAccessFullReviewTests
from test_c07_p1_thirty_native_domain import encode
from test_c07_p3_geometry_semantics import glb


class FullEntranceExitSemantics(unittest.TestCase):
    def setUp(self):
        base=PathAccessFullReviewTests('test_both_source_specific_positive_and_independent_consumer_replay')
        self.base=base
        test,ctx,doc=PathAccessFullReviewTests.context(self)
        self.t,self.ctx,self.paths=test,ctx,doc
        self.policy={
            'schema':'c07-p1-visual-metrics-pre-d-v1',
            'entry_exit_xy':{'entrance':[0,0], 'exit':[0.5,1]},
            'player_eye_height_m':1.75,
            'max_entry_exit_view_angle_deg':75,
            'player_camera':{
                'position_xyz':[0.25,-2,1.75],
                'target_xyz':[0.25,0.5,1.75],
            },
        }
        self.scene=json.loads(test.contents['P1_SCENE_CONTRACT'][1])
        self.refresh()

    def refresh(self):
        self.t.put('P1_PATHS_GEOJSON','paths.json',encode(self.paths))
        self.t.put('P1_VISUAL_METRICS_POLICY','circulation-policy.json',
                   encode(self.policy))
        self.t.put('P1_SCENE_CONTRACT','p1_scene.json',encode(self.scene))
        self.t.rebuild()
        self.ctx['controller']=self.t.f.controller
        self.ctx['plan']=self.t.f.plan

    def expected(self):
        return judgment.binding(
            self.ctx['work'],self.ctx['inventory']['rules'][RULE],RULE)

    def spec(self):
        return {'validator_id':VALIDATORS[RULE],
                'criteria':list(NATIVE_RULES[RULE][1]),
                'requirement_sha256':self.expected()['requirement_sha256'],
                'source_ref':'1'*40}

    def assert_source_fail(self,key):
        result=inspect_circulation(self.ctx,RULE)
        self.assertTrue(result['evidence_complete'])
        self.assertFalse(result['checks'][key],result['checks'])
        packet=build_packet(self.ctx,RULE)
        self.assertEqual(packet['rule']['result'],'FAIL')
        self.assertFalse(packet['mg0']['result']=='PASS')
        self.assertFalse(packet['rule']['result']=='PASS')

    def test_complete_entrance_exit_family_native_replay_positive_without_mg0(self):
        row=inspect_circulation(self.ctx,RULE)
        self.assertEqual(set(row['checks']),set(CRITERIA))
        self.assertTrue(row['evidence_complete'])
        self.assertTrue(all(row['checks'].values()),row['checks'])
        packet=build_packet(self.ctx,RULE)
        self.assertEqual(packet['rule']['result'],'PASS')
        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
        expected=self.expected()
        full=replay(None,packet,expected,self.spec(),
                    source_context=lambda _:self.ctx)
        self.assertEqual(full['documentary_result'],'PASS')
        self.assertFalse(full['advancement_authorized'])
        self.assertFalse(full['asset_advancement_authorized'])
        forged=copy.deepcopy(packet)
        forged['rule']['checks'][CRITERIA[2]]=False
        with self.assertRaisesRegex(ValueError,'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None,forged,expected,self.spec(),
                                 source_context=lambda _:self.ctx)

    def test_not_any_plan_entrance_counts_as_original_path_endpoint(self):
        self.policy['entry_exit_xy']['exit']=[0.3,0.8]
        self.refresh()
        self.assert_source_fail(CRITERIA[1])

    def test_accessible_polygon_is_not_forged_from_path_labels(self):
        self.paths['zones'][0]['allowed_actors']=['vehicle']
        self.refresh()
        self.assert_source_fail(CRITERIA[1])

    def test_separate_zones_and_disconnected_main_path_rejected(self):
        self.paths['features'][1]['geometry']['coordinates']=[
            [0.9,0.6],[0.5,1]]
        self.refresh()
        self.assert_source_fail(CRITERIA[1])

    def test_actual_native_wall_occludes_both_camera_lines(self):
        ground=[(0,0,0),(1,0,0),(0,1,0)]
        wall=[(-1,-0.5,1.3),(1,-0.5,1.3),(0,-0.5,2.2)]
        raw=glb(ground+wall,[(0,1,2),(3,4,5)])
        self.t.put('NATIVE_EXPORT','scene.glb',raw)
        self.refresh()
        self.assert_source_fail(CRITERIA[2])

    def test_camera_aimed_away_does_not_prove_sightline(self):
        self.policy['player_camera']['target_xyz']=[0.25,-3,1.75]
        self.refresh()
        self.assert_source_fail(CRITERIA[2])

    def test_pre_d_camera_or_entrance_contract_missing_not_pass(self):
        self.policy.pop('max_entry_exit_view_angle_deg')
        self.refresh()
        self.assert_source_fail(CRITERIA[0])

    def test_changed_original_bytes_without_matching_registered_sha_not_pass(self):
        original=self.t.f.root/'circulation-policy.json'
        original.write_bytes(b'{"entry_exit_xy":{"entrance":[0,0]}}')
        with self.assertRaises((ValueError,OSError,AssertionError)):
            build_packet(self.ctx,RULE)

    def test_missing_pinned_original_is_unknown_not_positive(self):
        self.t.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop(
            'P1_VISUAL_METRICS_POLICY')
        self.t.f.rebuild()
        row=inspect_circulation(self.ctx,RULE)
        self.assertFalse(row['evidence_complete'])
        self.assertFalse(any(row['checks'].values()))
        self.assertEqual(build_packet(self.ctx,RULE)['rule']['result'],'UNKNOWN')

    def test_cross_attempt_producer_packet_not_accepted(self):
        packet=build_packet(self.ctx,RULE)
        forged=copy.deepcopy(packet)
        forged['binding']['attempt_id']='f'*64
        with self.assertRaisesRegex(ValueError,
                                    'ATTEMPT_OPERATION_SOURCE_MISMATCH'):
            build_packet(self.ctx,RULE,expected=forged['binding'])


if __name__=='__main__':
    unittest.main()
