"""F-058 source-specific world connection: real mesh edges, not just labels."""
import copy
import unittest

import supervisor_judgment as judgment
from c07_native_source_rule_replayers import (
    NATIVE_RULES,VALIDATORS,build_packet,native_rule_readback)
from c07_native_replayer_dispatch import replay
from test_c07_p1_spatial_full_review import P1SpatialNativeTests
from test_c07_p1_thirty_native_domain import encode

RID='AAA-200-F-058'

class ConnectionEdgeTests(unittest.TestCase):
    def context(self):
        test,ctx,scene=P1SpatialNativeTests.context(self)
        scene['building_world_placements']['secondary']={
            'translation_xyz':[1,0,0],'yaw_deg':180,
            'scale_xyz':[1,1,1]}
        scene['module_connection_edges']=[{
            'primary_edge_xyz':[[0,0,0],[1,0,0]],
            'secondary_edge_xyz':[[0,0,0],[1,0,0]],
            'max_gap_m':0.01,'min_shared_length_m':0.9}]
        self.update(test,ctx,scene)
        return test,ctx,scene

    def update(self,test,ctx,scene):
        test.put('P1_SCENE_CONTRACT','p1_scene.json',encode(scene))
        test.rebuild()
        ctx['controller']=test.f.controller

    def test_positive_original_shared_edge_opposite_sides(self):
        _,ctx,_=self.context()
        packet=build_packet(ctx,RID)
        self.assertEqual(packet['rule']['result'],'PASS')
        self.assertTrue(all(packet['rule']['checks'].values()))
        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
        expected=judgment.binding(ctx['work'],ctx['inventory']['rules'][RID],RID)
        spec={'validator_id':VALIDATORS[RID],
              'criteria':list(NATIVE_RULES[RID][1]),
              'requirement_sha256':expected['requirement_sha256'],
              'source_ref':'1'*40}
        result=replay(None,packet,expected,spec,source_context=lambda _:ctx)
        self.assertEqual(result['documentary_result'],'PASS')
        self.assertFalse(result['advancement_authorized'])
        forged=copy.deepcopy(packet)
        forged['rule']['checks'][NATIVE_RULES[RID][1][2]]=False
        with self.assertRaisesRegex(ValueError,'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None,forged,expected,spec,
                                 source_context=lambda _:ctx)

    def test_world_edge_gap_detected(self):
        test,ctx,scene=self.context()
        scene['building_world_placements']['secondary']['translation_xyz']=[
            1.2,0,0]
        self.update(test,ctx,scene)
        self.assertEqual(build_packet(ctx,RID)['rule']['result'],'FAIL')

    def test_identical_overlapping_modules_are_not_adjacency(self):
        test,ctx,scene=self.context()
        scene['building_world_placements']['secondary']={
            'translation_xyz':[0,0,0],'yaw_deg':0,'scale_xyz':[1,1,1]}
        self.update(test,ctx,scene)
        self.assertEqual(build_packet(ctx,RID)['rule']['result'],'FAIL')

    def test_forged_edge_not_present_in_original_triangle(self):
        test,ctx,scene=self.context()
        scene['module_connection_edges'][0]['primary_edge_xyz'][0]=[0.25,0,0]
        self.update(test,ctx,scene)
        packet=build_packet(ctx,RID)
        self.assertEqual(packet['rule']['result'],'FAIL')
        self.assertFalse(packet['rule']['checks'][NATIVE_RULES[RID][1][1]])

    def test_missing_pre_d_source_pin_unknown(self):
        test,ctx,_=self.context()
        test.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop(
            'SECONDARY_EXPORT')
        test.f.rebuild()
        ctx['controller']=test.f.controller
        self.assertEqual(build_packet(ctx,RID)['rule']['result'],'UNKNOWN')

    def test_original_glb_tamper_and_attempt_change_rejected(self):
        test,ctx,_=self.context()
        (test.f.root/'other.glb').write_bytes(b'not original')
        with self.assertRaises(ValueError):
            build_packet(ctx,RID)
        _,ctx,_=self.context()
        ctx['work']['attempt_id']='f'*64
        with self.assertRaises(ValueError):
            build_packet(ctx,RID)


if __name__=='__main__':
    unittest.main()
