"""Adversarial current-operation S182/S187 original-byte replayer tests."""
import copy
import unittest
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p678_forty_native_domain import P678Forty, encode
from test_c07_native_output_oracle import two_triangles
from test_c07_positive_native_process import sha, canonical
from c07_p8_final_process_full_review import SPATIAL, RECHECK, CRITERIA
from c07_native_source_rule_replayers import (
    NATIVE_RULES, FULL_LITERAL_REVIEWED, VALIDATORS, build_packet,
    native_rule_readback, NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding, semantic_packet

POSE={'translation_xyz':[0,0,0],'yaw_deg':0,'scale_xyz':[1,1,1]}
OTHER={'translation_xyz':[1,0,0],'yaw_deg':0,'scale_xyz':[1,1,1]}
SPATIAL_POLICY={
    'component_roles':['NATIVE_EXPORT','SECONDARY_EXPORT'],
    'placements':{'NATIVE_EXPORT':POSE,'SECONDARY_EXPORT':OTHER},
    'world_bounds':{'NATIVE_EXPORT':[[0,0,0],[1,1,1]],
                    'SECONDARY_EXPORT':[[1,0,0],[2,1,1]]},
    'forward_anchor_vertices':{
        'NATIVE_EXPORT':[[0,0,0],[1,0,0]],
        'SECONDARY_EXPORT':[[0,0,0],[1,0,0]]},
    'expected_forward_world':{
        'NATIVE_EXPORT':[1,0,0],'SECONDARY_EXPORT':[1,0,0]},
    'native_to_world_axis_matrix':[[1,0,0],[0,1,0],[0,0,1]],
    'meters_per_unit':1,'max_bounds_error_m':0.01,
    'max_forward_error_deg':2,
    'alignment_pairs':[{'a':'NATIVE_EXPORT','b':'SECONDARY_EXPORT',
        'a_vertex_xyz':[1,0,0],'b_vertex_xyz':[0,0,0],
        'max_gap_m':0.01}],
    'dimension_ratios':[{'a':'NATIVE_EXPORT','b':'SECONDARY_EXPORT',
        'axis':0,'min_ratio':0.99,'max_ratio':1.01}],
}
REGRESSION_POLICY={
    'corrections':{'C1':{'before_role':'BASELINE_SNAPSHOT',
                         'after_role':'NATIVE_EXPORT'}},
    'required_checks':['no_degenerate','no_duplicate',
                       'minimum_triangles','bounds_shift'],
    'max_bounds_shift_m':2,'minimum_final_triangles':2,
}

class FinalProcessFullReviewTests(unittest.TestCase):
    def context(self,spatial_policy=None,regression_policy=None,
                *,include_recheck=True,change_geometry=False):
        test,ctx=NativeOriginalReplayerTests.context(
            self,P678Forty,'test_phase_P6_10_rules_due_P7_20_P8_40')
        test.f.plan['phase']=test.f.work['phase']='P8'
        test.add('SECONDARY_EXPORT','secondary.glb',two_triangles())
        test.add('P8_SPATIAL_POLICY','p8_spatial_policy.json',
                 encode(SPATIAL_POLICY if spatial_policy is None
                        else spatial_policy))
        test.add('P8_REGRESSION_POLICY','p8_regression_policy.json',
                 encode(REGRESSION_POLICY if regression_policy is None
                        else regression_policy))
        if change_geometry:
            from test_c07_p3_geometry_semantics import glb
            test.add('NATIVE_EXPORT','scene.glb',
                     glb([(0,0,0),(1,0,0),(2,0,0)],[(0,1,2)],
                         [(0,0,1)]*3))
        test.sync()
        ctx['controller']=test.f.controller
        self.events(test,include_recheck)
        return test,ctx

    def events(self,test,include_recheck):
        f=test.f
        before=f.items['BASELINE_SNAPSHOT']['sha256']
        after=f.items['NATIVE_EXPORT']['sha256']
        def add(name,**values):
            row=dict(asset=f.asset,event=name,step=f.step,
                     attempt_id=f.work['attempt_id'],
                     operation_sha256=f.work['operation_sha256'],
                     prev_hash=f.records[-1]['record_hash'],**values)
            row['record_hash']=sha(canonical(row))
            f.records.append(row)
        add('CORRECTION_APPLIED',correction_id='C1',
            before_role='BASELINE_SNAPSHOT',after_role='NATIVE_EXPORT',
            before_sha256=before,after_sha256=after)
        if include_recheck:
            add('QA_RECHECK',correction_id='C1',result='PASS',
                after_sha256=after,
                check_ids=list(REGRESSION_POLICY['required_checks']))
        f.controller.audit_path(f.asset).write_bytes(
            b''.join(canonical(row)+b'\n' for row in f.records))
        f.controller._state['last_audit_hash']=f.records[-1]['record_hash']

    def packet(self,ctx,rid):
        expected=binding(ctx['work'],ctx['inventory']['rules'][rid],rid)
        packet=build_packet(ctx,rid,expected=expected)
        spec={'validator_id':VALIDATORS[rid],
              'criteria':list(NATIVE_RULES[rid][1]),
              'requirement_sha256':expected['requirement_sha256'],
              'source_ref':'1'*40,
              'issuer':{'workflow_blob':'a'*40,'public_sha':'b'*40}}
        return packet,expected,spec

    def test_original_spatial_and_recheck_positive_unknown_mg0(self):
        _,ctx=self.context()
        for rid in (SPATIAL,RECHECK):
            with self.subTest(rule=rid):
                self.assertIn(rid,FULL_LITERAL_REVIEWED)
                self.assertEqual(NATIVE_RULES[rid][1],CRITERIA[rid])
                packet,expected,spec=self.packet(ctx,rid)
                self.assertEqual(packet['rule']['result'],'PASS')
                self.assertTrue(all(packet['rule']['checks'].values()))
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                self.assertEqual(replay(None,packet,expected,spec,
                    source_context=lambda _:ctx)['documentary_result'],'PASS')
                self.assertEqual(semantic_packet(packet,expected,spec)['result'],
                                 'UNKNOWN')
                forged=copy.deepcopy(packet)
                forged['rule']['proof_digest']='f'*64
                with self.assertRaisesRegex(
                    NativeRuleEvidenceBlocked,'PRODUCER_PACKET_NOT_RECOMPUTED'):
                    native_rule_readback(None,forged,expected,spec,
                                         source_context=lambda _:ctx)

    def test_spatial_original_world_bounds_mismatch(self):
        policy=copy.deepcopy(SPATIAL_POLICY)
        policy['world_bounds']['SECONDARY_EXPORT'][1][0]=7
        _,ctx=self.context(spatial_policy=policy)
        self.assertEqual(self.packet(ctx,SPATIAL)[0]['rule']['result'],'FAIL')

    def test_spatial_forward_alignment_and_ratio_negative(self):
        for name in ('forward','alignment','ratio','axis_swap'):
            policy=copy.deepcopy(SPATIAL_POLICY)
            if name=='forward':
                policy['expected_forward_world']['NATIVE_EXPORT']=[-1,0,0]
            elif name=='alignment':
                policy['placements']['SECONDARY_EXPORT']['translation_xyz']=[1.1,0,0]
                policy['world_bounds']['SECONDARY_EXPORT']=[[1.1,0,0],[2.1,1,1]]
            elif name=='axis_swap':
                policy['native_to_world_axis_matrix']=[[0,-1,0],[1,0,0],[0,0,1]]
            else:
                policy['dimension_ratios'][0]['max_ratio']=0.5
            with self.subTest(name=name):
                _,ctx=self.context(spatial_policy=policy)
                self.assertNotEqual(self.packet(ctx,SPATIAL)[0]['rule']['result'],
                                    'PASS')

    def test_missing_recheck_event_never_passes(self):
        _,ctx=self.context(include_recheck=False)
        self.assertNotEqual(self.packet(ctx,RECHECK)[0]['rule']['result'],'PASS')

    def test_unpinned_and_incomplete_regression_policy_never_pass(self):
        policy=copy.deepcopy(REGRESSION_POLICY)
        policy['required_checks']=['no_degenerate']
        _,ctx=self.context(regression_policy=policy)
        self.assertNotEqual(self.packet(ctx,RECHECK)[0]['rule']['result'],'PASS')
        test,ctx=self.context()
        test.f.plan['p678_evidence_contract']['original_artifact_sha256'].pop(
            'P8_REGRESSION_POLICY')
        test.f.rebuild()
        ctx['controller']=test.f.controller
        self.assertNotEqual(self.packet(ctx,RECHECK)[0]['rule']['result'],'PASS')

    def test_degenerate_after_correction_cannot_pass(self):
        _,ctx=self.context(change_geometry=True)
        self.assertNotEqual(self.packet(ctx,RECHECK)[0]['rule']['result'],'PASS')

    def test_cross_attempt_and_original_tamper_block(self):
        _,ctx=self.context()
        ctx['work']['attempt_id']='f'*64
        with self.assertRaises(ValueError):
            build_packet(ctx,RECHECK)
        test,ctx=self.context()
        (test.f.root/'scene.glb').write_bytes(b'forged')
        with self.assertRaises(ValueError):
            build_packet(ctx,SPATIAL)

if __name__=='__main__':
    unittest.main()
