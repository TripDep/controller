"""O149 original vegetation/transparency alpha budget positive/adversarial tests."""
import copy
import unittest
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p5_optimization_semantics import (
    Tests as OptimizationFixture,rewrite_glb)
from test_c07_positive_native_process import sha
from c07_p5_alpha_cost_full_review import RULE,CRITERIA
from c07_native_source_rule_replayers import (
    NATIVE_RULES,FULL_LITERAL_REVIEWED,VALIDATORS,build_packet,
    native_rule_readback,NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding,semantic_packet
import json

POLICY={'material_roles':{'0':'vegetation','1':'transparent'},
        'max_cost':{'vegetation_triangles':2,'transparent_triangles':2,
                    'vegetation_draws':1,'transparent_draws':1,
                    'rgba_bytes':65536}}

def alpha_scene(doc):
    first=doc['meshes'][0]['primitives'][0]
    second=copy.deepcopy(first)
    second['material']=1
    doc['meshes'][0]['primitives'].append(second)
    other=copy.deepcopy(doc['materials'][0])
    other['alphaMode']='BLEND'
    doc['materials'].append(other)

class AlphaCostFullReviewTests(unittest.TestCase):
    def context(self,policy=None,*,change_shader=False):
        test,ctx=NativeOriginalReplayerTests.context(
            self,OptimizationFixture,
            'test_four_scoped_positive_observations_and_runtime_unknown')
        test.native=rewrite_glb(test.native,alpha_scene)
        if change_shader:
            def opaque(doc):doc['materials'][1]['alphaMode']='OPAQUE'
            test.native=rewrite_glb(test.native,opaque)
        test.put()
        doc=copy.deepcopy(POLICY if policy is None else policy)
        doc['native_sha256']=sha(test.native)
        test.f.add_item('P5_ALPHA_COST_POLICY','p5_alpha_cost_policy.json',
                        json.dumps(doc,sort_keys=True).encode())
        test.f.plan['p345_evidence_contract']['original_artifact_sha256'][
            'P5_ALPHA_COST_POLICY']=test.f.items['P5_ALPHA_COST_POLICY']['sha256']
        test.f.rebuild()
        ctx['controller']=test.f.controller
        return test,ctx

    def packet(self,ctx):
        expected=binding(ctx['work'],ctx['inventory']['rules'][RULE],RULE)
        packet=build_packet(ctx,RULE,expected=expected)
        spec={'validator_id':VALIDATORS[RULE],
              'criteria':list(NATIVE_RULES[RULE][1]),
              'requirement_sha256':expected['requirement_sha256'],
              'source_ref':'1'*40,
              'issuer':{'workflow_blob':'a'*40,'public_sha':'b'*40}}
        return packet,expected,spec

    def test_original_vegetation_and_transparency_cost_positive_unknown_mg0(self):
        _,ctx=self.context()
        self.assertIn(RULE,FULL_LITERAL_REVIEWED)
        self.assertEqual(NATIVE_RULES[RULE][1],CRITERIA)
        packet,expected,spec=self.packet(ctx)
        self.assertEqual(packet['rule']['result'],'PASS')
        self.assertTrue(all(packet['rule']['checks'].values()))
        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
        self.assertEqual(replay(None,packet,expected,spec,
            source_context=lambda _:ctx)['documentary_result'],'PASS')
        self.assertEqual(semantic_packet(packet,expected,spec)['result'],'UNKNOWN')
        forged=copy.deepcopy(packet)
        forged['rule']['proof_digest']='f'*64
        with self.assertRaisesRegex(
            NativeRuleEvidenceBlocked,'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None,forged,expected,spec,
                                 source_context=lambda _:ctx)

    def test_actual_transparency_triangle_budget_exceeded(self):
        policy=copy.deepcopy(POLICY)
        policy['max_cost']['transparent_triangles']=1
        _,ctx=self.context(policy)
        self.assertEqual(self.packet(ctx)[0]['rule']['result'],'FAIL')

    def test_unclassified_original_alpha_material_is_not_complete(self):
        policy=copy.deepcopy(POLICY)
        policy['material_roles'].pop('1')
        _,ctx=self.context(policy)
        self.assertNotEqual(self.packet(ctx)[0]['rule']['result'],'PASS')

    def test_unexpected_original_opaque_material_is_not_alpha_cost(self):
        _,ctx=self.context(change_shader=True)
        self.assertNotEqual(self.packet(ctx)[0]['rule']['result'],'PASS')

    def test_missing_pre_d_pin_never_positive(self):
        test,ctx=self.context()
        test.f.plan['p345_evidence_contract']['original_artifact_sha256'].pop(
            'P5_ALPHA_COST_POLICY')
        test.f.rebuild()
        ctx['controller']=test.f.controller
        self.assertNotEqual(self.packet(ctx)[0]['rule']['result'],'PASS')

    def test_wrong_attempt_and_tampered_original_bytes_blocked(self):
        _,ctx=self.context()
        ctx['work']['attempt_id']='f'*64
        with self.assertRaises(ValueError):build_packet(ctx,RULE)
        test,ctx=self.context()
        (test.f.root/'scene.glb').write_bytes(b'forged')
        with self.assertRaises(ValueError):build_packet(ctx,RULE)

if __name__=='__main__':
    unittest.main()
