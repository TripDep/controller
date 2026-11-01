"""C07 five-rule coherent P3-P5 macro: source-positive and adversarial.

Only synthetic original-byte fixture tests. Independent MG0, owner approval
and actual FiveM compatibility remain UNKNOWN for every source-only PASS.
"""
import copy
import unittest
from test_c07_p345_remaining_original_review import RemainingP345Tests
from test_c07_p4_material_macro_full_review import P4MaterialMacroTests,POLICY
from test_c07_p3_uv_semantics import uv_glb
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import QUAD,NORMALS
from test_c07_p345_forty_native_evidence import encoded
from test_c07_p4_texture_semantics import png,solid
from c07_p345_five_macro_full_review import IDS,inspect
from c07_native_source_rule_replayers import (
  FULL_LITERAL_REVIEWED,build_packet,NATIVE_RULES,VALIDATORS,
  native_rule_readback,NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding

class FiveMacroOriginals(unittest.TestCase):
    def setup_source(self,rid):
        if rid.startswith('AAA-200-M'):
            fixture=P4MaterialMacroTests('test_all_seven_literal_rules_are_distinct_and_source_bound')
        else:
            fixture=RemainingP345Tests('test_positive_source_benefits_measured_not_promoted_to_full')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        test,ctx=fixture.context()
        return test,ctx

    def inspect(self,ctx,rid):
        return inspect(ctx,rid)

    def test_five_source_specific_full_macro_with_replayed_positive_native_evidence(self):
        self.assertEqual(len(IDS),5)
        self.assertEqual(len(IDS&FULL_LITERAL_REVIEWED),5)
        for rid in sorted(IDS):
            with self.subTest(rule=rid):
                test,ctx=self.setup_source(rid)
                measured=inspect(ctx,rid)
                self.assertTrue(measured['evidence_complete'],(rid,measured))
                self.assertTrue(all(measured['checks'].values()),(rid,measured))
                self.assertEqual(set(measured['checks']),set(NATIVE_RULES[rid][1]))
                packet=build_packet(ctx,rid)
                self.assertEqual(packet['rule']['result'],'PASS')
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                expected=binding(ctx['work'],ctx['inventory']['rules'][rid],rid)
                spec={'validator_id':VALIDATORS[rid],
                      'criteria':list(NATIVE_RULES[rid][1]),
                      'requirement_sha256':expected['requirement_sha256'],
                      'source_ref':'1'*40}
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

    def test_atlas_must_retain_original_surfaces_not_just_reduce_material_count(self):
        rid='AAA-200-L-118'
        test,ctx=self.setup_source(rid)
        fake=glb(QUAD,[(0,1,3),(1,2,3)],NORMALS)
        test.add('P3_ATLAS_BASELINE','atlas_baseline.glb',fake)
        test.sync()
        ctx['controller']=test.f.controller
        self.assertNotEqual(build_packet(ctx,rid)['rule']['result'],'PASS')

    def test_physical_class_pbr_cannot_be_labeled_wood_when_real_metallic(self):
        rid='AAA-200-M-121'
        test,ctx=self.setup_source(rid)
        bad=copy.deepcopy(POLICY)
        bad['physical_material_classes']['metal']['metallic']=[0.0,0.1]
        test.add('P4_MATERIAL_CONFORMANCE','p4_material_conformance.json',
                 encoded(bad))
        test.sync()
        ctx['controller']=test.f.controller
        self.assertEqual(build_packet(ctx,rid)['rule']['result'],'FAIL')

    def test_disconnected_uv_or_unreferenced_pbr_image_cannot_prove_variation(self):
        for rid in ('AAA-200-M-125','AAA-200-M-127'):
            with self.subTest(rule=rid):
                test,ctx=self.setup_source(rid)
                original=test.art['NATIVE_EXPORT']
                # Drop the TEXCOORD_0 accessor from real triangle primitives,
                # leaving the nice embedded PNG but no usable surface binding.
                from test_c07_p5_optimization_semantics import rewrite_glb
                def remove_uv(doc):
                    for mesh in doc['meshes']:
                        for primitive in mesh['primitives']:
                            primitive['attributes'].pop('TEXCOORD_0',None)
                test.add('NATIVE_EXPORT','scene.glb',rewrite_glb(original,remove_uv))
                test.sync()
                ctx['controller']=test.f.controller
                result=build_packet(ctx,rid)
                self.assertEqual(result['rule']['result'],'FAIL')

    def test_weathering_without_original_reference_is_not_full_semantics(self):
        rid='AAA-200-M-127'
        test,ctx=self.setup_source(rid)
        test.add('P4_WEATHERING_REFERENCE',
                 'p4_weathering_reference.png',png(solid(240)))
        test.sync()
        ctx['controller']=test.f.controller
        self.assertNotEqual(build_packet(ctx,rid)['rule']['result'],'PASS')

    def test_invisible_geometry_removal_must_preserve_each_unique_original_face(self):
        rid='AAA-200-O-143'
        test,ctx=self.setup_source(rid)
        test.add('P5_HIDDEN_BASELINE','hidden_before.glb',test.art['NATIVE_EXPORT'])
        test.sync()
        ctx['controller']=test.f.controller
        self.assertEqual(build_packet(ctx,rid)['rule']['result'],'FAIL')

    def test_original_pins_missing_remain_unknown_and_not_forged_pass(self):
        for rid,role in (('AAA-200-L-118','P3_ATLAS_BASELINE'),
                         ('AAA-200-M-121','P4_MATERIAL_CONFORMANCE'),
                         ('AAA-200-M-125','NATIVE_EXPORT'),
                         ('AAA-200-M-127','P4_WEATHERING_REFERENCE'),
                         ('AAA-200-O-143','P5_HIDDEN_BASELINE')):
            with self.subTest(rule=rid):
                test,ctx=self.setup_source(rid)
                ctx['plan']['p345_evidence_contract'][
                    'original_artifact_sha256'].pop(role)
                test.f.rebuild()
                ctx['controller']=test.f.controller
                self.assertNotEqual(build_packet(ctx,rid)['rule']['result'],'PASS')

if __name__=='__main__':
    unittest.main()
