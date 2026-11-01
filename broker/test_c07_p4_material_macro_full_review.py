"""Seven P4 original-material semantics; one five-class source-decidable.

Positive/negative original GLB+PNG evidence, producer replay, audit pinning.
No fixture grants actual MG0/owner/FiveM PASS or renderer/RAGE authenticity.
"""
import copy
import json
import unittest

from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p345_forty_native_evidence import P345Forty, encoded
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import with_embedded_texture, QUAD, NORMALS
from test_c07_p5_optimization_semantics import rewrite_glb
from test_c07_p4_texture_semantics import (
    png, gradient, solid, material)
from c07_p4_material_macro_full_review import (
    RULES, DECIDABLE, CRITERIA, inspect)
from c07_native_source_rule_replayers import (
    build_packet, NATIVE_RULES, FULL_LITERAL_REVIEWED,
    VALIDATORS, native_rule_readback, NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding, semantic_packet

def normalize_base():
    return rewrite_glb(with_embedded_texture(
        glb(QUAD,[(0,1,2),(0,2,3)],NORMALS),
        png(gradient())), material)

def five_materials(doc):
    physical = {
        'wood':(0.8,0.05,[0.4,0.2,0.1,1.0]),
        'stone':(0.7,0.0,[0.5,0.5,0.5,1.0]),
        'metal':(0.2,0.9,[0.7,0.7,0.7,1.0]),
        'glass':(0.05,0.0,[0.6,0.8,0.9,0.4]),
        'plaster':(0.95,0.0,[0.9,0.85,0.7,1.0]),
    }
    template=copy.deepcopy(doc['materials'][0])
    primitive=copy.deepcopy(doc['meshes'][0]['primitives'][0])
    doc['materials']=[]
    doc['meshes'][0]['primitives']=[]
    for idx,(name,(rough,metal,color)) in enumerate(physical.items()):
        m=copy.deepcopy(template)
        m['name']=name
        m['pbrMetallicRoughness']['roughnessFactor']=rough
        m['pbrMetallicRoughness']['metallicFactor']=metal
        m['pbrMetallicRoughness']['baseColorFactor']=color
        m['alphaMode']='BLEND' if name=='glass' else 'OPAQUE'
        doc['materials'].append(m)
        p=copy.deepcopy(primitive)
        p['material']=idx
        doc['meshes'][0]['primitives'].append(p)

def shifted():
    return png([[(r+10,g+10,b+10,a) for r,g,b,a in row]
                for row in gradient()])

POLICY={
    'physical_material_classes':{
        'wood':{'roughness':[0.75,0.85],'metallic':[0.0,0.1]},
        'stone':{'roughness':[0.6,0.8],'metallic':[0.0,0.15]},
        'metal':{'roughness':[0.1,0.3],'metallic':[0.8,1.0]},
        'glass':{'roughness':[0.0,0.1],'metallic':[0.0,0.1]},
        'plaster':{'roughness':[0.9,1.0],'metallic':[0.0,0.1]}},
    'material_to_class':{n:n for n in
        ('wood','stone','metal','glass','plaster')},
    'surface_variation':{'min_distinct_rgb':10,
        'min_quadrant_luma_delta':10,
        'min_variance':40,'max_variance':20000},
    'light_response':{'min_direct_neutral_delta':20,
                      'min_neutral_shadow_delta':20},
    'weathering':{'max_reference_mean_delta':25,
                  'min_texture_local_delta':10},
    'rage_shader_target':'GTA5_NATIVE_RAGE',
}

class P4MaterialMacroTests(unittest.TestCase):
    def context(self):
        test, ctx = NativeOriginalReplayerTests.context(
            self, P345Forty, 'test_p4_30_due_and_p5_40_due')
        test.f.plan['phase'] = 'P4'
        test.f.work['phase'] = 'P4'
        test.add('NATIVE_EXPORT','scene.glb',
                 rewrite_glb(normalize_base(),five_materials))
        test.add('P4_MATERIAL_CONFORMANCE','p4_material_conformance.json',
                 encoded(POLICY))
        test.add('P4_WEATHERING_REFERENCE','p4_weathering_reference.png',
                 shifted())
        for role, light in (('P4_VIEW_NEUTRAL',90),
                            ('P4_VIEW_DIRECT',180),
                            ('P4_VIEW_SHADOW',30)):
            test.add(role,role.lower()+'.png',png(solid(light)))
        test.sync()
        ctx['controller']=test.f.controller
        return test, ctx

    def packet(self,ctx,rid):
        row=ctx['inventory']['rules'][rid]
        expected=binding(ctx['work'],row,rid)
        packet=build_packet(ctx,rid,expected=expected)
        spec={'validator_id':VALIDATORS[rid],
              'criteria':list(NATIVE_RULES[rid][1]),
              'requirement_sha256':expected['requirement_sha256'],
              'source_ref':'1'*40,
              'issuer':{'workflow_blob':'a'*40,'public_sha':'b'*40}}
        return packet,expected,spec

    def test_whole_M121_to_M130_macro_has_exact_gate(self):
        all_ten={'AAA-200-M-%03d' % i for i in range(121,131)}
        self.assertEqual(set(NATIVE_RULES)&all_ten, all_ten)
        enrolled=set(FULL_LITERAL_REVIEWED)&all_ten
        self.assertEqual(enrolled,
                         {'AAA-200-M-123','AAA-200-M-124',
                          'AAA-200-M-126','AAA-200-M-128'})
        self.assertEqual(len(enrolled),4)
        self.assertEqual(set(NATIVE_RULES)&set(RULES),set(RULES))

    def test_all_seven_literal_rules_are_distinct_and_source_bound(self):
        self.assertEqual(len(RULES),7)
        self.assertEqual(len(DECIDABLE),1)
        self.assertEqual(set(CRITERIA),{121,122,125,126,127,129,130})
        self.assertEqual(len({x for row in CRITERIA.values() for x in row}),21)
        test,ctx=self.context()
        for rid in sorted(RULES):
            with self.subTest(rule=rid):
                packet,expected,spec=self.packet(ctx,rid)
                self.assertEqual(set(packet['rule']['checks']),
                                 set(NATIVE_RULES[rid][1]))
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                self.assertFalse(packet['mg0']['checks'].get(
                    'canonical_triggers_checked',True))
                self.assertEqual(
                    packet['rule']['result'],
                    'PASS' if rid in DECIDABLE else 'UNKNOWN')
                self.assertEqual(rid in FULL_LITERAL_REVIEWED,rid in DECIDABLE)
                self.assertEqual(semantic_packet(packet,expected,spec)['result'],
                                 'UNKNOWN')
                if rid in DECIDABLE:
                    readback=replay(None,packet,expected,spec,
                                    source_context=lambda _:ctx)
                    self.assertEqual(readback['documentary_result'],'PASS')
                    self.assertEqual(readback['individual_rule_mg0'],'UNKNOWN')
                    self.assertFalse(readback['advancement_authorized'])

    def test_five_class_replayer_rejects_producer_digest_forgery(self):
        _,ctx=self.context()
        for rid in sorted(DECIDABLE):
            with self.subTest(rule=rid):
                packet,expected,spec=self.packet(ctx,rid)
                forged=copy.deepcopy(packet)
                forged['rule']['proof_digest']='f'*64
                with self.assertRaisesRegex(
                        NativeRuleEvidenceBlocked,
                        'PRODUCER_PACKET_NOT_RECOMPUTED'):
                    native_rule_readback(None,forged,expected,spec,
                                         source_context=lambda _:ctx)

    def test_every_original_material_class_uses_actual_pbr(self):
        test,ctx=self.context()
        policy=copy.deepcopy(POLICY)
        policy['physical_material_classes']['stone']['roughness']=[0.1,0.2]
        test.add('P4_MATERIAL_CONFORMANCE','p4_material_conformance.json',
                 encoded(policy))
        test.sync()
        ctx['controller']=test.f.controller
        packet,_,_=self.packet(ctx,'AAA-200-M-121')
        self.assertEqual(packet['rule']['result'],'UNKNOWN')
        self.assertFalse(packet['rule']['checks'][
            'all_actual_original_roughness_and_metallic_values_in_physical_class_ranges'])

    def test_source_original_light_contradiction_is_failure(self):
        test,ctx=self.context()
        test.add('P4_VIEW_DIRECT','p4_view_direct.png',png(solid(60)))
        test.sync()
        ctx['controller']=test.f.controller
        packet,_,_=self.packet(ctx,'AAA-200-M-122')
        self.assertEqual(packet['rule']['result'],'UNKNOWN')
        self.assertFalse(packet['rule']['checks'][
            'real_original_direct_neutral_shadow_pixels_follow_source_bounds'])

    def test_flat_original_texture_rejects_variation_and_weathering(self):
        test,ctx=self.context()
        native=rewrite_glb(with_embedded_texture(
            glb(QUAD,[(0,1,2),(0,2,3)],NORMALS),
            png(solid(110))),material)
        test.add('NATIVE_EXPORT','scene.glb',native)
        test.sync()
        ctx['controller']=test.f.controller
        for rid in ('AAA-200-M-125','AAA-200-M-127'):
            with self.subTest(rule=rid):
                packet,_,_=self.packet(ctx,rid)
                self.assertEqual(packet['rule']['result'],'UNKNOWN')
                self.assertFalse(all(packet['rule']['checks'].values()))

    def test_five_class_original_missing_or_out_of_range_is_real_fail(self):
        test,ctx=self.context()
        packet,_,_=self.packet(ctx,'AAA-200-M-126')
        self.assertEqual(packet['rule']['result'],'PASS')
        policy=copy.deepcopy(POLICY)
        policy['physical_material_classes']['metal']['metallic']=[0.0,0.1]
        test.add('P4_MATERIAL_CONFORMANCE','p4_material_conformance.json',
                 encoded(policy))
        test.sync()
        ctx['controller']=test.f.controller
        packet,_,_=self.packet(ctx,'AAA-200-M-126')
        self.assertEqual(packet['rule']['result'],'FAIL')
        self.assertFalse(packet['rule']['checks'][
            'five_original_materials_have_distinct_physical_pbr_and_alpha_properties'])

    def test_missing_original_policy_pin_is_unknown(self):
        test,ctx=self.context()
        test.f.plan['p345_evidence_contract']['original_artifact_sha256'].pop(
            'P4_MATERIAL_CONFORMANCE')
        test.f.rebuild()
        ctx['controller']=test.f.controller
        packet,_,_=self.packet(ctx,'AAA-200-M-125')
        self.assertEqual(packet['rule']['result'],'UNKNOWN')

    def test_cross_attempt_or_original_byte_tamper_never_pass(self):
        test,ctx=self.context()
        ctx['work']['attempt_id']='f'*64
        with self.assertRaises(ValueError):
            self.packet(ctx,'AAA-200-M-121')
        test,ctx=self.context()
        (test.f.root/'scene.glb').write_bytes(b'forged glb')
        with self.assertRaises(ValueError):
            self.packet(ctx,'AAA-200-M-122')

    def test_shader_and_renderer_claims_remain_unknown_even_with_policy(self):
        _,ctx=self.context()
        for rid in ('AAA-200-M-129','AAA-200-M-130'):
            with self.subTest(rule=rid):
                packet,expected,spec=self.packet(ctx,rid)
                self.assertEqual(packet['rule']['result'],'UNKNOWN')
                self.assertNotIn(rid,DECIDABLE)
                self.assertNotIn(rid,FULL_LITERAL_REVIEWED)
                with self.assertRaisesRegex(ValueError,'NOT_WHITELISTED'):
                    replay(None,packet,expected,spec,source_context=lambda _:ctx)

if __name__=='__main__':
    unittest.main()
