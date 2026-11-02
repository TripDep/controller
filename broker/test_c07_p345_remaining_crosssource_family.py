"""All fourteen residual P3-P5 cross-source readers: real original-byte adversaries.

Fixtures are synthetic and NEVER attest independent renderer, engine or MG0.
"""
import unittest
from test_c07_p345_remaining_original_review import RemainingP345Tests
from test_c07_p345_forty_native_evidence import encoded
from test_c07_p4_texture_semantics import png,solid
from c07_p345_remaining_crosssource_family import (
    inspect_family,IDS,ROLES,NUMBERS)
from c07_native_source_rule_replayers import FULL_LITERAL_REVIEWED
from test_c07_positive_native_process import sha

class RemainingFourteenCrossSourceTests(unittest.TestCase):
    def setUp(self):
        self.t=RemainingP345Tests('test_positive_source_benefits_measured_not_promoted_to_full')
        self.t.setUp()
        self.addCleanup(self.t.doCleanups)
        self.test,self.ctx=self.t.context()
        extra={
            'P4_MATERIAL_CONFORMANCE':('material.json',encoded({
                'light_response':{'min_direct_neutral_delta':5,
                                  'min_neutral_shadow_delta':5},
                'rage_shader_target':'normal_spec.sps',
                'material_shader_map':{'metal':'normal_spec.sps'}})),
            'P4_NATIVE_DRAWABLE_XML':('drawable.xml',
                b'<Drawable><Shaders><Item><Name>normal_spec.sps</Name></Item></Shaders></Drawable>'),
            'P4_LIGHTING_QA':('lighting.json',encoded({
                'modes':['neutral','cinematic'],'neutral_lux':400,
                'player_eye_height_m':1.6})),
            'P4_MATERIAL_PLAN':('materialplan.json',encoded({'roles':['metal','glass']})),
            'P4_PLAYER_CAMERA':('camera.json',encoded({
                'camera_xyz':[0,-2,1.6],'forward_xyz':[0,1,0]})),
            'VISUAL_PLAYER_VIEW':('player.png',png(solid(110))),
            'P345_QA_REPORT':('qa.json',encoded({
                'underside_qa_sha256':sha(self.test.art['VISUAL_VIEW_UNDERSIDE'])})),
            'P4_VIEW_NEUTRAL':('p4neutral.png',png(solid(90))),
            'P4_VIEW_DIRECT':('p4direct.png',png(solid(180))),
            'P4_VIEW_SHADOW':('p4shadow.png',png(solid(30))),
        }
        for role,(name,raw) in extra.items():
            self.test.add(role,name,raw)
        self.test.sync()
        self.ctx['controller']=self.test.f.controller

    def test_fourteen_exact_original_source_predicates_not_full(self):
        r=inspect_family(self.ctx)
        self.assertEqual(r['rule_count'],14)
        self.assertEqual(set(r['rules']),set(IDS))
        self.assertEqual(len(set(IDS)),14)
        self.assertEqual(set(IDS)&set(FULL_LITERAL_REVIEWED),set())
        self.assertEqual(r['full_semantic_passes'],0)
        self.assertFalse(r['advancement_authorized'])
        for rid,row in r['rules'].items():
            with self.subTest(rule=rid):
                self.assertTrue(row['source_pins_complete'],rid)
                self.assertIs(type(row['original_literal_measurement']),bool)
                self.assertEqual(row['external_provenance'],'UNKNOWN')
                self.assertEqual(row['individual_mg0'],'UNKNOWN')
                self.assertFalse(row['advancement_authorized'])

    def test_every_literal_original_pin_tamper_fails_closed(self):
        for n,rid in zip(NUMBERS,IDS):
            with self.subTest(rule=rid):
                t=RemainingP345Tests('test_positive_source_benefits_measured_not_promoted_to_full')
                t.setUp()
                self.addCleanup(t.doCleanups)
                test,ctx=t.context()
                role=ROLES[n][0]
                self.assertIn(role,test.f.plan['p345_evidence_contract']['original_artifact_sha256'])
                test.f.plan['p345_evidence_contract']['original_artifact_sha256'].pop(role)
                test.f.rebuild()
                ctx['controller']=test.f.controller
                result=inspect_family(ctx)
                row=result['rules'][rid]
                self.assertFalse(row['source_pins_complete'])
                self.assertFalse(row['original_literal_measurement'])
                self.assertEqual(row['external_provenance'],'UNKNOWN')

    def test_measured_material_light_triplet_and_frame_budget(self):
        result=inspect_family(self.ctx)
        for rid in ('AAA-200-M-122','AAA-200-O-150'):
            self.assertTrue(result['rules'][rid]['original_literal_measurement'],rid)
        self.assertFalse(result['rules']['AAA-200-M-130']['original_literal_measurement'])
        self.assertEqual(result['rules']['AAA-200-O-150']['fivem_runtime'],'UNKNOWN')

    def test_reflection_requires_real_glass_as_well_as_metal(self):
        result=inspect_family(self.ctx)
        self.assertFalse(result['rules']['AAA-200-N-136']['original_literal_measurement'])
        self.assertTrue(result['rules']['AAA-200-N-136']['source_pins_complete'])

    def test_capture_event_not_a_renderer_attestation(self):
        result=inspect_family(self.ctx)
        for n in (131,132,133,134,135,136,137,139,140):
            rid='AAA-200-N-%03d'%n
            self.assertEqual(result['rules'][rid]['external_provenance'],'UNKNOWN')
        self.assertEqual(result['original_measured_count'],
                         sum(x['original_literal_measurement']
                             for x in result['rules'].values()))

if __name__=='__main__':
    unittest.main()
