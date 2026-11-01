"""P8 S184/S185/S186 integrated macro, with corrupted-source negatives.

The synthetic original image and native GLB fixtures establish source-level
verifier functionality, never artistic/FiveM/MG0 correctness.
"""
import copy
import unittest

from test_c07_p8_six_views_full_review import P8SixViewsTests
from test_c07_p3_uv_semantics import uv_glb
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import with_embedded_texture
from test_c07_p4_texture_semantics import png,gradient,material
from test_c07_p5_optimization_semantics import rewrite_glb
from test_c07_p678_forty_native_domain import encode
from test_c07_positive_native_process import sha
from c07_p8_three_final_quality_macro import RULES,CRITERIA,inspect
from c07_native_source_rule_replayers import (
    NATIVE_RULES,build_packet,FULL_LITERAL_REVIEWED)

VIEWS=('FRONT','REAR','LEFT','RIGHT','TOP','UNDERSIDE')
def image(i):
    return png([[(20+24*i+3*x+5*y,)*3+(255,)
        for x in range(4)] for y in range(4)])

class FinalThreeSemanticTests(unittest.TestCase):
    def setUp(self):
        self.h=P8SixViewsTests(
            'test_six_original_views_qa_and_controller_events_positive_unknown_mg0')
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.test,self.ctx=self.h.context()
        self.native=rewrite_glb(with_embedded_texture(
            uv_glb(with_texture=False),png(gradient())),material)
        self.env=glb([(-2,-2,0),(2,-2,0),(2,2,0),(-2,2,0)],
                     [(0,1,2),(0,2,3)],[(0,0,1)]*4)
        self.policy={
            'schema':'gg-c07-p8-three-final-source-v1',
            'max_surface_defects':0,
            'max_material_reference_mean_delta':25,
            'min_material_variance':10,
            'asset_anchor_xyz':[.5,.5,0],
            'environment_anchor_xyz':[0,0,0],
            'max_anchor_distance_m':.1,
            'max_asset_to_environment_span_ratio':.5}
        self.defects={'native_sha256':sha(self.native),
                      'per_view_surface_defects':{v:0 for v in VIEWS}}
        self.refresh()

    def refresh(self):
        t=self.test
        t.add('NATIVE_EXPORT','scene.glb',self.native)
        t.add('P8_FINAL_SURFACE_POLICY','p8_final_quality.json',
              encode(self.policy))
        t.add('P8_NORMALS_REPORT','p8_normals_report.json',
              encode({'native_sha256':sha(self.native)}))
        self.defects['native_sha256']=sha(self.native)
        t.add('P8_SURFACE_DEFECT_MATRIX','p8_surface_matrix.json',
              encode(self.defects))
        t.add('P8_ENVIRONMENT_REFERENCE','environment.glb',self.env)
        t.add('P8_MATERIAL_REFERENCE','p8_material_reference.png',
              png(gradient()))
        t.add('P8_MATERIAL_RENDER','p8_material_render.png',
              image(2))
        t.add('P8_AREA_CONTEXT','p8_area_context.png',image(3))
        for i,v in enumerate(VIEWS):
            t.add('VISUAL_VIEW_'+v,v.lower()+'.png',image(i))
        self.h.refresh(t,self.ctx)
        self.ctx['controller']=t.f.controller

    def row(self,rid):
        return inspect(self.ctx,rid)

    def test_all_three_original_source_qa_cases(self):
        self.assertEqual(len(RULES),3)
        for rid in RULES:
            with self.subTest(rid=rid):
                result=self.row(rid)
                self.assertTrue(result['evidence_complete'],result)
                self.assertTrue(all(result['checks'].values()),result)
                self.assertEqual(result['checks'].keys(),dict.fromkeys(CRITERIA[rid]).keys())
                self.assertFalse(result['advancement_authorized'])
                self.assertEqual(result['fivem_runtime'],'UNVERIFIED')
                packet=build_packet(self.ctx,rid)
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                self.assertEqual(packet['rule']['result'],
                                 'PASS' if rid in FULL_LITERAL_REVIEWED
                                 else 'UNKNOWN')

    def test_reversed_or_degenerate_face_normals_rejected(self):
        self.native=rewrite_glb(self.native,lambda d: d['meshes'][0][
            'primitives'][0].update(attributes=dict(
                d['meshes'][0]['primitives'][0]['attributes'],
                NORMAL=d['meshes'][0]['primitives'][0]['attributes']['POSITION'])))
        self.refresh()
        self.assertFalse(self.row('AAA-200-S-184')['checks'][
            CRITERIA['AAA-200-S-184'][1]])

    def test_forged_clean_qa_matrix_not_enough_with_original_mesh_defect(self):
        # A forged report with zero failures cannot override corrupted geometry.
        self.native=glb([(0,0,0),(1,0,0),(0,1,0)],
                        [(0,1,1)],[(0,0,1)]*3)
        self.refresh()
        self.assertFalse(self.row('AAA-200-S-184')['checks'][
            CRITERIA['AAA-200-S-184'][1]])

    def test_missing_original_camera_audit_events_rejected(self):
        self.test.sync()
        self.ctx['controller']=self.test.f.controller
        self.assertFalse(self.row('AAA-200-S-184')['checks'][
            CRITERIA['AAA-200-S-184'][0]])

    def test_wrong_material_roughness_rejected(self):
        def bad(doc):
            doc['materials'][0]['pbrMetallicRoughness']['roughnessFactor']=4.
        self.native=rewrite_glb(self.native,bad)
        self.refresh()
        self.assertFalse(self.row('AAA-200-S-185')['checks'][
            CRITERIA['AAA-200-S-185'][1]])

    def test_texture_table_without_active_uv_rejected(self):
        def remove(doc):
            doc['meshes'][0]['primitives'][0]['attributes'].pop('TEXCOORD_0')
        self.native=rewrite_glb(self.native,remove)
        self.refresh()
        self.assertFalse(self.row('AAA-200-S-185')['checks'][
            CRITERIA['AAA-200-S-185'][1]])

    def test_impossible_original_material_reference_tolerance_rejected(self):
        self.policy['max_material_reference_mean_delta']=0
        self.refresh()
        self.test.add('P8_MATERIAL_REFERENCE','p8_material_reference.png',image(5))
        self.h.refresh(self.test,self.ctx)
        self.assertFalse(self.row('AAA-200-S-185')['checks'][
            CRITERIA['AAA-200-S-185'][2]])

    def test_environment_reference_disconnected_asset_rejected(self):
        self.env=glb([(100,100,0),(104,100,0),(104,104,0),(100,104,0)],
                     [(0,1,2),(0,2,3)],[(0,0,1)]*4)
        self.refresh()
        self.assertFalse(self.row('AAA-200-S-186')['checks'][
            CRITERIA['AAA-200-S-186'][1]])

    def test_context_capture_identical_to_front_not_environment_qa(self):
        self.test.add('P8_AREA_CONTEXT','p8_area_context.png',image(0))
        self.h.refresh(self.test,self.ctx)
        self.assertFalse(self.row('AAA-200-S-186')['checks'][
            CRITERIA['AAA-200-S-186'][2]])

    def test_missing_sha_pinned_source_cannot_give_full(self):
        for rid,role in [('AAA-200-S-184','P8_SURFACE_DEFECT_MATRIX'),
                         ('AAA-200-S-185','P8_MATERIAL_REFERENCE'),
                         ('AAA-200-S-186','P8_ENVIRONMENT_REFERENCE')]:
            with self.subTest(rid=rid):
                self.refresh()
                self.ctx['plan']['p678_evidence_contract'][
                    'original_artifact_sha256'].pop(role)
                self.test.f.rebuild()
                self.ctx['controller']=self.test.f.controller
                result=self.row(rid)
                self.assertFalse(result['evidence_complete'])
                self.assertFalse(all(result['checks'].values()))

if __name__=='__main__':
    unittest.main()
