"""C07 L119 + O147 original-byte texture baking and reuse macro.

Synthetic acceptance plus corrupted texture, changed UV surface, missing pin
and producer packet forgery regressions. No MG0 or runtime PASS.
"""
import json
import unittest
from test_c07_p345_remaining_original_review import RemainingP345Tests
from test_c07_p5_full_review import two_material_bindings
from test_c07_p345_forty_native_evidence import encoded
from test_c07_p4_texture_semantics import png,solid,gradient
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import QUAD,NORMALS
from c07_p345_bake_reuse_macro_full_review import RULES,L,O,inspect
from c07_native_source_rule_replayers import build_packet,NATIVE_RULES,FULL_LITERAL_REVIEWED

class BakeReuseOriginalSourceTests(unittest.TestCase):
    def setUp(self):
        self.fx=RemainingP345Tests('test_positive_source_benefits_measured_not_promoted_to_full')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.test,self.ctx=self.fx.context()
        self.budget=json.loads(self.test.art['P5_PERF_BUDGET'].decode())
        self.budget['max_reuse_rgb_delta']=0
        self.before=two_material_bindings(self.test.art['NATIVE_EXPORT'])
        self.refresh()

    def refresh(self):
        self.test.add('P5_REUSE_BASELINE','reuse_baseline.glb',self.before)
        self.test.add('P5_PERF_BUDGET','perf.json',encoded(self.budget))
        self.test.sync()
        self.ctx['controller']=self.test.f.controller

    def row(self,rid):
        return inspect(self.ctx,rid)

    def test_both_exact_originals_reconstruct_positive_semantics(self):
        self.assertEqual(len(RULES),2)
        for rid in (L,O):
            with self.subTest(rid=rid):
                result=self.row(rid)
                self.assertTrue(result['evidence_complete'])
                self.assertTrue(all(result['checks'].values()),result)
                packet=build_packet(self.ctx,rid)
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                self.assertEqual(packet['rule']['result'],
                    'PASS' if rid in FULL_LITERAL_REVIEWED else 'UNKNOWN')

    def test_grayscale_photo_renamed_normal_map_is_not_a_baked_normal(self):
        self.test.add('P3_BAKED_NORMAL','baked_normal.png',png(gradient()))
        self.refresh()
        self.assertFalse(self.row(L)['checks'][NATIVE_RULES[L][1][2]])

    def test_missing_source_bake_policy_is_unknown(self):
        self.ctx['plan']['p345_evidence_contract'][
            'original_artifact_sha256'].pop('P3_BAKE_POLICY')
        self.test.f.rebuild();self.ctx['controller']=self.test.f.controller
        self.assertFalse(self.row(L)['evidence_complete'])

    def test_reuse_without_actual_shared_native_primitive_is_rejected(self):
        native=self.test.art['NATIVE_EXPORT']
        from test_c07_p5_optimization_semantics import rewrite_glb
        def remove_shared(doc):
            doc['meshes'][0]['primitives']=doc['meshes'][0]['primitives'][:1]
        self.test.add('NATIVE_EXPORT','scene.glb',rewrite_glb(native,remove_shared))
        self.refresh()
        self.assertFalse(self.row(O)['checks'][NATIVE_RULES[O][1][1]])

    def test_reuse_with_changed_source_geometry_cannot_claim_no_quality_loss(self):
        self.before=glb(QUAD,[(0,1,3),(0,3,2)],NORMALS)
        self.refresh()
        self.assertFalse(self.row(O)['checks'][NATIVE_RULES[O][1][2]])

    def test_reuse_with_unacceptable_original_color_difference_is_rejected(self):
        from test_c07_p5_budget_semantics import with_embedded_texture
        from test_c07_p3_uv_semantics import uv_glb
        from test_c07_p4_texture_semantics import material
        from test_c07_p5_optimization_semantics import rewrite_glb
        bad=with_embedded_texture(uv_glb(with_texture=False),
                                  png(solid(30)))
        self.before=two_material_bindings(rewrite_glb(bad,material))
        self.refresh()
        self.assertFalse(self.row(O)['checks'][NATIVE_RULES[O][1][2]])

    def test_no_source_reuse_baseline_pin_is_not_positive(self):
        self.ctx['plan']['p345_evidence_contract'][
            'original_artifact_sha256'].pop('P5_REUSE_BASELINE')
        self.test.f.rebuild();self.ctx['controller']=self.test.f.controller
        self.assertFalse(self.row(O)['evidence_complete'])

if __name__=='__main__':
    unittest.main()
