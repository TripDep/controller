"""C07 F056 five-view original-native geometry and raster adversarial tests.

These fixtures prove the ray-projection reader's correctness, NOT engine or MG0.
"""
import copy
import json
import unittest
from pathlib import Path
from test_c07_p1_thirty_native_domain import P1Thirty,encode
from test_c07_p3_geometry_semantics import glb
from test_c07_p4_texture_semantics import png,solid
from c07_p1_five_camera_native_review import RULE,CRITERIA,inspect,hit

VIEWS=('FRONT','REAR','LEFT','RIGHT','TOP')

class FiveOriginalCameraViews(unittest.TestCase):
    def setUp(self):
        self.fx=P1Thirty('test_exact_30_individual_P1_and_90_unique_predicates')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.mesh=glb([(0,0,0),(1,0,0),(0,1,0),(0,0,1)],
            [(0,2,1),(0,1,3),(0,3,2),(1,2,3)],
            [(0,0,1)]*4)
        c=[.5,.5,.5]
        offset={'FRONT':[0,-3,0],'REAR':[0,3,0],
                'LEFT':[-3,0,0],'RIGHT':[3,0,0],'TOP':[0,0,3]}
        self.policy={'schema':'c07-p1-five-native-views-pre-d-v1',
            'max_axis_deviation_deg':15,
            'min_visible_projected_area_m2':.001,
            'cameras':{v:{
              'position_xyz':[c[i]+d[i] for i in range(3)],
              'target_xyz':c[:]} for v,d in offset.items()}}
        self.rasters={v:png(solid(18+32*i)) for i,v in enumerate(VIEWS)}
        self.refresh()

    def refresh(self):
        self.fx.put('NATIVE_EXPORT','scene.glb',self.mesh)
        self.fx.put('P1_FIVE_VIEW_INSPECTION_POLICY','p1_views.json',
                    encode(self.policy))
        for v,raw in self.rasters.items():
            self.fx.put('VISUAL_VIEW_'+v,v.lower()+'.png',raw)
        self.fx.rebuild()

    def ctx(self):
        f=self.fx.f
        return {'inventory':f.inv,'plan':f.plan,'controller':f.controller,
            'asset':f.asset,'step':f.step,'work':f.work,
            'source_loader':lambda p:Path(p).read_bytes()}

    def read(self):return inspect(self.ctx(),RULE)

    def test_five_actual_original_camera_projections_positive(self):
        row=self.read()
        self.assertTrue(row['evidence_complete'])
        self.assertTrue(all(row['checks'].values()),row)
        self.assertEqual(len(row['native_camera_projection_report']),5)
        self.assertGreater(row['native_camera_projection_report'][
            'TOP']['projected_area_m2'],.001)
        self.assertFalse(row['advancement_authorized'])
        self.assertEqual(row['fivem_runtime'],'UNVERIFIED')

    def test_forged_five_labels_with_same_pose_rejected(self):
        self.policy['cameras']['TOP']=copy.deepcopy(
            self.policy['cameras']['FRONT'])
        self.refresh()
        self.assertFalse(self.read()['checks'][CRITERIA[1]])

    def test_missing_original_top_view_rejected(self):
        self.fx.contents.pop('VISUAL_VIEW_TOP')
        self.fx.f.items.pop('VISUAL_VIEW_TOP',None)
        self.fx.rebuild()
        self.assertFalse(self.read()['evidence_complete'])

    def test_duplicate_decoded_pixels_rejected_even_different_filenames(self):
        self.rasters['REAR']=self.rasters['FRONT']
        self.refresh()
        self.assertTrue(self.read()['checks'][CRITERIA[1]])
        self.assertFalse(self.read()['checks'][CRITERIA[2]])

    def test_all_flat_triangle_geometry_cannot_prove_side_view(self):
        self.mesh=glb([(0,0,0),(1,0,0),(0,1,0)],
                      [(0,1,2)],[(0,0,1)]*3)
        self.refresh()
        self.assertFalse(self.read()['checks'][CRITERIA[1]])

    def test_duplicate_triangle_occlusion_not_counted_as_unique_visibility(self):
        tri=[[0,0,0],[1,0,0],[0,1,0]]
        self.assertTrue(hit([.2,.2,-1],[.2,.2,1],tri))
        self.assertFalse(hit([.2,.2,0],[.2,.2,1],tri))

    def test_deviating_pre_d_camera_axis_fails(self):
        self.policy['cameras']['RIGHT']['position_xyz']=[.5,-3,.5]
        self.refresh()
        self.assertFalse(self.read()['checks'][CRITERIA[1]])

    def test_original_native_bytes_mutation_rejected_by_operation(self):
        Path(self.fx.f.items['NATIVE_EXPORT']['path']).write_bytes(b'not-glb')
        with self.assertRaises(ValueError):self.read()

    def test_absent_pre_d_camera_sha_is_not_a_pass(self):
        self.fx.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop(
            'P1_FIVE_VIEW_INSPECTION_POLICY')
        self.fx.f.rebuild()
        row=self.read()
        self.assertFalse(row['evidence_complete'])
        self.assertFalse(any(row['checks'].values()))

if __name__=='__main__':
    unittest.main()
