"""Original-byte positive and rule-specific adversarial P1 residual family tests.

A fixture with all thirteen measurable predicates true is NOT proof of style,
artistic quality, actual camera provenance, MG0, or owner approval.
"""
import copy
import json
import unittest
from pathlib import Path

from test_c07_p1_thirty_native_domain import P1Thirty, encode
from test_c07_p4_texture_semantics import png, gradient, solid
from test_c07_p5_optimization_semantics import rewrite_glb
from test_c07_positive_native_process import canonical, sha
from c07_p1_remaining_visual_review import IDS, inspect
from c07_native_source_rule_replayers import FULL_LITERAL_REVIEWED
from c07_native_replayer_dispatch import REPLAYERS

def image():
    return png(gradient())

def policy():
    return {
        'schema':'c07-p1-visual-metrics-pre-d-v1',
        'max_style_rgb_distance':5,
        'max_peer_rgb_distance':5,
        'palette_rgb':[[v,v,v] for v in sorted({
            20+30*y+10*x for y in range(4) for x in range(4)})],
        'max_palette_rgb_distance':5,
        'void_polygon_xy':[[2,2],[3,2],[3,3],[2,3]],
        'max_void_triangle_fraction':0.1,
        'min_silhouette_iou':0.99,
        'focal_xy':[1,1],
        'min_focal_luma_contrast':10,
        'max_repeated_row_fraction':0.2,
        'min_distinct_material_rgb':8,
        'player_eye_height_m':1.75,
        'player_camera':{'position_xyz':[0.5,-2,1.75],
                         'target_xyz':[0.5,0.5,0.5]},
        'component_mesh_names':['blockout'],
        'entry_exit_xy':{'entrance':[0,0],'exit':[1,1]},
    }

class P1ResidualFamilyTests(unittest.TestCase):
    def setUp(self):
        self.t=P1Thirty('test_exact_30_individual_P1_and_90_unique_predicates')
        self.t.setUp()
        self.addCleanup(self.t.doCleanups)
        self.p=policy()
        self.raw=image()
        self.t.put('NATIVE_EXPORT','scene.glb',rewrite_glb(
            self.t.contents['NATIVE_EXPORT'][1],
            lambda doc:doc['meshes'][0].update({'name':'blockout'})))
        for role in ('VISUAL_VIEW_FRONT','REFERENCE_IMAGE',
                     'SCENE_PEER_REFERENCE','IMAGE_MATERIAL'):
            self.t.put(role,role.lower()+'.png',self.raw)
        self.t.put('VISUAL_VIEW_TOP','visual_view_top.png',png(solid(70)))
        self.scene=json.loads(self.t.contents['P1_SCENE_CONTRACT'][1])
        self.refresh()

    def refresh(self,*,qa_event=True):
        self.t.put('P1_VISUAL_METRICS_POLICY','p1_visual_policy.json',
                   encode(self.p))
        self.t.put('P1_SCENE_CONTRACT','p1_scene.json',encode(self.scene))
        self.t.rebuild()
        if qa_event:
            f=self.t.f
            event={'asset':f.asset,'event':'BLOCKOUT_QA',
                   'prev_hash':f.records[-1]['record_hash'],
                   'step':f.step,'attempt_id':f.work['attempt_id'],
                   'operation_sha256':f.work['operation_sha256']}
            event['record_hash']=sha(canonical(event))
            f.records.append(event)
            f.controller.audit_path(f.asset).write_bytes(
                b''.join(canonical(row)+b'\n' for row in f.records))
            f.controller._state['last_audit_hash']=event['record_hash']

    def ctx(self):
        f=self.t.f
        return {'inventory':f.inv,'plan':f.plan,'controller':f.controller,
                'asset':f.asset,'step':f.step,'work':f.work,
                'source_loader':lambda p:Path(p).read_bytes()}

    def read(self,rid):
        return inspect(self.ctx(),rid)

    def test_all_thirteen_distinct_real_original_measurements_positive(self):
        self.assertEqual(len(IDS),13)
        for rid in IDS:
            with self.subTest(rule=rid):
                r=self.read(rid)
                self.assertTrue(all(r['checks'].values()),(rid,r['checks']))
                self.assertEqual(r['full_rule_semantics'],'UNKNOWN')
                self.assertEqual(r['individual_mg0'],'UNKNOWN')
                self.assertFalse(r['advancement_authorized'])
                # E046 has its separate full original-geometry consumer;
                # these 13 residual metrics remain diagnostics, not MG0.
                if rid=='AAA-200-E-046':
                    self.assertIn(rid,FULL_LITERAL_REVIEWED)
                    self.assertIn(rid,REPLAYERS)
                else:
                    self.assertNotIn(rid,FULL_LITERAL_REVIEWED)
                    self.assertNotIn(rid,REPLAYERS)

    def test_all_thirteen_literal_specific_adversarial_original_changes(self):
        for rid in IDS:
            with self.subTest(rule=rid):
                t=P1ResidualFamilyTests('test_all_thirteen_distinct_real_original_measurements_positive')
                t.setUp()
                try:
                    n=int(rid[-3:])
                    if n==31:
                        t.t.put('REFERENCE_IMAGE','reference_image.png',png(solid(200)))
                    elif n==32:
                        t.t.put('SCENE_PEER_REFERENCE','scene_peer_reference.png',png(solid(200)))
                    elif n==33:
                        t.p['palette_rgb']=[[0,0,0]]
                    elif n==34:
                        t.p['void_polygon_xy']=[[-1,-1],[2,-1],[2,2],[-1,2]]
                    elif n==35:
                        t.t.put('REFERENCE_IMAGE','reference_image.png',png(solid(200)))
                    elif n==36:
                        t.p['focal_xy']=[0,0]
                    elif n==37:
                        t.t.put('VISUAL_VIEW_FRONT','visual_view_front.png',png(solid(50)))
                    elif n==38:
                        t.t.put('IMAGE_MATERIAL','image_material.png',png(solid(60)))
                    elif n==39:
                        t.p['player_camera']['position_xyz'][2]=8
                    elif n==40:
                        t.p['component_mesh_names']=['invented_mesh']
                    elif n==46:
                        t.p['entry_exit_xy']['exit']=[9,9]
                    elif n==56:
                        t.t.put('VISUAL_VIEW_TOP','visual_view_top.png',t.raw)
                    elif n==57:
                        pass
                    t.refresh(qa_event=n!=57)
                    result=t.read(rid)
                    self.assertTrue(result['checks'][
                        'pre_d_policy_and_current_original_bytes_reopened'])
                    self.assertFalse(result['checks'][
                        'rule_specific_original_measurement_within_pre_d_contract'],
                        (rid,result['checks']))
                    self.assertEqual(result['individual_mg0'],'UNKNOWN')
                finally:
                    t.doCleanups()

    def test_original_binary_tamper_cannot_be_repaired_by_policy_labels(self):
        self.assertTrue(all(self.read(IDS[0])['checks'].values()))
        Path(self.t.f.items['NATIVE_EXPORT']['path']).write_bytes(b'forged')
        with self.assertRaises(ValueError):
            self.read(IDS[0])

if __name__=='__main__':
    unittest.main()
