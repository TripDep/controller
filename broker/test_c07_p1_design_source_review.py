"""13 P1 original-byte per-literal positive and adversarial source fixtures.

Fixture pixels/GLB are synthetic: NO independent artistic/owner/MG0 approval.
"""
import copy
import json
import struct
import unittest
import zlib
from pathlib import Path
from c07_p1_design_source_review import IDS,inspect,OriginalP1DesignBlocked
from test_c07_p1_thirty_native_domain import P1Thirty,encode
from test_c07_p5_optimization_semantics import rewrite_glb
from c07_positive_native_process import NativeEvidenceBlocked

def png_quadrants(values):
    def chunk(tag,data):
        return (struct.pack('>I',len(data))+tag+data+
                struct.pack('>I',zlib.crc32(tag+data)&0xffffffff))
    pixels=b''
    for y in range(4):
        pixels+=b'\x00'
        for x in range(4):
            value=values[(2 if y>=2 else 0)+(1 if x>=2 else 0)]
            pixels+=bytes((value,value,value,255))
    return (b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',
        struct.pack('>IIBBBBB',4,4,8,6,0,0,0))+
        chunk(b'IDAT',zlib.compress(pixels))+chunk(b'IEND',b''))

class P1DesignSourceTests(unittest.TestCase):
    def setUp(self):
        self.fixture=P1Thirty('test_exact_30_individual_P1_and_90_unique_predicates')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.scene=json.loads(self.fixture.contents['P1_SCENE_CONTRACT'][1])
        self.palette={'colors':['#141414','#dcdcdc']}
        self.qa={'open_findings':['BBOX_MISMATCH'],'owner_approved':False}
        self.scene.update({
            'style_luminance_tolerance':10,
            'style_quadrant_tolerance':10,
            'peer_luminance_tolerance':10,
            'peer_quadrant_tolerance':10,
            'palette_luminance_tolerance':40,
            'void_zones':[[[0.1,0.1],[0.2,0.1],[0.2,0.2],[0.1,0.2]]],
            'max_void_ratio':0.5,
            'silhouette_quadrant_tolerance':10,
            'focal_anchor':'gate','min_focal_luminance_delta':15,
            'max_repeated_quadrants':1,
            'min_material_unique_rgb':4,
            'min_material_variance':100,'max_material_variance':50000,
            'player_eye_tolerance_m':0.15,
            'player_camera':{'eye_xyz':[0.5,-2,1.75],
                             'target_xyz':[0.5,0.5,0.5]},
            'component_roles':['primary'],
            'component_role_mesh_map':{'primary':'primary_mesh'},
            'named_anchors':{'gate':[0.75,0.75,0.75],
                             'north':[0.1,0.1,0],
                             'south':[0.9,0.9,0]},
            'entrances':['north'],'exits':['south'],
            'min_entry_exit_separation_m':0.5,
            'cameras':{
                'front':{'eye_xyz':[0.5,-2,1.5],
                         'target_xyz':[0.5,0.5,0.5]},
                'left':{'eye_xyz':[-2,0.5,1.5],
                        'target_xyz':[0.5,0.5,0.5]},
                'right':{'eye_xyz':[2,0.5,1.5],
                         'target_xyz':[0.5,0.5,0.5]},
                'top':{'eye_xyz':[0.5,0.5,3],
                       'target_xyz':[0.5,0.5,0.5]},
            },
            'expected_bbox_local':{'min':[0,0,0],'max':[1.5,1,1]},
        })
        self.views={
            'VISUAL_VIEW_FRONT':[20,80,150,220],
            'VISUAL_VIEW_LEFT':[19,81,149,221],
            'VISUAL_VIEW_RIGHT':[18,82,148,222],
            'VISUAL_VIEW_TOP':[17,83,147,223],
            'REFERENCE_IMAGE':[21,81,151,219],
            'SCENE_PEER_REFERENCE':[22,82,152,218],
            'IMAGE_MATERIAL':[20,80,150,220],
        }
        original=self.fixture.contents['NATIVE_EXPORT'][1]
        self.native=rewrite_glb(original,
             lambda doc:doc['meshes'][0].update(name='primary_mesh'))
        self.install()
    def install(self):
        for role,values in self.views.items():
            self.fixture.put(role,role.lower()+'.png',png_quadrants(values))
        self.fixture.put('NATIVE_EXPORT','scene.glb',self.native)
        self.fixture.put('P1_SCENE_CONTRACT','p1_scene.json',encode(self.scene))
        self.fixture.put('P1_PALETTE','palette.json',encode(self.palette))
        self.fixture.put('P1_QA_REPORT','qa.json',encode(self.qa))
        self.fixture.rebuild()
    def examine(self):
        f=self.fixture.f
        return inspect(f.inv,f.plan,f.controller,f.asset,f.step,f.work,
                       source_loader=lambda path:Path(path).read_bytes())
    def test_thirteen_real_original_pixel_and_geometry_predicates(self):
        r=self.examine()
        self.assertEqual(r['family_rule_count'],30)
        self.assertEqual(r['rule_count'],13)
        self.assertEqual(set(r['rules']),set(IDS))
        self.assertEqual(r['source_observed_count'],13)
        self.assertEqual(r['full_semantic_passes'],0)
        self.assertEqual(r['individual_mg0_passes'],0)
        self.assertFalse(r['advancement_authorized'])
        for rid,row in r['rules'].items():
            with self.subTest(rule=rid):
                self.assertTrue(all(row['original_pixel_geometry_checks'].values()),
                                (rid,row['original_pixel_geometry_checks']))
                self.assertEqual(row['full_rule_semantics'],'UNKNOWN')
                self.assertEqual(row['individual_mg0'],'UNKNOWN')
    def test_each_of_thirteen_has_distinct_negative_semantic_mutation(self):
        changes={
            31:('scene','style_quadrant_tolerance',0),
            32:('scene','peer_quadrant_tolerance',0),
            33:('palette','colors',['#000000','#000001']),
            34:('scene','void_zones',[]),
            35:('scene','silhouette_quadrant_tolerance',0),
            36:('scene','min_focal_luminance_delta',250),
            37:('scene','max_repeated_quadrants',0),
            38:('scene','min_material_unique_rgb',100),
            39:('scene','player_camera',{'eye_xyz':[0,0,99],
                                       'target_xyz':[0.5,0.5,0.5]}),
            40:('scene','component_role_mesh_map',{'primary':'forged'}),
            46:('scene','min_entry_exit_separation_m',100),
            56:('scene','cameras',{'front':self.scene['cameras']['front'],
                                 'left':self.scene['cameras']['left'],
                                 'right':self.scene['cameras']['right'],
                                 'top':self.scene['cameras']['front']}),
            57:('qa','open_findings',['UNRELATED']),
        }
        for n,(target,key,bad) in changes.items():
            with self.subTest(rule=n):
                obj=getattr(self,target)
                old=copy.deepcopy(obj[key])
                obj[key]=bad
                self.install()
                rid=next(r for r in IDS if int(r[-3:])==n)
                row=self.examine()['rules'][rid]
                self.assertFalse(all(row['original_pixel_geometry_checks'].values()),
                                 (rid,row['original_pixel_geometry_checks']))
                self.assertEqual(row['full_rule_semantics'],'UNKNOWN')
                obj[key]=old
                self.install()
    def test_each_original_canonical_literal_tamper_is_blocked(self):
        for rid in IDS:
            with self.subTest(rule=rid):
                row=self.fixture.f.inv['rules'][rid]
                old=row['requirement']
                row['requirement']='forged positive'
                with self.assertRaisesRegex(OriginalP1DesignBlocked,'LITERAL_DRIFT'):
                    self.examine()
                row['requirement']=old
    def test_original_file_modified_after_registration_blocks(self):
        (self.fixture.f.root/'scene.glb').write_bytes(b'forged binary')
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    'REGISTERED_ARTIFACT_BYTES_CHANGED'):
            self.examine()
    def test_missing_pre_d_reference_sha_pin_is_not_positive(self):
        self.fixture.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop(
            'REFERENCE_IMAGE')
        self.fixture.f.rebuild()
        self.assertFalse(self.examine()['rules']['AAA-200-D-031'][
            'original_pixel_geometry_checks']['real_reference_front_luminance_recomputed'])
    def test_cross_attempt_replay_cannot_create_positive(self):
        self.fixture.f.work['attempt_id']='f'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.examine()

if __name__=='__main__':
    unittest.main()
