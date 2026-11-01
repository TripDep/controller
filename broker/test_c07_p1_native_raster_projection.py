"""Eleven P1 native GLB raster oracles: real pixel positives and adversaries.

Fixtures are SYNTHETIC and NEVER certify a production asset, owner or MG0.
"""
import copy
import json
import struct
import unittest
import zlib
from pathlib import Path
from c07_p1_native_raster_projection import (
    inspect_family,mask_from_triangles,IDS,VIEWS)
from test_c07_p1_thirty_native_domain import P1Thirty,encode
from c07_positive_native_process import NativeEvidenceBlocked

TRI=[[[0.,0.,0.],[1.,0.,.5],[0.,1.,1.]]]
def native_glb():
    coords=struct.pack('<9f',*(x for p in TRI[0] for x in p))
    doc={'asset':{'version':'2.0'},'buffers':[{'byteLength':len(coords)}],
         'bufferViews':[{'buffer':0,'byteOffset':0,'byteLength':len(coords)}],
         'meshes':[{'primitives':[{'attributes':{'POSITION':0},'mode':4}]}],
         'accessors':[{'bufferView':0,'byteOffset':0,'count':3,
                       'type':'VEC3','componentType':5126}]}
    raw=json.dumps(doc,separators=(',',':')).encode()
    raw+=b' '*(-len(raw)%4)
    return (struct.pack('<4sII',b'glTF',2,12+8+len(raw)+8+len(coords))+
            struct.pack('<I4s',len(raw),b'JSON')+raw+
            struct.pack('<I4s',len(coords),b'BIN\x00')+coords)
def png(mask,w,h,base):
    raw=bytearray()
    for y in range(h):
        raw.append(0)
        for x in range(w):
            v=(base if (x+y)%2 else base+20) if mask[y*w+x] else 0
            raw.extend((v,v,v))
    def chunk(tag,payload):
        return (struct.pack('>I',len(payload))+tag+payload+
                struct.pack('>I',zlib.crc32(tag+payload)&0xffffffff))
    return (b'\x89PNG\r\n\x1a\n'+
            chunk(b'IHDR',struct.pack('>IIBBBBB',w,h,8,2,0,0,0))+
            chunk(b'IDAT',zlib.compress(bytes(raw)))+chunk(b'IEND',b''))

class NativeRasterFamily(unittest.TestCase):
    def setUp(self):
        self.t=P1Thirty('test_exact_30_individual_P1_and_90_unique_predicates')
        self.t.setUp()
        self.addCleanup(self.t.doCleanups)
        self.t.put('NATIVE_EXPORT','scene.glb',native_glb())
        self.w=self.h=24
        self.images={}
        for i,role in enumerate(VIEWS):
            m=mask_from_triangles(TRI,role,self.w,self.h)
            raw=png(m,self.w,self.h,190+i*5)
            self.images[role]=raw
            self.t.put('VISUAL_VIEW_'+role,role.lower()+'.png',raw)
        self.t.put('REFERENCE_IMAGE','reference_image.png',self.images['FRONT'])
        self.t.put('SCENE_PEER_REFERENCE','scene_peer_reference.png',
                   self.images['FRONT'])
        self.policy={
          'schema':'c07-p1-native-raster-pre-d-v1',
          'width':self.w,'height':self.h,'background_rgb':[0,0,0],
          'min_projection_iou':1.0,
          'max_reference_rgb_delta':0,
          'max_peer_rgb_delta':0,
          'palette_rgb':[[190,190,190],[210,210,210]],
          'max_palette_distance':0,
          'solid_fraction_range':[.01,.9],
          'focal_xyz':[.3,.3,.3],
          'max_duplicate_triangle_ratio':0,
          'min_foreground_colors':2,
          'player_eye_xyz':[.5,-2,1.75],
          'player_eye_tolerance_m':.05,
          'component_mesh_roles':{'main':0},
          'cameras':{
             'FRONT':{'position_xyz':[.5,-2,.5],'forward_xyz':[0,1,0]},
             'LEFT':{'position_xyz':[-2,.5,.5],'forward_xyz':[1,0,0]},
             'RIGHT':{'position_xyz':[2,.5,.5],'forward_xyz':[-1,0,0]},
             'TOP':{'position_xyz':[.5,.5,2],'forward_xyz':[0,0,-1]},
          },
        }
        self.sync()
    def sync(self):
        self.t.put('P1_NATIVE_RASTER_POLICY','raster_policy.json',
                   encode(self.policy))
        self.t.rebuild()
    def report(self):
        f=self.t.f
        return inspect_family({
            'inventory':f.inv,'plan':f.plan,'controller':f.controller,
            'asset':f.asset,'step':f.step,'work':f.work,
            'source_loader':lambda path:Path(path).read_bytes()})
    def test_all_eleven_distinct_original_native_predicates_positive_fixture(self):
        result=self.report()
        self.assertEqual(set(result['rules']),set(IDS))
        self.assertEqual(result['rule_count'],11)
        self.assertEqual(result['full_semantic_passes'],0)
        self.assertEqual(result['individual_mg0_passes'],0)
        for rid,row in result['rules'].items():
            with self.subTest(rule=rid):
                self.assertEqual(len(row['checks']),3)
                self.assertTrue(all(row['checks'].values()),(rid,row['checks']))
                self.assertEqual(row['full_rule_semantics'],'UNKNOWN')
                self.assertEqual(row['individual_mg0'],'UNKNOWN')
                self.assertFalse(row['advancement_authorized'])
    def test_every_original_rule_has_distinct_adversarial_source_mutation(self):
        attacks={
          31:('max_reference_rgb_delta',-1),
          32:('max_peer_rgb_delta',-1),
          33:('palette_rgb',[]),
          34:('solid_fraction_range',[.9,1]),
          35:('min_projection_iou',1.1),
          36:('focal_xyz',[99,99,99]),
          37:('max_duplicate_triangle_ratio',-1),
          38:('min_foreground_colors',100),
          39:('player_eye_xyz',[.5,-2,99]),
          40:('component_mesh_roles',{'fake':9}),
          56:('cameras',{'FRONT':{'position_xyz':[0,0,0],
                                'forward_xyz':[0,0,1]}}),
        }
        for n,(key,bad) in attacks.items():
            before=copy.deepcopy(self.policy[key])
            self.policy[key]=bad
            self.sync()
            rid='AAA-200-'+('D' if n<=40 else 'F')+'-%03d'%n
            with self.subTest(rule=rid,field=key):
                row=self.report()['rules'][rid]
                self.assertFalse(all(row['checks'].values()),row)
                self.assertEqual(row['full_rule_semantics'],'UNKNOWN')
            self.policy[key]=before
        self.sync()
        self.assertTrue(all(all(row['checks'].values())
            for row in self.report()['rules'].values()))
    def test_original_png_byte_tamper_is_not_a_valid_render(self):
        p=self.t.f.root/'front.png'
        p.write_bytes(p.read_bytes()+b'FORGED')
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    'REGISTERED_ARTIFACT_BYTES_CHANGED'):
            self.report()
    def test_original_policy_unpinned_fails_closed_without_source_pass(self):
        self.t.f.plan['p1_evidence_contract'][
            'original_artifact_sha256'].pop('P1_NATIVE_RASTER_POLICY')
        self.t.f.rebuild()
        result=self.report()
        self.assertEqual(result['full_semantic_passes'],0)
        self.assertTrue(all(not all(row['checks'].values())
                            for row in result['rules'].values()))
    def test_cross_attempt_source_replay_rejected(self):
        self.t.f.work=copy.deepcopy(self.t.f.work)
        self.t.f.work['attempt_id']='d'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.report()
    def test_forged_canonical_literal_cannot_pass(self):
        rid=IDS[0]
        self.t.f.inv['rules'][rid]['requirement']='forged PASS'
        with self.assertRaisesRegex(ValueError,'R144_CANONICAL_P1_RULE_CHANGED'):
            self.report()
if __name__=='__main__':unittest.main()
