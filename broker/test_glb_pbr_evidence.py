"""C07 PBR native-byte adversarial tests (synthetic only; never an asset PASS)."""
import copy
import math
import struct
import unittest
from glb_pbr_evidence import inspect, MaterialEvidenceError
from glb_machine_qa import audit_bytes

import zlib

def png_chunk(kind, content):
    return (struct.pack('>I',len(content)) + kind + content +
            struct.pack('>I',zlib.crc32(kind+content)&0xffffffff))

PNG=(b'\x89PNG\r\n\x1a\n' +
     png_chunk(b'IHDR', struct.pack('>IIBBBBB',16,16,8,2,0,0,0)) +
     png_chunk(b'IDAT', zlib.compress((b'\x00'+b'\x80'*(16*3))*16)) +
     png_chunk(b'IEND',b''))
POS=b''.join(struct.pack('<fff',*p) for p in ((0,0,0),(1,0,0),(0,1,0)))
UV=b''.join(struct.pack('<ff',*p) for p in ((0,0),(1,0),(0,1)))

def fixture(*,texcoord=True, png=PNG, tint=None):
    blob=POS+UV+png
    mat={'name':'TEST_PBR','pbrMetallicRoughness':{
      'baseColorTexture':{'index':0},
      'baseColorFactor':tint if tint is not None else [1,1,1,1],
      'metallicFactor':0.1,'roughnessFactor':0.5}}
    g={'asset':{'version':'2.0'},'buffers':[{'byteLength':len(blob)}],
       'bufferViews':[{'buffer':0,'byteOffset':0,'byteLength':len(POS)},
                      {'buffer':0,'byteOffset':len(POS),'byteLength':len(UV)},
                      {'buffer':0,'byteOffset':len(POS)+len(UV),'byteLength':len(png)}],
       'accessors':[{'bufferView':0,'componentType':5126,'type':'VEC3','count':3},
                    {'bufferView':1,'componentType':5126,'type':'VEC2','count':3}],
       'materials':[mat],'textures':[{'source':0}],
       'images':[{'bufferView':2,'mimeType':'image/png'}],
       'meshes':[{'primitives':[{'material':0,'attributes':{'POSITION':0,**({'TEXCOORD_0':1} if texcoord else {})}}]}]}
    return g,blob,[(0,0,None)]

def pack(g,blob):
    import json
    j=json.dumps(g,separators=(',',':')).encode()
    j+=b' '*(-len(j)%4)
    blob+=b'\x00'*(-len(blob)%4)
    return (struct.pack('<4sII',b'glTF',2,12+8+len(j)+8+len(blob))+
            struct.pack('<I4s',len(j),b'JSON')+j+
            struct.pack('<I4s',len(blob),b'BIN\x00')+blob)

class PbrNativeTests(unittest.TestCase):
    def test_proven_embedded_material_and_uv_without_semantic_pass(self):
        g,b,w=fixture();a=inspect(g,b,w)
        self.assertEqual(a['material_source_status'],'NO_STRUCTURAL_PBR_DEFECT_DETECTED')
        self.assertEqual(a['referenced_images_count'],1)
        self.assertEqual(a['referenced_image_dimensions']['0'],[16,16])
        self.assertEqual(a['uv_coordinates_finite_checked'],3)
        self.assertEqual(a['visual_material_quality'],'UNKNOWN')
        self.assertFalse(a['advancement_authorized'])
    def test_textured_surface_missing_uv_is_fail(self):
        g,b,w=fixture(texcoord=False);a=inspect(g,b,w)
        self.assertEqual(a['material_source_status'],'FAIL')
        self.assertTrue(any('USED_TEXCOORD_MISSING' in x for x in a['pbr_structural_errors']))
    def test_uv_count_mismatch_is_fail(self):
        g,b,w=fixture();g['accessors'][1]['count']=2
        a=inspect(g,b,w)
        self.assertTrue(any('UV_VERTEX_COUNT_MISMATCH' in x for x in a['pbr_structural_errors']))
    def test_nonfinite_uv_is_fail(self):
        g,b,w=fixture();data=bytearray(b);data[len(POS):len(POS)+4]=struct.pack('<f',math.nan)
        a=inspect(g,bytes(data),w)
        self.assertTrue(any('NONFINITE_UV' in x for x in a['pbr_structural_errors']))
    def test_image_declared_png_but_bad_bytes_fails(self):
        g,b,w=fixture(png=b'not-png-anymore-data!!!!')
        a=inspect(g,b,w)
        self.assertTrue(any('PNG_HEADER_INVALID' in x for x in a['pbr_structural_errors']))
    def test_png_interior_crc_corruption_fails(self):
        broken=bytearray(PNG);broken[29]^=1
        g,b,w=fixture(png=bytes(broken))
        a=inspect(g,b,w)
        self.assertTrue(any('PBR_EMBEDDED_PNG_CRC_INVALID' in x for x in a['pbr_structural_errors']))
    def test_png_truncated_chunk_fails(self):
        g,b,w=fixture(png=PNG[:-3])
        a=inspect(g,b,w)
        self.assertTrue(any('PBR_EMBEDDED_PNG' in x for x in a['pbr_structural_errors']))
    def test_texture_index_out_of_bounds_fails(self):
        g,b,w=fixture();g['materials'][0]['pbrMetallicRoughness']['baseColorTexture']['index']=7
        a=inspect(g,b,w)
        self.assertTrue(any('TEXTURE_REF_INVALID' in x for x in a['pbr_structural_errors']))
    def test_sampler_index_out_of_bounds_fails(self):
        g,b,w=fixture();g['textures'][0]['sampler']=7
        a=inspect(g,b,w)
        self.assertTrue(any('SAMPLER_REF_INVALID' in x for x in a['pbr_structural_errors']))
    def test_texture_transform_coords_require_actual_uv(self):
        g,b,w=fixture()
        g['materials'][0]['pbrMetallicRoughness']['baseColorTexture']['extensions']={
            'KHR_texture_transform':{'texCoord':1,'offset':[0,0]}}
        a=inspect(g,b,w)
        self.assertTrue(any('USED_TEXCOORD_MISSING' in x and 'TEXCOORD_1' in x
                            for x in a['pbr_structural_errors']))
    def test_factor_greater_than_one_or_nan_is_rejected(self):
        for bad in (2.0,float('nan')):
            g,b,w=fixture();g['materials'][0]['pbrMetallicRoughness']['roughnessFactor']=bad
            self.assertTrue(any('FACTOR_INVALID' in x for x in inspect(g,b,w)['pbr_structural_errors']))
    def test_normalized_uint16_uvs_are_valid_not_false_fail(self):
        g,b,w=fixture()
        packed=b''.join(struct.pack('<HH',*p) for p in ((0,0),(65535,0),(0,65535)))
        b=POS+packed+PNG
        g['bufferViews'][1]['byteLength']=len(packed)
        g['bufferViews'][2]['byteOffset']=len(POS)+len(packed)
        g['accessors'][1]['componentType']=5123
        g['accessors'][1]['normalized']=True
        a=inspect(g,b,w)
        self.assertEqual(a['pbr_structural_errors'],[])
        self.assertEqual(a['uv_coordinates_finite_checked'],3)
    def test_unsigned_integer_uv_without_normalization_is_rejected(self):
        g,b,w=fixture()
        packed=b''.join(struct.pack('<HH',*p) for p in ((0,0),(65535,0),(0,65535)))
        b=POS+packed+PNG
        g['bufferViews'][1]['byteLength']=len(packed)
        g['bufferViews'][2]['byteOffset']=len(POS)+len(packed)
        g['accessors'][1]['componentType']=5123
        a=inspect(g,b,w)
        self.assertTrue(any('INTEGER_UV_REQUIRES_NORMALIZED' in x for x in a['pbr_structural_errors']))
    def test_double_normalization_suspected_not_false_fail(self):
        g,b,w=fixture(tint=[1/255]*4)
        a=inspect(g,b,w)
        self.assertEqual(a['near_black_textured_materials_count'],1)
        self.assertTrue(any('NEAR_BLACK' in x for x in a['pbr_diagnostic_warnings']))
        self.assertEqual(a['material_source_status'],'NO_STRUCTURAL_PBR_DEFECT_DETECTED')
        self.assertEqual(a['overall_rule_semantics'],'UNKNOWN')
    def test_opaque_png_decoding_not_claimed(self):
        g,b,w=fixture();a=inspect(g,b,w)
        self.assertIn('PBR_PNG_PIXELS_NOT_DECODED:0',a['pbr_unverified_requirements'])
    def test_embedded_glb_full_scanner_does_not_hide_pbr_issue(self):
        g,b,w=fixture(texcoord=False)
        g['nodes']=[{'mesh':0}]
        g['scenes']=[{'nodes':[0]}];g['scene']=0
        report=audit_bytes(pack(g,b))
        self.assertEqual(report['machine_evidence_status'],'FAIL')
        self.assertTrue(any('USED_TEXCOORD_MISSING' in x for x in report['errors']))
        self.assertEqual(report['overall_rule_semantics'],'UNKNOWN')
        self.assertEqual(report['asset_acceptance'],'NOT_AUTHORIZED')

if __name__=='__main__':unittest.main()
