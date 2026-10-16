"""C07 real PNG source-pixel forensic checks, adversarial test suite only."""
import copy
import hashlib
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from glb_basecolor_pixels import inspect, png_rgb_means, PixelReviewUnsupported
from glb_machine_qa import audit_bytes
from glb_output_close_gate import inspect as check_output
from test_glb_pbr_evidence import fixture, pack, png_chunk, PNG

WORK={'attempt_id':'a'*64,'operation_sha256':'b'*64,'master_sha256':'c'*64}

def two_material_glb(factors):
    g,blob,_=fixture()
    g['materials']=[copy.deepcopy(g['materials'][0]) for _ in factors]
    for mat,mul in zip(g['materials'],factors):
        mat['pbrMetallicRoughness']['baseColorFactor']=[mul,mul,mul,1.0]
    primitive=g['meshes'][0]['primitives'][0]
    g['meshes'][0]['primitives']=[
        {**copy.deepcopy(primitive),'material':i} for i in range(len(factors))]
    g['nodes']=[{'mesh':0}]
    g['scenes']=[{'nodes':[0]}];g['scene']=0
    return pack(g,blob)

def png_filtered(filter_id):
    # 2x2 known RGB pixels, synthesize each PNG row-filter encoding.
    w,h=2,2;channels=3
    rows=[bytes([60,120,180,12,78,140]),bytes([200,20,70,9,10,11])]
    prev=bytes(w*channels);encoded=b''
    for row in rows:
        line=bytearray()
        for i,v in enumerate(row):
            a=row[i-channels] if i>=channels else 0
            b=prev[i];c=prev[i-channels] if i>=channels else 0
            p=a+b-c
            ab,bb,cb=abs(p-a),abs(p-b),abs(p-c)
            paeth=a if ab<=bb and ab<=cb else b if bb<=cb else c
            predictor=(0,a,b,(a+b)//2,paeth)[filter_id]
            line.append((v-predictor)&255)
        encoded+=bytes([filter_id])+line
        prev=row
    ihdr=struct.pack('>IIBBBBB',w,h,8,2,0,0,0)
    return b'\x89PNG\r\n\x1a\n'+png_chunk(b'IHDR',ihdr)+png_chunk(
        b'IDAT',zlib.compress(encoded))+png_chunk(b'IEND',b'')

class PixelEvidenceTests(unittest.TestCase):
    def test_all_five_png_row_filters_reconstruct_identical_real_pixels(self):
        expected=[(60+12+200+9)/4,(120+78+20+10)/4,(180+140+70+11)/4]
        for i in range(5):
            with self.subTest(filter=i):
                result=png_rgb_means(png_filtered(i))
                self.assertEqual(result['pixel_count'],4)
                self.assertEqual(result['rgb_mean_srgb_0_255'],expected)
                self.assertEqual(result['pixel_decode'],'COMPLETE_FOR_SUPPORTED_PNG_RGB_RGBA')
    def test_invalid_crc_rejected(self):
        raw=bytearray(png_filtered(0));raw[29]^=8
        with self.assertRaisesRegex(PixelReviewUnsupported,'PIXEL_PNG_CRC'):
            png_rgb_means(bytes(raw))
    def test_truncated_png_rejected(self):
        with self.assertRaises(PixelReviewUnsupported):
            png_rgb_means(png_filtered(1)[:-4])
    def test_unsupported_interlaced_png_returns_unknown_not_clean(self):
        raw=bytearray(png_filtered(0))
        raw[28]=1 # IHDR interlace method, leave CRC stale deliberately
        with self.assertRaises(PixelReviewUnsupported):
            png_rgb_means(bytes(raw))
    def test_real_png_pixels_detect_systemic_darkening_without_visual_pass(self):
        glb=two_material_glb([1/255,1/255])
        result=audit_bytes(glb)
        px=result['basecolor_pixel_evidence']
        self.assertEqual(px['decoded_textured_materials'],2)
        self.assertEqual(px['systemic_tint_risk'],'REVIEW_REQUIRED_CONFIRMED_PIXEL_MULTIPLIER')
        self.assertTrue(px['requires_visual_review'])
        self.assertEqual(px['semantic_result'],'UNKNOWN')
        self.assertFalse(px['advancement_authorized'])
        self.assertEqual(result['overall_rule_semantics'],'UNKNOWN')
    def test_one_dark_material_does_not_block_all_materials(self):
        report=audit_bytes(two_material_glb([1/255,1.0]))['basecolor_pixel_evidence']
        self.assertFalse(report['requires_visual_review'])
        self.assertEqual(report['systemic_tint_risk'],'NOT_CONFIRMED')
    def test_diagnostic_close_blocks_systemic_tint_even_with_valid_glb_hash(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'real_glb_source.glb'
            path.write_bytes(two_material_glb([1/255,1/255]))
            item={'step':'0001','path':str(path),
                  'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                  'size_bytes':path.stat().st_size}
            result=check_output([item],WORK,'TEST','0001')
            self.assertFalse(result['may_continue_to_independent_native_post_review'])
            self.assertTrue(any(x['reason']=='PBR_SYSTEMIC_DARK_TINT_REQUIRES_INDEPENDENT_VISUAL_REVIEW'
                                for x in result['machine_blockers']))
            self.assertEqual(result['semantic_result'],'UNKNOWN')
            self.assertEqual(result['individual_mg0'],'UNKNOWN')
            self.assertFalse(result['advancement_authorized'])
            self.assertEqual(result['machine_results'][0]['real_basecolor_pixel_evidence']['decoded_textured_materials'],2)
    def test_good_material_glb_still_requires_independent_semantic_qa(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'good_materials.glb'
            path.write_bytes(two_material_glb([1.,1.]))
            item={'step':'0001','path':str(path),
                  'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                  'size_bytes':path.stat().st_size}
            result=check_output([item],WORK,'TEST','0001')
            self.assertTrue(result['may_continue_to_independent_native_post_review'])
            self.assertFalse(result['advancement_authorized'])
            self.assertEqual(result['semantic_result'],'UNKNOWN')
    def test_pixel_raster_budget_is_not_a_pass(self):
        # Header is 16x16 but inflate hostile output; bounded decompressor must reject.
        raw=PNG
        # append extra IDAT invalid placement => decoder fails closed, no false claim
        broken=raw[:-12]+png_chunk(b'IDAT',zlib.compress(b'X'*20000))+raw[-12:]
        with self.assertRaises(PixelReviewUnsupported):
            png_rgb_means(broken)

if __name__=='__main__':
    unittest.main()
