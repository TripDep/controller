"""C07 adversarial actual-PNG visual measurements; never artistic PASS."""
import struct
import unittest
import zlib
from visual_content_metrics import (
    decode_grid,compare_pair,inspect_bytes,VisualContentBlocked,VIEWS,MODES
)
BG=(199,207,212)

def chunk(kind,data):
    return (struct.pack('>I',len(data))+kind+data+
            struct.pack('>I',zlib.crc32(kind+data)&0xffffffff))

def image(fill=(70,55,45),shift=0,blank=False,width=200,height=160,filter_id=0,rgba=False):
    channels=4 if rgba else 3
    raw=[];previous=bytearray(width*channels)
    for y in range(height):
        decoded=bytearray()
        for x in range(width):
            color=fill if not blank and 20+shift<=x<180+shift and 20<=y<140 else BG
            decoded.extend(color+((255,) if rgba else ()))
        encoded=bytearray()
        for i,v in enumerate(decoded):
            a=decoded[i-channels] if i>=channels else 0
            b=previous[i];c=previous[i-channels] if i>=channels else 0
            p=a+b-c;da=abs(p-a);db=abs(p-b);dc=abs(p-c)
            paeth=a if da<=db and da<=dc else b if db<=dc else c
            predictor=(0,a,b,(a+b)//2,paeth)[filter_id]
            encoded.append((v-predictor)&255)
        raw.append(bytes([filter_id])+encoded)
        previous=decoded
    ihdr=struct.pack('>IIBBBBB',width,height,8,6 if rgba else 2,0,0,0)
    return (b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',ihdr)+
            chunk(b'IDAT',zlib.compress(b''.join(raw)))+
            chunk(b'IEND',b''))

class ContentTests(unittest.TestCase):
    def test_all_five_png_row_filters_identical(self):
        base=decode_grid(image(filter_id=0))[2]
        for f in range(1,5):
            with self.subTest(filter=f):
                self.assertEqual(decode_grid(image(filter_id=f))[2],base)
    def test_rgba_alpha_supported(self):
        self.assertEqual(decode_grid(image(rgba=True))[:2],(200,160))
    def test_systematically_dark_material_is_review_not_pass(self):
        a=image(fill=(10,10,10));b=image(fill=(95,80,70))
        r=compare_pair(a,b)
        self.assertTrue(r['significant_material_darkening_measured'])
        self.assertFalse(r['geometry_or_camera_mismatch_suspected'])
        self.assertLess(r['source_to_neutral_brightness_ratio'],.78)
        deck={(v,m):a if m==MODES[0] else b for v in VIEWS for m in MODES}
        summary=inspect_bytes(deck)
        self.assertEqual(summary['significantly_darkened_views'],8)
        self.assertEqual(summary['systemic_darkening'],'REVIEW_REQUIRED_MEASURED_6_OF_8')
        self.assertTrue(summary['requires_independent_visual_review'])
        self.assertEqual(summary['semantic_verdict'],'UNKNOWN')
        self.assertEqual(summary['individual_mg0'],'UNKNOWN')
        self.assertFalse(summary['work_advancement_authorized'])
    def test_same_color_has_no_darkness_measurement(self):
        a=image(fill=(100,70,50))
        self.assertFalse(compare_pair(a,a)['significant_material_darkening_measured'])
    def test_camera_or_geometry_mismatch_stops_darkness_inference(self):
        r=compare_pair(image(fill=(35,40,45)),image(fill=(115,115,115),shift=65))
        self.assertTrue(r['geometry_or_camera_mismatch_suspected'])
        self.assertFalse(r['significant_material_darkening_measured'])
    def test_blank_deck_cannot_be_declared_verified(self):
        a=image(blank=True)
        r=inspect_bytes({(v,m):a for v in VIEWS for m in MODES})
        self.assertEqual(r['systemic_darkening'],'UNKNOWN')
        self.assertEqual(len(r['unverified_views']),8)
        self.assertFalse(r['work_advancement_authorized'])
    def test_five_dark_views_do_not_prove_systemic(self):
        dark=image(fill=(10,10,10));bright=image(fill=(95,80,70))
        data={(v,m):dark if i<5 and m==MODES[0] else bright
              for i,v in enumerate(VIEWS) for m in MODES}
        r=inspect_bytes(data)
        self.assertEqual(r['significantly_darkened_views'],5)
        self.assertEqual(r['systemic_darkening'],'NOT_ESTABLISHED')
    def test_mismatched_size_is_not_compared(self):
        with self.assertRaisesRegex(VisualContentBlocked,'PAIR_MISMATCHED_DIMENSIONS'):
            compare_pair(image(),image(width=220))
    def test_png_bad_crc_fails(self):
        raw=bytearray(image());raw[30]^=8
        with self.assertRaisesRegex(VisualContentBlocked,'PNG_CRC_INVALID'):
            decode_grid(bytes(raw))
    def test_png_truncated_fails(self):
        with self.assertRaises(VisualContentBlocked):
            decode_grid(image()[:-7])
    def test_missing_eight_pair_bytes_fail(self):
        with self.assertRaisesRegex(VisualContentBlocked,'EXACT_16_IMAGE_BYTES_REQUIRED'):
            inspect_bytes({})
    def test_bad_idat_fails_with_crc_recomputed(self):
        raw=image();p=8;parts=[]
        while p<len(raw):
            n=int.from_bytes(raw[p:p+4],'big');kind=raw[p+4:p+8]
            payload=raw[p+8:p+8+n]
            if kind==b'IDAT':payload=b'invalid-deflate'
            parts.append(chunk(kind,payload));p+=12+n
        with self.assertRaisesRegex(VisualContentBlocked,'PNG_ZLIB_CORRUPT'):
            decode_grid(raw[:8]+b''.join(parts))

if __name__=='__main__':
    unittest.main()
