import hashlib
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch
from native_format_evidence import inspect, scan_blend_buffer, scan_ydr_bytes, NativeScanBlocked

def modern(rows=None, tail=b''):
    rows=rows if rows is not None else [(b'OB\x00\x00',b'object'),(b'DNA1',b'SDNAnames')]
    b=b'BLENDER17-01v0502'
    for code,data in rows+[(b'ENDB',b'')]:
        b+=struct.pack('<4sIQQQ',code,0,0,len(data),1)+data
    return b+tail

def legacy(ptr=8,endian='<'):
    pre=b'BLENDER'+(b'-' if ptr==8 else b'_')+(b'v' if endian=='<' else b'V')+b'405'
    fmt=endian+('4sIQII' if ptr==8 else '4sIIII')
    return pre+ b''.join(struct.pack(fmt,code,len(data),0,0,1)+data for code,data in
        [(b'DNA1',b'SDNAnames'),(b'ENDB',b'')])

def rsc(data=b'resource sample object geometry',wbits=-15,vers=165):
    obj=zlib.compressobj(wbits=wbits)
    return b'RSC7'+struct.pack('<III',vers,0x00010000,0x00020000)+obj.compress(data)+obj.flush()

class TestNativeEvidence(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.root=Path(t.name)
    def entry(self,name,blob):
        p=self.root/name;p.write_bytes(blob)
        return p,hashlib.sha256(blob).hexdigest()
    def test_blender5_17_byte_large_bhead8_parse(self):
        evidence=scan_blend_buffer(modern())
        self.assertEqual(evidence['header_variant'],'MODERN_17')
        self.assertEqual(evidence['blender_file_version'],502)
        self.assertEqual(evidence['file_blocks'],3)
        self.assertEqual(evidence['object_blocks'],1)
        self.assertEqual(evidence['semantic_verdict'],'UNKNOWN')
    def test_blend_legacy_32bit_big_endian_and_64bit_little(self):
        for ptr,endian in ((4,'>'),(8,'<')):
            self.assertEqual(scan_blend_buffer(legacy(ptr,endian))['dna1_blocks'],1)
    def test_blend_missing_dna_or_end_fails(self):
        for rows in ([(b'OB\x00\x00',b'object')],[(b'DNA1',b'CORRUPT')]):
            with self.assertRaises(NativeScanBlocked):
                scan_blend_buffer(modern(rows))
        with self.assertRaises(NativeScanBlocked):
            scan_blend_buffer(modern()[:-32])
    def test_blend_corrupted_file_block_length_fails(self):
        data=bytearray(modern());struct.pack_into('<Q',data,17+16,1_000_000)
        with self.assertRaisesRegex(NativeScanBlocked,'TRUNCATED_BLOCK_BODY'):
            scan_blend_buffer(bytes(data))
    def test_blend_trailing_untrusted_payload_denied(self):
        with self.assertRaisesRegex(NativeScanBlocked,'UNEXPECTED_TRAILING_BLOCKS'):
            scan_blend_buffer(modern(tail=b'evil'))
    def test_blend_file_authenticated_and_never_authorized(self):
        p,sha=self.entry('asset.blend',modern())
        v=inspect(p,sha)
        self.assertFalse(v['advancement_authorized'])
        self.assertEqual(v['inspection']['runtime_open_by_blender'],'NOT_TESTED')
        self.assertEqual(v['inspection']['binary_structure'],'BLOCK_FRAMING_CHECKED')
    def test_blend_sha_mismatch_fails_before_parse(self):
        p,sha=self.entry('asset.blend',modern())
        p.write_bytes(p.read_bytes()+b'altered')
        with self.assertRaisesRegex(NativeScanBlocked,'NATIVE_SOURCE_SHA_MISMATCH'):
            inspect(p,sha)
    def test_blend_zstd_magic_is_not_falsely_accepted_as_complete(self):
        p,sha=self.entry('compressed.blend',b'\x28\xb5\x2f\xfd'+b'unknown')
        v=inspect(p,sha)
        self.assertEqual(v['inspection']['binary_structure'],'UNKNOWN_NEEDS_BOUNDED_DECOMPRESSION')
        self.assertEqual(v['semantic_verdict'],'UNKNOWN')
    def test_ydr_rsc7_raw_and_zlib_deflate_detected(self):
        for wbits in (-15,15):
            evidence=scan_ydr_bytes(rsc(wbits=wbits))
            self.assertEqual(evidence['decompressed_payload_bytes'],len(b'resource sample object geometry'))
            self.assertEqual(evidence['drawable_geometry'],'NOT_PARSED')
            self.assertEqual(evidence['individual_mg0'],'UNKNOWN')
    def test_ydr_false_magic_and_no_payload_blocked(self):
        for blob in (b'YDR7'+rsc()[4:],b'RSC7'+b'0'*14):
            with self.assertRaises(NativeScanBlocked):scan_ydr_bytes(blob)
    def test_ydr_wrong_version_or_flags_denied(self):
        a=bytearray(rsc());struct.pack_into('<I',a,4,0)
        with self.assertRaisesRegex(NativeScanBlocked,'VERSION_INVALID'):scan_ydr_bytes(bytes(a))
        a=bytearray(rsc());struct.pack_into('<II',a,8,0,0)
        with self.assertRaisesRegex(NativeScanBlocked,'PAGE_FLAGS_EMPTY'):scan_ydr_bytes(bytes(a))
    def test_ydr_compressed_data_must_be_entire_complete_stream(self):
        valid=rsc()
        for data in (valid[:-4],valid+b'evil'):
            with self.assertRaisesRegex(NativeScanBlocked,'RSC7_COMPRESSED_DATA_INVALID'):
                scan_ydr_bytes(data)
    def test_ydr_compression_bomb_rejected(self):
        from native_format_evidence import MAX_RSC_UNPACKED
        with patch('native_format_evidence.MAX_RSC_UNPACKED', 64):
            with self.assertRaises(NativeScanBlocked):
                scan_ydr_bytes(rsc(b'a'*100000))
    def test_ydr_authenticated_source_never_runtime_pass(self):
        p,sha=self.entry('model.ydr',rsc())
        v=inspect(p,sha)
        self.assertEqual(v['inspection']['binary_structure'],'RESOURCE_CONTAINER_VERIFIED_ONLY')
        self.assertEqual(v['runtime_compatibility'],'UNKNOWN')
        self.assertFalse(v['advancement_authorized'])
    def test_disguised_file_does_not_become_blend_or_ydr(self):
        p,sha=self.entry('model.ydr',modern())
        with self.assertRaisesRegex(NativeScanBlocked,'RSC7_MAGIC'):inspect(p,sha)
        q,sha=self.entry('model.blend',rsc())
        with self.assertRaisesRegex(NativeScanBlocked,'BLEND_HEADER_MAGIC'):inspect(q,sha)

if __name__=='__main__':unittest.main()