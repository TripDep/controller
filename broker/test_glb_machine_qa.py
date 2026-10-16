"""Adversarial C07 scanner tests; fixtures never certify an actual asset."""
import copy
import hashlib
import json
import math
import os
import struct
import tempfile
import unittest
from pathlib import Path
from glb_machine_qa import audit_bytes, examine, GLBError, matrix, xform

def synthetic_glb(*, triangles=None, indexes=None, child_translation=None, malformed_index=False):
    triangles=triangles or [(0.,0.,0.),(1.,0.,0.),(0.,1.,0.)]
    indexes=indexes or [0,1,2]
    xyz=b''.join(struct.pack('<fff',*x) for x in triangles)
    indexed=b''.join(struct.pack('<H',i) for i in indexes)
    data=xyz+indexed
    data+=b'\0' * (-len(data)%4)
    nodes=[{'mesh':0}]
    if child_translation is not None:nodes[0]['translation']=child_translation
    root={'asset':{'version':'2.0'},'buffers':[{'byteLength':len(data)}],
          'bufferViews':[{'buffer':0,'byteOffset':0,'byteLength':len(xyz)},
                         {'buffer':0,'byteOffset':len(xyz),'byteLength':len(indexed)}],
          'accessors':[{'bufferView':0,'componentType':5126,'count':len(triangles),'type':'VEC3'},
                       {'bufferView':1,'componentType':5123,'count':len(indexes),'type':'SCALAR'}],
          'meshes':[{'primitives':[{'attributes':{'POSITION':0},'indices':1}]}],
          'nodes':nodes,'scenes':[{'nodes':[0]}],'scene':0}
    if malformed_index:root['meshes'][0]['primitives'][0]['indices']=17
    payload=json.dumps(root,separators=(',',':')).encode()
    payload+=b' ' * (-len(payload)%4)
    raw=struct.pack('<4sII',b'glTF',2,12+8+len(payload)+8+len(data))
    return raw+struct.pack('<I4s',len(payload),b'JSON')+payload+struct.pack('<I4s',len(data),b'BIN\x00')+data

class GLBScannerTests(unittest.TestCase):
    def test_healthy_geometry_yields_only_machine_evidence(self):
        r=audit_bytes(synthetic_glb())
        self.assertEqual(r['machine_evidence_status'],'NO_FATAL_STRUCTURAL_DEFECT_DETECTED')
        self.assertEqual(r['triangles_examined'],1)
        self.assertEqual(r['degenerate_triangles'],0)
        self.assertEqual(r['overall_rule_semantics'],'UNKNOWN')
        self.assertEqual(r['asset_acceptance'],'NOT_AUTHORIZED')
        self.assertEqual(r['visual_qa'],'UNKNOWN')
    def test_degenerate_is_a_machine_fail(self):
        r=audit_bytes(synthetic_glb(triangles=[(0,0,0),(1,1,1),(2,2,2)]))
        self.assertEqual(r['machine_evidence_status'],'FAIL')
        self.assertIn('DEGENERATE_TRIANGLES:1',r['errors'])
    def test_out_of_range_indices_fail(self):
        r=audit_bytes(synthetic_glb(indexes=[0,1,3]))
        self.assertEqual(r['invalid_indices'],1)
        self.assertEqual(r['machine_evidence_status'],'FAIL')
    def test_nonfinite_position_fails(self):
        r=audit_bytes(synthetic_glb(triangles=[(0,0,0),(float('nan'),0,0),(0,1,0)]))
        self.assertEqual(r['nonfinite_positions'],1)
        self.assertEqual(r['machine_evidence_status'],'FAIL')
    def test_wrong_reference_raises(self):
        with self.assertRaisesRegex(GLBError,'ACCESSOR_OUT_OF_RANGE'):
            audit_bytes(synthetic_glb(malformed_index=True))
    def test_corrupted_header_and_length_fail(self):
        raw=synthetic_glb()
        for changed in (b'oops'+raw[4:],raw[:-1],raw[:4]+b'\x01\x00\x00\x00'+raw[8:]):
            with self.assertRaisesRegex(GLBError,'GLB_BAD_HEADER'):
                audit_bytes(changed)
    def test_immutable_file_digest_required(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'fixture.glb';path.write_bytes(synthetic_glb())
            with self.assertRaisesRegex(GLBError,'SOURCE_GLB_SHA256_MISMATCH'):
                examine(path,'0'*64)
            self.assertEqual(examine(path,hashlib.sha256(path.read_bytes()).hexdigest())['triangles_examined'],1)
    def test_transform_is_not_ignored(self):
        # Traversal must apply a node translation and still preserve triangle area.
        r=audit_bytes(synthetic_glb(child_translation=[20.,30.,-10.]))
        self.assertEqual(r['degenerate_triangles'],0)
        self.assertEqual(r['aabb_overlap_candidates_count'],0)
    def test_glb_rotated_nonuniform_scale_uses_column_scaling(self):
        # 90 degree about Z, scale x=2,y=3: original (1,0,0) -> (0,2,0)
        # and original (0,1,0) -> (-3,0,0), then translate (4,5,6).
        root2=math.sqrt(.5)
        m=matrix({'translation':[4,5,6], 'scale':[2,3,1],
                  'rotation':[0,0,root2,root2]})
        for point,wanted in [((1,0,0),(4,7,6)),((0,1,0),(1,5,6))]:
            actual=xform(m,point)
            for a,b in zip(actual,wanted):self.assertAlmostEqual(a,b,places=10)
    def test_explicit_glb_matrix_column_major_orientation(self):
        # glTF columns are [0,2,0], [-3,0,0], [0,0,1], [4,5,6].
        m=matrix({'matrix':[0,2,0,0,-3,0,0,0,0,0,1,0,4,5,6,1]})
        self.assertEqual(xform(m,(1,0,0)),(4,7,6))
        self.assertEqual(xform(m,(0,1,0)),(1,5,6))
    def test_two_meshes_share_aabb_but_not_proven_interpenetrating(self):
        # Multiple nodes can share a primitive without any crossing of actual triangles.
        raw=synthetic_glb()
        r=audit_bytes(raw)
        self.assertFalse(r['overlaps_confirmed'])
        self.assertEqual(r['asset_acceptance'],'NOT_AUTHORIZED')

if __name__=='__main__':unittest.main()