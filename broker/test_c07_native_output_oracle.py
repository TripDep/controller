"""R139 exact binary positive/negative output evidence tests. Synthetic only."""
import hashlib
import json
import struct
import unittest
from pathlib import Path
from test_c07_r124_positive_process import Tests as Fixture, test_glb
from c07_native_output_oracle import inspect, read_mesh_geometry, CONTRACT, OriginalGeometryBlocked
from c07_positive_native_process import NativeEvidenceBlocked

def two_triangles():
    pts=struct.pack('<18f',
        0,0,0, 1,0,0, 0,1,0,
        0,0,0, 1,0,0, 0,1,1)
    doc={'asset':{'version':'2.0'},'buffers':[{'byteLength':len(pts)}],
         'bufferViews':[{'buffer':0,'byteOffset':0,'byteLength':len(pts)}],
         'meshes':[{'primitives':[{'attributes':{'POSITION':0},'mode':4}]}],
         'accessors':[{'bufferView':0,'byteOffset':0,'count':6,
                       'type':'VEC3','componentType':5126}]}
    raw=json.dumps(doc,separators=(',',':')).encode()
    raw+=b' '*(-len(raw)%4)
    return (struct.pack('<4sII',b'glTF',2,12+8+len(raw)+8+len(pts))+
            struct.pack('<I4s',len(raw),b'JSON')+raw+
            struct.pack('<I4s',len(pts),bytes((66,73,78,0)))+pts)

def expectation(z=1,count=2):
    return {'schema':CONTRACT,'bbox_min':[0,0,0],'bbox_max':[1,1,z],
            'bbox_tolerance_m':0.0001,'min_meshes':1,
            'min_triangles':count,'max_triangles':count,
            'min_triangle_delta_from_baseline':1}

class Tests(unittest.TestCase):
    def setUp(self):
        self.fx=Fixture('test_eight_literal_rules_exact_criteria')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
    def examine(self):
        f=self.fx.f
        return inspect(f.inv,f.plan,f.controller,f.asset,f.step,f.work,
                       source_loader=lambda p:Path(p).read_bytes())
    def test_actual_glb_float_geometry_not_accessors(self):
        d=read_mesh_geometry(two_triangles())
        self.assertEqual(d['triangles'],2)
        self.assertEqual(d['mesh_definitions'],1)
        self.assertEqual(d['bbox_max'],[1,1,1])
    def test_real_pre_d_output_matches_exact_measured_vertices(self):
        self.fx.f.plan['output_expectation']=expectation()
        self.fx.f.add_item('NATIVE_EXPORT','scene.glb',two_triangles())
        self.fx.f.rebuild()
        r=self.examine()
        self.assertEqual(r['rules']['AAA-200-R-176']['machine_semantics'],'OBSERVED_SCOPE_PASS')
        self.assertEqual(r['rules']['AAA-200-R-180']['machine_semantics'],'UNKNOWN')
        self.assertEqual(r['full_work_rule_passes'],0)
        self.assertEqual(r['individual_mg0_passes'],0)
    def test_original_baseline_changed_two_tris_machine_positive(self):
        self.fx.f.plan['output_expectation']=expectation()
        self.fx.f.add_item('NATIVE_EXPORT','scene.glb',two_triangles())
        self.fx.f.add_item('BASELINE_SNAPSHOT','base.glb',test_glb())
        self.fx.f.rebuild()
        r=self.examine()
        self.assertEqual(r['new_output_semantics_observed'],2)
        self.assertEqual(r['rules']['AAA-200-R-180']['machine_semantics'],'OBSERVED_SCOPE_PASS')
        self.assertFalse(r['advancement_authorized'])
    def test_only_exit_success_without_valid_output_is_unknown(self):
        self.fx.f.plan['output_expectation']=expectation()
        self.fx.f.rebuild()
        r=self.examine()
        self.assertEqual(r['new_output_semantics_observed'],0)
    def test_uncommitted_contract_not_pass(self):
        self.fx.f.add_item('NATIVE_EXPORT','scene.glb',two_triangles())
        self.fx.f.rebuild()
        self.assertEqual(self.examine()['rules']['AAA-200-R-176']['machine_semantics'],'UNKNOWN')
    def test_wrong_expected_bounds_is_not_pass(self):
        self.fx.f.plan['output_expectation']=expectation(z=2)
        self.fx.f.add_item('NATIVE_EXPORT','scene.glb',two_triangles())
        self.fx.f.rebuild()
        self.assertEqual(self.examine()['rules']['AAA-200-R-176']['machine_semantics'],'UNKNOWN')
    def test_glb_binary_tamper_fails_closed(self):
        self.fx.f.plan['output_expectation']=expectation()
        self.fx.f.add_item('NATIVE_EXPORT','scene.glb',two_triangles())
        self.fx.f.rebuild()
        (self.fx.f.root/'scene.glb').write_bytes(b'altered')
        with self.assertRaisesRegex(NativeEvidenceBlocked,'ARTIFACT_BYTES_CHANGED'):
            self.examine()
    def test_glb_declared_length_corruption_detected(self):
        b=bytearray(two_triangles());struct.pack_into('<I',b,8,len(b)+1)
        with self.assertRaisesRegex(OriginalGeometryBlocked,'VERSION_LENGTH'):
            read_mesh_geometry(bytes(b))
    def test_cross_attempt_replay_rejected(self):
        self.fx.f.work['attempt_id']='e'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.examine()

if __name__=='__main__':unittest.main()
