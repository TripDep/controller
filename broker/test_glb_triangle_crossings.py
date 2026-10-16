"""C07 strict crossing negative and positive regression fixtures only."""
import json
import struct
import unittest
import glb_triangle_crossings as c
from glb_machine_qa import audit_bytes

A=((0.,0.,0.),(2.,0.,0.),(0.,2.,0.))
B=((.5,.5,-1.),(.5,.5,1.),(.5,1.5,0.))
COPLANAR=((.2,.2,0.),(1.,.2,0.),(.2,1.,0.))
TOUCH=((0.,0.,0.),(0.,0.,1.),(2.,0.,0.))

def two_groups(second):
    return [{'key':(0,0),'triangles':[A]},
            {'key':(1,0),'triangles':[second]}]

def tiny_two_group_glb(second):
    positions = [v for tri in (A,second) for v in tri]
    binary=b''.join(struct.pack('<fff',*p) for p in positions)
    gltf={'asset':{'version':'2.0'},'buffers':[{'byteLength':len(binary)}],
          'bufferViews':[{'buffer':0,'byteOffset':0,'byteLength':len(binary)}],
          'accessors':[{'bufferView':0,'componentType':5126,'count':3,'type':'VEC3','byteOffset':0},
                       {'bufferView':0,'componentType':5126,'count':3,'type':'VEC3','byteOffset':36}],
          'meshes':[{'primitives':[{'attributes':{'POSITION':0}}]},
                    {'primitives':[{'attributes':{'POSITION':1}}]}],
          'nodes':[{'mesh':0},{'mesh':1}],
          'scenes':[{'nodes':[0,1]}],'scene':0}
    data=json.dumps(gltf,separators=(',',':')).encode()
    data+=b' ' * (-len(data)%4)
    return (struct.pack('<4sII',b'glTF',2,12+8+len(data)+8+len(binary))+
            struct.pack('<I4s',len(data),b'JSON')+data+
            struct.pack('<I4s',len(binary),b'BIN\x00')+binary)

class CrossingTests(unittest.TestCase):
    def test_real_non_coplanar_interior_pierce_is_measured(self):
        self.assertTrue(c.strict_crossing(A,B))
        result=c.inspect(two_groups(B),[[0,0,1,0]])
        self.assertEqual(result['strict_surface_crossing_pairs_found'],1)
        self.assertEqual(result['candidate_triangle_pairs_tested'],1)
        self.assertTrue(result['all_requested_pairs_fully_scanned'])
        self.assertEqual(result['individual_mg0'],'UNKNOWN')
        self.assertFalse(result['advancement_authorized'])
    def test_coplanar_and_touch_are_not_certified(self):
        for tri in (COPLANAR,TOUCH):
            with self.subTest(tri=tri):
                self.assertFalse(c.strict_crossing(A,tri))
                result=c.inspect(two_groups(tri),[[0,0,1,0]])
                self.assertEqual(result['strict_surface_crossing_pairs_found'],0)
                self.assertEqual(result['contact_and_coplanar_cases'],'NOT_COVERED')
                self.assertEqual(result['defect_classification'],'UNKNOWN_REQUIRES_ASSET_RULE_CONTEXT')
    def test_budget_is_never_silent(self):
        rows=[{'key':(0,0),'triangles':[A]*4},{'key':(1,0),'triangles':[B]*4}]
        r=c.inspect(rows,[[0,0,1,0]],max_tests=1)
        self.assertFalse(r['all_requested_pairs_fully_scanned'])
        self.assertTrue(r['unresolved_pairs'])
        self.assertEqual(r['candidate_triangle_pairs_tested'],1)
        self.assertFalse(r['advancement_authorized'])
    def test_wrong_group_does_not_disappear(self):
        r=c.inspect(two_groups(B),[[0,0,9,0]])
        self.assertFalse(r['all_requested_pairs_fully_scanned'])
        self.assertEqual(r['unresolved_pairs'][0]['reason'],'CROSSING_GROUP_MISSING')
    def test_scanner_reports_actual_strict_crossings_but_not_semantic_pass(self):
        r=audit_bytes(tiny_two_group_glb(B))
        self.assertGreaterEqual(r['aabb_overlap_candidates_count'],1)
        e=r['triangle_surface_crossing_evidence']
        self.assertEqual(e['strict_surface_crossing_pairs_found'],1)
        self.assertEqual(r['overall_rule_semantics'],'UNKNOWN')
        self.assertEqual(r['asset_acceptance'],'NOT_AUTHORIZED')
        self.assertEqual(r['mg0'],'UNKNOWN')
        self.assertNotEqual(r['machine_evidence_status'],'FAIL')
    def test_scanner_coplanar_remains_unresolved(self):
        r=audit_bytes(tiny_two_group_glb(COPLANAR))
        e=r['triangle_surface_crossing_evidence']
        self.assertEqual(e['strict_surface_crossing_pairs_found'],0)
        self.assertEqual(e['contact_and_coplanar_cases'],'NOT_COVERED')
        self.assertEqual(r['overall_rule_semantics'],'UNKNOWN')

if __name__=='__main__':
    unittest.main()
