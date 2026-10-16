"""C07 index-topology GLB orientation regressions: no artistic or MG0 PASS."""
import hashlib
import unittest

from glb_winding_readback import scan_bytes, WindingBlocked
from test_glb_machine_qa import synthetic_glb


def audit(vertices, indices):
    raw = synthetic_glb(triangles=vertices, indexes=indices)
    return scan_bytes(raw, hashlib.sha256(raw).hexdigest())


V = [(0., 0., 0.), (1., 0., 0.), (0., 1., 0.), (1., 1., 0.)]


class IndexedWindingTests(unittest.TestCase):
    def test_single_triangle_has_open_boundary_not_a_false_winding_error(self):
        r = audit(V[:3], [0, 1, 2])
        self.assertEqual(r['mesh_count'], 1)
        self.assertEqual(r['boundary_edges'], 3)
        self.assertEqual(r['orientation_conflict_meshes'], 0)
        self.assertEqual(r['consistent_meshes'], 1)
        self.assertEqual(r['index_topology_closed_meshes'], 0)
        self.assertFalse(r['asset_approved'])
        self.assertFalse(r['advancement_authorized'])

    def test_adjacent_triangles_with_opposite_edge_winding_are_coherent(self):
        r = audit(V, [0, 1, 2, 2, 1, 3])
        self.assertEqual(r['triangles_examined'], 2)
        self.assertEqual(r['orientation_conflict_meshes'], 0)
        self.assertEqual(r['same_direction_shared_edges'], 0)
        self.assertEqual(r['boundary_edges'], 4)
        self.assertEqual(r['artistic_qa'], 'UNKNOWN')

    def test_shared_edge_same_direction_is_an_independently_detectable_issue(self):
        r = audit(V, [0, 1, 2, 1, 2, 3])
        self.assertEqual(r['orientation_conflict_meshes'], 1)
        self.assertEqual(r['same_direction_shared_edges'], 1)
        self.assertEqual(r['flagged_meshes'][0]['mesh_index'], 0)
        self.assertEqual(r['flagged_meshes'][0]['triangle_count'], 2)
        self.assertEqual(r['topology_observation'],
                         'SOURCE_EDGE_ORIENTATION_CONFLICT_OBSERVED')
        self.assertEqual(r['individual_mg0'], 'UNKNOWN')
        self.assertFalse(r['advancement_authorized'])

    def test_closed_consistently_wound_tetrahedron(self):
        v = [(0.,0.,0.), (1.,0.,0.), (0.,1.,0.), (0.,0.,1.)]
        r = audit(v, [0,2,1, 0,1,3, 1,2,3, 2,0,3])
        self.assertEqual(r['index_topology_closed_meshes'], 1)
        self.assertEqual(r['consistent_meshes'], 1)
        self.assertEqual(r['boundary_edges'], 0)
        self.assertEqual(r['nonmanifold_edges'], 0)
        self.assertEqual(r['orientation_conflict_meshes'], 0)
        self.assertFalse(r['asset_approved'])

    def test_reversed_tetra_face_blocks_coherent_winding(self):
        v = [(0.,0.,0.), (1.,0.,0.), (0.,1.,0.), (0.,0.,1.)]
        r = audit(v, [0,1,2, 0,1,3, 1,2,3, 2,0,3])
        self.assertEqual(r['index_topology_closed_meshes'], 1)
        self.assertEqual(r['orientation_conflict_meshes'], 1)
        self.assertEqual(r['same_direction_shared_edges'], 3)

    def test_nonmanifold_three_faces_sharing_edge_is_not_missed(self):
        v = V + [(0.5, 0.5, 1.)]
        r = audit(v, [0,1,2, 1,0,3, 0,1,4])
        self.assertEqual(r['nonmanifold_edges'], 1)
        self.assertEqual(r['orientation_conflict_meshes'], 1)

    def test_corrupt_digest_and_indices_fail_before_evidence(self):
        raw = synthetic_glb(triangles=V, indexes=[0,1,2])
        with self.assertRaisesRegex(WindingBlocked, 'SOURCE_SHA256_DRIFT'):
            scan_bytes(raw, '0'*64)
        raw = synthetic_glb(triangles=V, indexes=[0,1,9])
        with self.assertRaisesRegex(WindingBlocked, 'INVALID_TRIANGLE_INDICES'):
            scan_bytes(raw, hashlib.sha256(raw).hexdigest())

    def test_degenerate_index_triangle_rejected(self):
        raw = synthetic_glb(triangles=V, indexes=[0, 0, 1])
        with self.assertRaisesRegex(WindingBlocked, 'DEGENERATE_INDEX_TRIANGLE'):
            scan_bytes(raw, hashlib.sha256(raw).hexdigest())


if __name__ == '__main__':
    unittest.main()
