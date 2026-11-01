"""Adversarial original GLB triangle tests for four literal P3 requirements."""
import json
import struct
import unittest
from pathlib import Path

import test_c07_positive_native_process as fixture
from c07_p345_forty_native_evidence import TEXT
from c07_p3_geometry_semantics import (
    IDS, inspect, geometry, OriginalTopologyBlocked,
)
from c07_positive_native_process import NativeEvidenceBlocked

def glb(points, faces, normals=None):
    positions = struct.pack("<" + "f" * (len(points)*3),
                            *(c for p in points for c in p))
    data = positions
    views = [{"buffer": 0, "byteOffset": 0, "byteLength": len(positions)}]
    accessors = [{"bufferView": 0, "componentType": 5126,
                  "count": len(points), "type": "VEC3"}]
    attrs = {"POSITION": 0}
    if normals is not None:
        normal_data = struct.pack("<" + "f" * (len(normals)*3),
                                  *(c for p in normals for c in p))
        views.append({"buffer": 0, "byteOffset": len(data),
                      "byteLength": len(normal_data)})
        accessors.append({"bufferView": 1, "componentType": 5126,
                          "count": len(normals), "type": "VEC3"})
        attrs["NORMAL"] = 1
        data += normal_data
    indices = [i for face in faces for i in face]
    # Align index stream to 2 bytes.
    data += b"\x00" * (-len(data) % 2)
    index_offset = len(data)
    encoded = struct.pack("<" + "H" * len(indices), *indices)
    data += encoded
    views.append({"buffer": 0, "byteOffset": index_offset,
                  "byteLength": len(encoded)})
    accessors.append({"bufferView": len(views)-1, "componentType": 5123,
                      "count": len(indices), "type": "SCALAR"})
    data += b"\x00" * (-len(data) % 4)
    doc = {
        "asset": {"version": "2.0"},
        "buffers": [{"byteLength": len(data)}],
        "bufferViews": views, "accessors": accessors,
        "meshes": [{"primitives": [{"mode": 4, "attributes": attrs,
                                    "indices": len(accessors)-1}]}],
    }
    js = json.dumps(doc, separators=(",", ":")).encode()
    js += b" " * (-len(js) % 4)
    return (struct.pack("<4sII", b"glTF", 2,
                        12 + 8 + len(js) + 8 + len(data)) +
            struct.pack("<I4s", len(js), b"JSON") + js +
            struct.pack("<I4s", len(data), b"BIN\x00") + data)

TRI = [(0,0,0), (1,0,0), (0,1,0)]
UP = [(0,0,1)] * 3

class Tests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"] = "P3"
        self.f.work["phase"] = "P3"
        for n, rid in zip(range(111, 115), IDS):
            source, phase = TEXT[str(n)]
            self.f.inv["rules"][rid] = {
                "family": "AAA-200", "catalog_number": n,
                "catalog_section": "L", "catalog_phase": phase,
                "requirement": source,
                "requirement_sha256": fixture.sha(source.encode()),
                "source_sha256": "c"*64,
            }
        self.put(glb(TRI, [(0,1,2)], UP))

    def put(self, raw):
        self.f.add_item("NATIVE_EXPORT", "scene.glb", raw)
        self.f.rebuild()

    def examine(self):
        return inspect(self.f.inv, self.f.plan, self.f.controller,
                       self.f.asset, self.f.step, self.f.work,
                       source_loader=lambda p: Path(p).read_bytes())

    def test_four_real_per_rule_triangle_oracles_without_mg0_or_owner_pass(self):
        result = self.examine()
        self.assertEqual(set(result["rules"]), set(IDS))
        self.assertEqual(result["machine_positive_obligations"], 4)
        self.assertEqual(result["totals"]["triangles"], 1)
        self.assertEqual(result["totals"]["boundary_edges"], 3)
        self.assertEqual(result["full_rule_semantic_passes"], 0)
        self.assertEqual(result["individual_mg0_passes"], 0)
        self.assertFalse(result["advancement_authorized"])
        self.assertTrue(all(row["full_rule_semantics"] == "UNKNOWN"
                            for row in result["rules"].values()))

    def test_duplicate_geometric_face_detected_even_when_winding_reversed(self):
        self.put(glb(TRI, [(0,1,2), (2,1,0)], UP))
        r = self.examine()
        self.assertEqual(r["totals"]["duplicate_geometric_faces"], 1)
        self.assertEqual(r["rules"][IDS[1]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")
        self.assertEqual(r["full_rule_semantic_passes"], 0)

    def test_duplicate_coordinate_vertices_are_measured_not_silently_approved(self):
        points = TRI + [(0,0,0), (1,0,0), (0,1,0)]
        self.put(glb(points, [(0,1,2), (3,4,5)], UP*2))
        r = self.examine()
        self.assertEqual(r["totals"]["duplicate_coordinate_vertices"], 3)
        self.assertEqual(r["totals"]["duplicate_geometric_faces"], 1)

    def test_collinear_triangle_detected_as_degenerate(self):
        self.put(glb([(0,0,0), (1,0,0), (2,0,0)], [(0,1,2)], UP))
        r = self.examine()
        self.assertEqual(r["totals"]["degenerate_triangles"], 1)
        self.assertEqual(r["rules"][IDS[2]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_opposed_vertex_normals_detected(self):
        self.put(glb(TRI, [(0,1,2)], [(0,0,-1)]*3))
        r = self.examine()
        self.assertEqual(r["totals"]["opposed_face_normals"], 1)
        self.assertEqual(r["rules"][IDS[3]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_missing_normals_never_becomes_shading_pass(self):
        self.put(glb(TRI, [(0,1,2)]))
        self.assertEqual(self.examine()["rules"][IDS[3]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_malformed_glb_and_bad_index_fail_closed(self):
        bad = bytearray(glb(TRI, [(0,1,2)], UP))
        struct.pack_into("<I", bad, 8, len(bad)+1)
        with self.assertRaisesRegex(OriginalTopologyBlocked,
                                    "VERSION_LENGTH"):
            geometry(bytes(bad))
        with self.assertRaisesRegex(OriginalTopologyBlocked,
                                    "TRIANGLE_INDICES"):
            geometry(glb(TRI, [(0,1,99)], UP))

    def test_registered_binary_tamper_and_cross_attempt_replay_rejected(self):
        (self.f.root / "scene.glb").write_bytes(b"tampered")
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "ARTIFACT_BYTES_CHANGED"):
            self.examine()
        self.put(glb(TRI, [(0,1,2)], UP))
        self.f.work["attempt_id"] = "f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "EXACT_RESERVED_WORK"):
            self.examine()

    def test_changed_literal_original_source_rejected(self):
        self.f.inv["rules"][IDS[0]]["requirement"] = "Unreviewed substitute"
        with self.assertRaisesRegex(OriginalTopologyBlocked,
                                    "LITERAL_SOURCE_CHANGED"):
            self.examine()

if __name__ == "__main__":
    unittest.main()
