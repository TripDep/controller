"""P5 original-byte optimization: positive/negative/adversarial fixture tests.

The fixtures demonstrate only the verifier's behavior, not production
FiveM performance, visual quality, individual MG0 or owner approval.
"""
import copy
import json
import struct
import unittest
from pathlib import Path

import test_c07_positive_native_process as fixture
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import with_embedded_texture, QUAD, NORMALS
from c07_p345_forty_native_evidence import TEXT
from c07_p5_optimization_semantics import (
    IDS, inspect, OriginalOptimizationBlocked,
)
from c07_positive_native_process import NativeEvidenceBlocked

BUDGET = {
    "lod_max_triangle_ratio": 0.5, "lod_bounds_tolerance_m": 0.0,
    "min_shared_texture_bindings": 2, "max_alpha_triangles": 2,
}

def rewrite_glb(raw, update):
    jsz = struct.unpack_from("<I", raw, 12)[0]
    doc = json.loads(raw[20:20+jsz])
    binary = raw[28+jsz:]
    update(doc)
    js = json.dumps(doc, separators=(",", ":")).encode()
    js += b" " * (-len(js) % 4)
    return (struct.pack("<4sII", b"glTF", 2, 28+len(js)+len(binary)) +
            struct.pack("<I4s", len(js), b"JSON") + js +
            struct.pack("<I4s", len(binary), b"BIN\x00") + binary)

def materials(doc):
    m = doc["materials"][0]
    m["normalTexture"] = {"index": 0}
    m["alphaMode"] = "MASK"

class Tests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"] = "P5"
        self.f.work["phase"] = "P5"
        for n, rid in zip((143,145,147,149,150), IDS):
            literal, phase = TEXT[str(n)]
            self.f.inv["rules"][rid] = {
                "family": "AAA-200", "catalog_number": n,
                "catalog_section": "O", "catalog_phase": phase,
                "requirement": literal,
                "requirement_sha256": fixture.sha(literal.encode()),
                "source_sha256": "c"*64,
            }
        self.native = rewrite_glb(
            with_embedded_texture(glb(QUAD, [(0,1,2),(0,2,3)], NORMALS)),
            materials)
        self.lod = glb(QUAD[:3], [(0,1,2)], NORMALS[:3])
        self.put()

    def put(self, *, budget=None, native=None, lod=None, capture=None):
        self.f.add_item("NATIVE_EXPORT", "scene.glb",
                        self.native if native is None else native)
        self.f.add_item("LOD_EXPORT", "lod.glb",
                        self.lod if lod is None else lod)
        self.f.add_item("P5_PERF_BUDGET", "p5_budget.json",
                        json.dumps(BUDGET if budget is None else budget).encode())
        if capture is not None:
            self.f.add_item("P5_RUNTIME_CAPTURE", "p5_runtime.json",
                            json.dumps(capture).encode())
        self.f.plan["p345_evidence_contract"] = {
            "original_artifact_sha256": {
                role: item["sha256"] for role, item in self.f.items.items()
                if role in ("NATIVE_EXPORT", "LOD_EXPORT",
                            "P5_PERF_BUDGET", "P5_RUNTIME_CAPTURE")}}
        self.f.rebuild()

    def examine(self):
        return inspect(self.f.inv, self.f.plan, self.f.controller,
                       self.f.asset, self.f.step, self.f.work,
                       source_loader=lambda p: Path(p).read_bytes())

    def test_four_scoped_positive_observations_and_runtime_unknown(self):
        r = self.examine()
        self.assertEqual(set(r["rules"]), set(IDS))
        self.assertEqual(r["machine_positive_obligations"], 4)
        self.assertEqual(r["metrics"]["native_triangles"], 2)
        self.assertEqual(r["metrics"]["lod_triangles"], 1)
        self.assertEqual(r["metrics"]["alpha_triangles"], 2)
        self.assertEqual(r["metrics"]["texture_binding_count"], 2)
        self.assertEqual(r["rules"][IDS[4]]["machine_scope"], "UNKNOWN_OR_DEFECT")
        self.assertEqual(r["full_rule_semantic_passes"], 0)
        self.assertEqual(r["individual_mg0_passes"], 0)
        self.assertFalse(r["advancement_authorized"])

    def test_each_original_rule_has_distinct_negative_case(self):
        negative = {
            143: {"native": glb(QUAD, [(0,1,2),(2,1,0)], NORMALS)},
            145: {"lod": glb(QUAD, [(0,1,2),(0,2,3)], NORMALS)},
            147: {"native": with_embedded_texture(
                glb(QUAD, [(0,1,2),(0,2,3)], NORMALS))},
            149: {"budget": dict(BUDGET, max_alpha_triangles=1)},
            150: {"capture": {"frame_ms_samples": [16.0]*20}},
        }
        for i, kwargs in negative.items():
            with self.subTest(rule=i):
                self.put(**kwargs)
                row = self.examine()["rules"]["AAA-200-O-%03d" % i]
                self.assertEqual(row["machine_scope"], "UNKNOWN_OR_DEFECT")
                self.assertEqual(row["individual_mg0"], "UNKNOWN")
                self.put()

    def test_untrusted_runtime_samples_never_become_game_pass(self):
        self.put(capture={"frame_ms_samples": [15.0]*30,
                          "origin": "self_reported_fivem"})
        r = self.examine()
        checks = r["rules"][IDS[4]]["original_machine_checks"]
        self.assertTrue(checks["source_runtime_sample_vector_structurally_valid"])
        self.assertFalse(checks["independent_fivem_runtime_provenance_confirmed"])
        self.assertEqual(r["full_rule_semantic_passes"], 0)

    def test_missing_pre_d_pins_remain_unknown(self):
        self.f.plan["p345_evidence_contract"]["original_artifact_sha256"].clear()
        self.f.rebuild()
        r = self.examine()
        self.assertEqual(r["machine_positive_obligations"], 0)

    def test_original_bytes_tamper_and_attempt_replay_fail_closed(self):
        (self.f.root / "scene.glb").write_bytes(b"forged")
        with self.assertRaisesRegex(NativeEvidenceBlocked, "ARTIFACT_BYTES_CHANGED"):
            self.examine()
        self.put()
        self.f.work["attempt_id"] = "f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked, "EXACT_RESERVED_WORK"):
            self.examine()

    def test_changed_canonical_literal_fails_closed(self):
        self.f.inv["rules"][IDS[0]]["requirement"] = "replacement"
        with self.assertRaisesRegex(OriginalOptimizationBlocked,
                                    "OPTIMIZATION_LITERAL_CHANGED"):
            self.examine()

    def test_duplicate_original_budget_json_key_rejected(self):
        self.f.add_item("P5_PERF_BUDGET", "p5_budget.json",
                        b'{"max_alpha_triangles":2,"max_alpha_triangles":999}')
        self.f.plan["p345_evidence_contract"]["original_artifact_sha256"][
            "P5_PERF_BUDGET"] = self.f.items["P5_PERF_BUDGET"]["sha256"]
        self.f.rebuild()
        with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
            self.examine()

if __name__ == "__main__":
    unittest.main()
