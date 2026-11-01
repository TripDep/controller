"""P3 L-118/119/120 original-byte positive and adversarial tests.

All geometry and PNGs are synthetic fixtures. These tests do not attest an
actual bake, owner-approved baseline, artistic result or MG0.
"""
import copy
import json
import unittest
from pathlib import Path

import test_c07_positive_native_process as fixture
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import (
    QUAD,NORMALS,with_embedded_texture,png as atlas_png,
)
from test_c07_p5_optimization_semantics import rewrite_glb
from test_c07_p7_rage_semantics import png as view_png
from c07_p345_forty_native_evidence import TEXT
from c07_p3_finalization_semantics import IDS,inspect,OriginalFinalizationBlocked
from c07_positive_native_process import NativeEvidenceBlocked

def twin(doc):
    prim=copy.deepcopy(doc["meshes"][0]["primitives"][0])
    doc["meshes"][0]["primitives"].append(prim)
    doc["materials"][0]["normalTexture"]={"index":0}

class Tests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"]="P3"
        self.f.work["phase"]="P3"
        for n,rid in zip((118,119,120),IDS):
            literal,phase=TEXT[str(n)]
            self.f.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":"L","catalog_phase":phase,
                "requirement":literal,
                "requirement_sha256":fixture.sha(literal.encode()),
                "source_sha256":"c"*64,
            }
        self.native=rewrite_glb(with_embedded_texture(
            glb(QUAD,[(0,1,2)],NORMALS),atlas_png()),twin)
        self.high=glb(QUAD,[(0,1,2),(0,2,3),(0,1,3),(1,2,3)],NORMALS)
        self.reference=self.native
        self.atlas={"max_images":1,"min_primitives_per_atlas":2,
                    "expected_atlas_image_sha256":fixture.sha(atlas_png())}
        self.bake={"high_poly_sha256":fixture.sha(self.high),
                   "low_poly_sha256":fixture.sha(self.native),
                   "min_high_to_low_triangle_ratio":1.5}
        self.compare={"reference_sha256":fixture.sha(self.reference),
                      "max_vertex_delta_m":0.0}
        self.put()

    def put(self):
        self.f.add_item("NATIVE_EXPORT","scene.glb",self.native)
        self.f.add_item("P3_HIGH_POLY_SOURCE","high.glb",self.high)
        self.f.add_item("P3_APPROVED_REFERENCE","reference.glb",self.reference)
        self.f.add_item("P3_ATLAS_PLAN","atlas.json",json.dumps(self.atlas).encode())
        self.f.add_item("P3_BAKE_PLAN","bake.json",json.dumps(self.bake).encode())
        self.f.add_item("P3_APPROVED_COMPARISON","compare.json",
                        json.dumps(self.compare).encode())
        self.f.add_item("P3_COMPARE_FRONT","front.png",
                        view_png((255,0,0,255)))
        self.f.add_item("P3_COMPARE_SIDE","side.png",
                        view_png((0,255,0,255)))
        roles=("NATIVE_EXPORT","P3_HIGH_POLY_SOURCE","P3_APPROVED_REFERENCE",
               "P3_ATLAS_PLAN","P3_BAKE_PLAN","P3_APPROVED_COMPARISON",
               "P3_COMPARE_FRONT","P3_COMPARE_SIDE")
        self.f.plan["p345_evidence_contract"]={
            "original_artifact_sha256":{
                role:self.f.items[role]["sha256"] for role in roles}}
        self.f.rebuild()

    def examine(self):
        return inspect(self.f.inv,self.f.plan,self.f.controller,
                       self.f.asset,self.f.step,self.f.work,
                       source_loader=lambda p:Path(p).read_bytes())

    def test_three_scoped_original_oracles_not_full_approval(self):
        r=self.examine()
        self.assertEqual(set(r["rules"]),set(IDS))
        self.assertEqual(r["machine_positive_obligations"],3)
        self.assertEqual(r["metrics"]["native_triangles"],2)
        self.assertEqual(r["metrics"]["high_poly_triangles"],4)
        self.assertEqual(r["metrics"]["atlas_max_primitive_sharing"],2)
        self.assertEqual(r["metrics"]["comparison_views"],2)
        self.assertEqual(r["full_rule_semantic_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertFalse(r["advancement_authorized"])

    def test_each_rule_has_distinct_adversarial_negative(self):
        changes={
            118:("atlas","max_images",0),
            119:("bake","min_high_to_low_triangle_ratio",10.0),
            120:("compare","reference_sha256","0"*64),
        }
        for n,(name,key,bad) in changes.items():
            with self.subTest(rule=n):
                obj=getattr(self,name)
                old=obj[key]
                obj[key]=bad
                self.put()
                row=self.examine()["rules"]["AAA-200-L-%03d"%n]
                self.assertEqual(row["machine_scope"],"UNKNOWN_OR_DEFECT")
                self.assertEqual(row["individual_mg0"],"UNKNOWN")
                obj[key]=old
                self.put()

    def test_missing_pre_d_pins_never_positive(self):
        self.f.plan["p345_evidence_contract"]["original_artifact_sha256"].clear()
        self.f.rebuild()
        self.assertEqual(self.examine()["machine_positive_obligations"],0)

    def test_corrupt_original_atlas_png_is_not_positive(self):
        bad=bytearray(atlas_png())
        bad[-8]^=1
        self.native=rewrite_glb(with_embedded_texture(
            glb(QUAD,[(0,1,2)],NORMALS),bytes(bad)),twin)
        self.put()
        self.assertEqual(self.examine()["rules"][IDS[0]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_original_binary_tamper_and_attempt_replay_rejected(self):
        (self.f.root/"scene.glb").write_bytes(b"fake")
        with self.assertRaisesRegex(NativeEvidenceBlocked,"ARTIFACT_BYTES_CHANGED"):
            self.examine()
        self.put()
        self.f.work["attempt_id"]="f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,"EXACT_RESERVED_WORK"):
            self.examine()

    def test_changed_canonical_literal_rejected(self):
        self.f.inv["rules"][IDS[0]]["requirement"]="fake"
        with self.assertRaisesRegex(OriginalFinalizationBlocked,
                                    "FINALIZATION_LITERAL_CHANGED"):
            self.examine()

if __name__=="__main__":
    unittest.main()
