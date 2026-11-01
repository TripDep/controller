"""Adversarial original-GLB UV tests for L-115/116/117; no MG0."""
import json
import struct
import unittest
from pathlib import Path

import test_c07_positive_native_process as fixture
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import with_embedded_texture
from c07_p345_forty_native_evidence import TEXT
from c07_p3_uv_semantics import IDS,inspect,OriginalUVBlocked
from c07_positive_native_process import NativeEvidenceBlocked

QUAD=[(0,0,0),(1,0,0),(1,1,0),(0,1,0)]
UV=[(0,0),(1,0),(1,1),(0,1)]
UP=[(0,0,1)]*4
POLICY={
    "meters_per_unit":1,"max_uv_edge_anisotropy":1.05,
    "texel_px_per_m":2,"texel_density_tolerance_pct":5,
    "uv_overlap_policy":"NO_UNINTENDED_OVERLAPS",
}

def uv_glb(points=QUAD,faces=None,uv=UV,with_texture=True):
    if faces is None:faces=[(0,1,2),(0,2,3)]
    raw=glb(points,faces,[(0,0,1)]*len(points))
    if with_texture:raw=with_embedded_texture(raw)
    jsz=struct.unpack_from("<I",raw,12)[0]
    doc=json.loads(raw[20:20+jsz])
    data=bytearray(raw[28+jsz:])
    off=len(data)
    uv_data=struct.pack("<"+"f"*len(uv)*2,
                        *(c for point in uv for c in point))
    data.extend(uv_data)
    data.extend(b"\x00"*(-len(data)%4))
    doc["bufferViews"].append({"buffer":0,"byteOffset":off,
                               "byteLength":len(uv_data)})
    doc["accessors"].append({"bufferView":len(doc["bufferViews"])-1,
                             "componentType":5126,"count":len(uv),
                             "type":"VEC2"})
    doc["meshes"][0]["primitives"][0]["attributes"]["TEXCOORD_0"]=len(
        doc["accessors"])-1
    doc["buffers"][0]["byteLength"]=len(data)
    js=json.dumps(doc,separators=(",",":")).encode()
    js+=b" "*(-len(js)%4)
    return (struct.pack("<4sII",b"glTF",2,28+len(js)+len(data))+
            struct.pack("<I4s",len(js),b"JSON")+js+
            struct.pack("<I4s",len(data),b"BIN\x00")+bytes(data))

class Tests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"]="P3"
        self.f.work["phase"]="P3"
        for n,rid in zip((115,116,117),IDS):
            source,phase=TEXT[str(n)]
            self.f.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":"L","catalog_phase":phase,
                "requirement":source,
                "requirement_sha256":fixture.sha(source.encode()),
                "source_sha256":"c"*64}
        self.native=uv_glb()
        self.put()

    def put(self,native=None,policy=None):
        self.f.add_item("NATIVE_EXPORT","scene.glb",
                        self.native if native is None else native)
        self.f.add_item("P3_UV_POLICY","uv_policy.json",
                        json.dumps(POLICY if policy is None else policy).encode())
        self.f.plan["p345_evidence_contract"]={
            "original_artifact_sha256":{
                role:self.f.items[role]["sha256"]
                for role in ("NATIVE_EXPORT","P3_UV_POLICY")}}
        self.f.rebuild()

    def examine(self):
        return inspect(self.f.inv,self.f.plan,self.f.controller,
                       self.f.asset,self.f.step,self.f.work,
                       source_loader=lambda p:Path(p).read_bytes())

    def test_three_actual_uv_oracles_are_not_full_rule_or_mg0(self):
        r=self.examine()
        self.assertEqual(set(r["rules"]),set(IDS))
        self.assertEqual(r["machine_positive_obligations"],3)
        self.assertEqual(r["original_uv_metrics"]["triangles"],2)
        self.assertEqual(r["original_uv_metrics"]["uv_overlap_pairs"],0)
        self.assertEqual(r["original_uv_metrics"]["measured_density_edges"],6)
        self.assertEqual(r["full_rule_semantic_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertFalse(r["advancement_authorized"])

    def test_real_uv_anisotropy_violation(self):
        self.put(native=uv_glb(uv=[(0,0),(1,0),(1,0.1),(0,0.1)]))
        r=self.examine()
        self.assertEqual(r["rules"][IDS[0]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")
        self.assertEqual(r["rules"][IDS[1]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_overlapping_original_uv_triangles_detected(self):
        self.put(native=uv_glb(faces=[(0,1,2),(0,1,2)]))
        r=self.examine()
        self.assertGreater(r["original_uv_metrics"]["uv_overlap_pairs"],0)
        self.assertEqual(r["rules"][IDS[2]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_real_embedded_texture_density_target_mismatch(self):
        self.put(policy=dict(POLICY,texel_px_per_m=10))
        self.assertEqual(self.examine()["rules"][IDS[1]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_unlinked_or_missing_image_not_texel_proof(self):
        self.put(native=uv_glb(with_texture=False))
        r=self.examine()
        self.assertEqual(r["rules"][IDS[1]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")
        self.assertEqual(r["rules"][IDS[0]]["machine_scope"],
                         "OBSERVED_SCOPE_PASS")

    def test_missing_original_policy_pin_cannot_pass(self):
        self.f.plan["p345_evidence_contract"]["original_artifact_sha256"].pop(
            "P3_UV_POLICY")
        self.f.rebuild()
        self.assertEqual(self.examine()["machine_positive_obligations"],0)

    def test_zero_uv_triangle_area_rejected(self):
        self.put(native=uv_glb(uv=[(0,0),(1,0),(2,0),(0,1)]))
        with self.assertRaisesRegex(OriginalUVBlocked,"ZERO_AREA"):
            self.examine()

    def test_changed_registered_source_fails_closed(self):
        (self.f.root/"scene.glb").write_bytes(b"tampered")
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "ARTIFACT_BYTES_CHANGED"):
            self.examine()

    def test_cross_attempt_replay_rejected(self):
        self.f.work["attempt_id"]="f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "EXACT_RESERVED_WORK"):
            self.examine()

    def test_original_rule_literal_cannot_be_replaced(self):
        self.f.inv["rules"][IDS[0]]["requirement"]="forged"
        with self.assertRaisesRegex(OriginalUVBlocked,
                                    "ORIGINAL_LITERAL_CHANGED"):
            self.examine()

if __name__=="__main__":
    unittest.main()
