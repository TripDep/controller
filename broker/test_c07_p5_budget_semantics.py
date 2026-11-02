"""Adversarial original-byte tests for five exact P5 rules (not MG0)."""
import json
import struct
import unittest
import zlib
from pathlib import Path

import test_c07_positive_native_process as fixture
from test_c07_p3_geometry_semantics import glb
from c07_p345_forty_native_evidence import TEXT
from c07_p5_budget_semantics import IDS, inspect, OriginalBudgetBlocked
from c07_positive_native_process import NativeEvidenceBlocked

QUAD = [(0,0,0), (1,0,0), (1,1,0), (0,1,0)]
NORMALS = [(0,0,1)]*4

def png():
    def chunk(tag, data):
        return struct.pack(">I", len(data))+tag+data+struct.pack(
            ">I", zlib.crc32(tag+data)&0xffffffff)
    ihdr=struct.pack(">IIBBBBB", 2,2,8,6,0,0,0)
    scan=b"".join(b"\x00"+b"\xff\x00\x00\xff"*2 for _ in range(2))
    return b"\x89PNG\r\n\x1a\n"+chunk(b"IHDR",ihdr)+chunk(
        b"IDAT",zlib.compress(scan))+chunk(b"IEND",b"")

def with_embedded_texture(raw, image=None):
    jsz=struct.unpack_from("<I",raw,12)[0]
    doc=json.loads(raw[20:20+jsz])
    data=bytearray(raw[28+jsz:])
    img=png() if image is None else image
    off=len(data)
    data.extend(img)
    data.extend(b"\x00"*(-len(data)%4))
    doc["bufferViews"].append({"buffer":0,"byteOffset":off,"byteLength":len(img)})
    doc["images"]=[{"bufferView":len(doc["bufferViews"])-1,
                    "mimeType":"image/png"}]
    doc["textures"]=[{"source":0}]
    doc["materials"]=[{"pbrMetallicRoughness":{
        "baseColorTexture":{"index":0}}}]
    doc["meshes"][0]["primitives"][0]["material"]=0
    doc["buffers"][0]["byteLength"]=len(data)
    js=json.dumps(doc,separators=(",",":")).encode()
    js+=b" "*(-len(js)%4)
    return (struct.pack("<4sII",b"glTF",2,28+len(js)+len(data))+
            struct.pack("<I4s",len(js),b"JSON")+js+
            struct.pack("<I4s",len(data),b"BIN\x00")+bytes(data))

BUDGET={
    "platform":"GTA_V_FIVEM","scene_class":"outdoor-small",
    "max_triangles":2,"material_count_budget":1,
    "max_texture_mb":0.001,"lod_max_triangle_ratio":0.5,
    "lod_near_m":10,"lod_far_m":100,
}

class Tests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"]="P5"
        self.f.work["phase"]="P5"
        for number,rid in zip((141,142,144,146,148),IDS):
            original,phase=TEXT[str(number)]
            self.f.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":number,
                "catalog_section":"O","catalog_phase":phase,
                "requirement":original,
                "requirement_sha256":fixture.sha(original.encode()),
                "source_sha256":"c"*64,
            }
        self.native=with_embedded_texture(glb(
            QUAD,[(0,1,2),(0,2,3)],NORMALS))
        self.lod=glb(QUAD[:3],[(0,1,2)],NORMALS[:3])
        self.put()

    def put(self,budget=None,native=None,lod=None):
        raw=json.dumps(BUDGET if budget is None else budget,
                       separators=(",",":")).encode()
        self.f.add_item("P5_PERF_BUDGET","budget.json",raw)
        self.f.add_item("NATIVE_EXPORT","scene.glb",
                        self.native if native is None else native)
        self.f.add_item("LOD_EXPORT","lod.glb",
                        self.lod if lod is None else lod)
        self.f.plan["p345_evidence_contract"]={
            "original_artifact_sha256":{
                role:self.f.items[role]["sha256"]
                for role in ("P5_PERF_BUDGET","NATIVE_EXPORT","LOD_EXPORT")}}
        self.f.rebuild()

    def examine(self):
        return inspect(self.f.inv,self.f.plan,self.f.controller,
                       self.f.asset,self.f.step,self.f.work,
                       source_loader=lambda p:Path(p).read_bytes())

    def test_five_original_quantitative_oracles_no_mg0(self):
        r=self.examine()
        self.assertEqual(set(r["rules"]),set(IDS))
        self.assertEqual(r["machine_positive_obligations"],5)
        self.assertEqual(r["metrics"]["triangles"],2)
        self.assertEqual(r["metrics"]["lod_triangles"],1)
        self.assertEqual(r["metrics"]["materials"],1)
        self.assertEqual(r["metrics"]["rgba_uncompressed_bytes"],16)
        self.assertEqual(r["full_rule_semantic_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertFalse(r["advancement_authorized"])

    def test_real_triangle_budget_violation_detected(self):
        budget=dict(BUDGET,max_triangles=1)
        self.put(budget=budget)
        r=self.examine()
        self.assertEqual(r["rules"][IDS[1]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")
        self.assertEqual(r["rules"][IDS[0]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_lod_not_reduced_is_not_a_positive(self):
        self.put(lod=glb(QUAD,[(0,1,2),(0,2,3)],NORMALS))
        self.assertEqual(self.examine()["rules"][IDS[2]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_material_budget_exceeded(self):
        self.put(budget=dict(BUDGET,material_count_budget=0))
        self.assertEqual(self.examine()["rules"][IDS[3]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_real_texture_budget_exceeded(self):
        self.put(budget=dict(BUDGET,max_texture_mb=0.000001))
        self.assertEqual(self.examine()["rules"][IDS[4]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_malformed_png_is_not_texture_pass(self):
        self.put(native=with_embedded_texture(glb(
            QUAD,[(0,1,2),(0,2,3)],NORMALS),b"not-an-image"))
        self.assertEqual(self.examine()["rules"][IDS[4]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_missing_original_pre_d_pin_cannot_be_positive(self):
        self.f.plan["p345_evidence_contract"]["original_artifact_sha256"].pop(
            "P5_PERF_BUDGET")
        self.f.rebuild()
        r=self.examine()
        self.assertEqual(r["machine_positive_obligations"],0)

    def test_registered_binary_tamper_fails_closed(self):
        (self.f.root/"scene.glb").write_bytes(b"changed")
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "ARTIFACT_BYTES_CHANGED"):
            self.examine()

    def test_cross_attempt_replay_rejected(self):
        self.f.work["attempt_id"]="f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "EXACT_RESERVED_WORK"):
            self.examine()

    def test_changed_literal_canonical_source_rejected(self):
        self.f.inv["rules"][IDS[0]]["requirement"]="forged"
        with self.assertRaisesRegex(OriginalBudgetBlocked,
                                    "ORIGINAL_LITERAL_CHANGED"):
            self.examine()

    def test_duplicate_budget_keys_rejected(self):
        self.f.add_item("P5_PERF_BUDGET","budget.json",
                        b'{"platform":"GTA_V_FIVEM","platform":"FAKE"}')
        self.f.plan["p345_evidence_contract"]["original_artifact_sha256"][
            "P5_PERF_BUDGET"]=self.f.items["P5_PERF_BUDGET"]["sha256"]
        self.f.rebuild()
        with self.assertRaisesRegex(OriginalBudgetBlocked,
                                    "DUPLICATE_JSON_KEY"):
            self.examine()

if __name__=="__main__":
    unittest.main()
