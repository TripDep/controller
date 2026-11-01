"""P4 pixel/texture oracles: original-byte positive and adversarial fixtures.

This does not certify material realism, shader support in FiveM, owner
acceptance or MG0; every result is scoped to independently decoded bytes.
"""
import copy
import json
import struct
import unittest
import zlib
from pathlib import Path

import test_c07_positive_native_process as fixture
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import with_embedded_texture, QUAD, NORMALS
from test_c07_p5_optimization_semantics import rewrite_glb
from c07_p345_forty_native_evidence import TEXT
from c07_p4_texture_semantics import IDS, inspect, OriginalPixelBlocked
from c07_positive_native_process import NativeEvidenceBlocked

def png(pixels):
    width = height = 4
    def chunk(tag, data):
        return (struct.pack(">I",len(data))+tag+data+
                struct.pack(">I",zlib.crc32(tag+data)&0xffffffff))
    header = struct.pack(">IIBBBBB",width,height,8,6,0,0,0)
    raw = b"".join(b"\x00"+b"".join(bytes(px) for px in row)
                   for row in pixels)
    return (b"\x89PNG\r\n\x1a\n"+chunk(b"IHDR",header)+
            chunk(b"IDAT",zlib.compress(raw))+chunk(b"IEND",b""))

def gradient():
    return [[(20+30*y+10*x,20+30*y+10*x,20+30*y+10*x,255)
             for x in range(4)] for y in range(4)]

def solid(v):
    return [[(v,v,v,255) for _ in range(4)] for _ in range(4)]

def material(doc):
    m=doc["materials"][0]
    m["name"]="stone"
    m["pbrMetallicRoughness"]["roughnessFactor"]=0.7
    m["pbrMetallicRoughness"]["metallicFactor"]=0.0

POLICY = {
    "min_distinct_rgb":4, "min_luminance_variance":50.0,
    "max_luminance_variance":20000.0, "min_quadrant_luma_delta":10.0,
    "min_texture_side_px":4, "max_texture_side_px":1024,
    "max_png_bytes":10000, "allowed_material_names":["stone"],
}

class Tests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"]="P4"
        self.f.work["phase"]="P4"
        for n,rid in zip((124,125,127,128,129,130),IDS):
            literal,phase=TEXT[str(n)]
            self.f.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":"M","catalog_phase":phase,
                "requirement":literal,
                "requirement_sha256":fixture.sha(literal.encode()),
                "source_sha256":"c"*64,
            }
        self.native = rewrite_glb(with_embedded_texture(
            glb(QUAD,[(0,1,2),(0,2,3)],NORMALS),png(gradient())),material)
        self.policy = copy.deepcopy(POLICY)
        self.views = {"P4_VIEW_NEUTRAL":png(solid(90)),
                      "P4_VIEW_DIRECT":png(solid(180)),
                      "P4_VIEW_SHADOW":png(solid(30))}
        self.put()

    def put(self):
        self.f.add_item("NATIVE_EXPORT","scene.glb",self.native)
        self.f.add_item("P4_TEXTURE_POLICY","p4_policy.json",
                        json.dumps(self.policy).encode())
        for role,raw in self.views.items():
            self.f.add_item(role,role.lower()+".png",raw)
        roles = {"NATIVE_EXPORT","P4_TEXTURE_POLICY"} | set(self.views)
        self.f.plan["p345_evidence_contract"]={
            "original_artifact_sha256":{
                role:self.f.items[role]["sha256"] for role in roles}}
        self.f.rebuild()

    def examine(self):
        return inspect(self.f.inv,self.f.plan,self.f.controller,
                       self.f.asset,self.f.step,self.f.work,
                       source_loader=lambda p:Path(p).read_bytes())

    def test_six_original_pixel_oracles_observed_not_approved(self):
        r=self.examine()
        self.assertEqual(set(r["rules"]),set(IDS))
        self.assertEqual(r["machine_positive_obligations"],6)
        self.assertEqual(r["metrics"]["decoded_original_textures"],1)
        self.assertEqual(r["metrics"]["neutral_direct_shadow_means"],
                         [90.0,180.0,30.0])
        self.assertEqual(r["full_rule_semantic_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertFalse(r["advancement_authorized"])

    def test_each_literal_rule_has_independent_negative(self):
        def uniform():
            return rewrite_glb(with_embedded_texture(
                glb(QUAD,[(0,1,2),(0,2,3)],NORMALS),png(solid(50))),material)
        mutations = {
            124: ("native",uniform()),
            125: ("policy",dict(POLICY,min_quadrant_luma_delta=250.0)),
            127: ("policy",dict(POLICY,min_luminance_variance=10000.0)),
            128: ("policy",dict(POLICY,max_png_bytes=64)),
            129: ("policy",dict(POLICY,allowed_material_names=["metal"])),
            130: ("views",dict(self.views,
                              P4_VIEW_DIRECT=png(solid(20)))),
        }
        for n,(field,bad) in mutations.items():
            with self.subTest(rule=n):
                old=copy.deepcopy(getattr(self,field))
                setattr(self,field,bad)
                self.put()
                row=self.examine()["rules"]["AAA-200-M-%03d"%n]
                self.assertEqual(row["machine_scope"],"UNKNOWN_OR_DEFECT")
                self.assertEqual(row["individual_mg0"],"UNKNOWN")
                setattr(self,field,old)
                self.put()

    def test_no_original_pre_d_pins_no_positive(self):
        self.f.plan["p345_evidence_contract"]["original_artifact_sha256"].clear()
        self.f.rebuild()
        self.assertEqual(self.examine()["machine_positive_obligations"],0)

    def test_corrupt_original_png_pixels_cannot_pass(self):
        altered=bytearray(png(gradient()))
        altered[-10]^=0x01
        self.native=rewrite_glb(with_embedded_texture(
            glb(QUAD,[(0,1,2),(0,2,3)],NORMALS),bytes(altered)),material)
        self.put()
        r=self.examine()
        self.assertEqual(r["rules"][IDS[0]]["machine_scope"],"UNKNOWN_OR_DEFECT")
        self.assertEqual(r["rules"][IDS[3]]["machine_scope"],"UNKNOWN_OR_DEFECT")

    def test_tampered_original_bytes_and_cross_attempt_rejected(self):
        (self.f.root/"scene.glb").write_bytes(b"fake")
        with self.assertRaisesRegex(NativeEvidenceBlocked,"ARTIFACT_BYTES_CHANGED"):
            self.examine()
        self.put()
        self.f.work["attempt_id"]="f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,"EXACT_RESERVED_WORK"):
            self.examine()

    def test_original_literal_changed_rejected(self):
        self.f.inv["rules"][IDS[0]]["requirement"]="fake"
        with self.assertRaisesRegex(OriginalPixelBlocked,"PIXEL_LITERAL_CHANGED"):
            self.examine()

    def test_duplicate_pre_d_policy_json_key_rejected(self):
        self.f.add_item("P4_TEXTURE_POLICY","p4_policy.json",
                        b'{"min_distinct_rgb":4,"min_distinct_rgb":999}')
        self.f.plan["p345_evidence_contract"]["original_artifact_sha256"][
            "P4_TEXTURE_POLICY"]=self.f.items["P4_TEXTURE_POLICY"]["sha256"]
        self.f.rebuild()
        with self.assertRaisesRegex(ValueError,"DUPLICATE_JSON_KEY"):
            self.examine()

if __name__=="__main__":
    unittest.main()
