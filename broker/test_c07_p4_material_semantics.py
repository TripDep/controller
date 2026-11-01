"""Adversarial original GLB material tests for four literal P4 rules."""
import json
import struct
import unittest
from pathlib import Path

import test_c07_positive_native_process as fixture
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import with_embedded_texture
from c07_p345_forty_native_evidence import TEXT
from c07_p4_material_semantics import IDS,inspect,OriginalMaterialBlocked
from c07_positive_native_process import NativeEvidenceBlocked

CLASSES=("wood","stone","metal","glass","plaster")
PAIRS=((0.8,0),(0.65,0),(0.2,1),(0.05,0),(0.9,0))
PLAN={"physical_materials":[
    {"name":c.upper(),"class":c,"roughness_target":r,
     "metallic_target":m} for c,(r,m) in zip(CLASSES,PAIRS)],
    "roughness_tolerance":0.01}

def material_glb(*,remove_normal=False,roughness_override=None,
                 remove_class=None):
    raw=with_embedded_texture(glb(
        [(0,0,0),(1,0,0),(0,1,0)],[(0,1,2)],[(0,0,1)]*3))
    jsz=struct.unpack_from("<I",raw,12)[0]
    doc=json.loads(raw[20:20+jsz])
    data=raw[28+jsz:]
    prim=doc["meshes"][0]["primitives"][0]
    materials=[]
    prims=[]
    for i,(cls,(rough,metal)) in enumerate(zip(CLASSES,PAIRS)):
        if cls==remove_class:continue
        mat={"name":cls.upper(),
             "pbrMetallicRoughness":{
                "roughnessFactor":(roughness_override if
                                   roughness_override is not None and i==0
                                   else rough),
                "metallicFactor":metal,
                "metallicRoughnessTexture":{"index":0}},
             "normalTexture":{"index":0}}
        if remove_normal and i==0:mat.pop("normalTexture")
        materials.append(mat)
        prims.append(dict(prim,material=len(materials)-1))
    doc["materials"]=materials
    doc["meshes"][0]["primitives"]=prims
    js=json.dumps(doc,separators=(",",":")).encode()
    js+=b" "*(-len(js)%4)
    return (struct.pack("<4sII",b"glTF",2,28+len(js)+len(data))+
            struct.pack("<I4s",len(js),b"JSON")+js+
            struct.pack("<I4s",len(data),b"BIN\x00")+data)

class Tests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"]="P4"
        self.f.work["phase"]="P4"
        for n,rid in zip((121,122,123,126),IDS):
            source,phase=TEXT[str(n)]
            self.f.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":"M","catalog_phase":phase,
                "requirement":source,
                "requirement_sha256":fixture.sha(source.encode()),
                "source_sha256":"c"*64}
        self.native=material_glb()
        self.put()

    def put(self,native=None,material_plan=None):
        self.f.add_item("NATIVE_EXPORT","scene.glb",
                        self.native if native is None else native)
        self.f.add_item("P4_MATERIAL_PLAN","materials.json",
                        json.dumps(PLAN if material_plan is None else
                                   material_plan).encode())
        self.f.plan["p345_evidence_contract"]={
            "original_artifact_sha256":{
                role:self.f.items[role]["sha256"]
                for role in ("NATIVE_EXPORT","P4_MATERIAL_PLAN")}}
        self.f.rebuild()

    def examine(self):
        return inspect(self.f.inv,self.f.plan,self.f.controller,
                       self.f.asset,self.f.step,self.f.work,
                       source_loader=lambda p:Path(p).read_bytes())

    def test_four_real_material_oracles_no_false_mg0(self):
        r=self.examine()
        self.assertEqual(set(r["rules"]),set(IDS))
        self.assertEqual(r["machine_positive_obligations"],4)
        self.assertEqual(r["original_material_metrics"]["exported_materials"],5)
        self.assertEqual(r["original_material_metrics"]["distinct_measured_pbr_pairs"],5)
        self.assertEqual(r["full_rule_semantic_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertFalse(r["advancement_authorized"])

    def test_roughness_target_mismatch_detected(self):
        self.put(native=material_glb(roughness_override=0.1))
        self.assertEqual(self.examine()["rules"][IDS[1]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_normal_map_slot_missing_is_not_positive(self):
        self.put(native=material_glb(remove_normal=True))
        self.assertEqual(self.examine()["rules"][IDS[2]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_missing_one_physical_class_is_not_complete(self):
        self.put(native=material_glb(remove_class="glass"))
        r=self.examine()
        self.assertEqual(r["rules"][IDS[0]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")
        self.assertEqual(r["rules"][IDS[3]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_missing_pre_d_material_plan_pin_not_positive(self):
        self.f.plan["p345_evidence_contract"]["original_artifact_sha256"].pop(
            "P4_MATERIAL_PLAN")
        self.f.rebuild()
        self.assertEqual(self.examine()["machine_positive_obligations"],0)

    def test_original_material_source_tamper_rejected(self):
        (self.f.root/"materials.json").write_bytes(b"tampered")
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "ARTIFACT_BYTES_CHANGED"):
            self.examine()

    def test_changed_literal_source_rejected(self):
        self.f.inv["rules"][IDS[0]]["requirement"]="fake"
        with self.assertRaisesRegex(OriginalMaterialBlocked,
                                    "ORIGINAL_LITERAL_CHANGED"):
            self.examine()

    def test_cross_attempt_replay_rejected(self):
        self.f.work["attempt_id"]="f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "EXACT_RESERVED_WORK"):
            self.examine()

if __name__=="__main__":
    unittest.main()
