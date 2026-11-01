"""Adversarial N-131..140 original PNG pixel and native lighting tests."""
import copy
import json
import unittest
from pathlib import Path
import test_c07_positive_native_process as fixture
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import with_embedded_texture,QUAD,NORMALS
from test_c07_p5_optimization_semantics import rewrite_glb
from test_c07_p4_texture_semantics import png,solid,gradient
from c07_p345_forty_native_evidence import TEXT
from c07_p4_lighting_semantics import IDS,inspect,OriginalLightingBlocked
from c07_positive_native_process import NativeEvidenceBlocked

POLICY={
 "min_neutral_luma":40,"max_neutral_luma":150,
 "min_direct_delta":30,"min_shadow_delta":20,
 "player_eye_height_m":1.65,"modes":["NEUTRAL","CINEMATIC"],
}
def metallic(doc):
    doc["materials"][0]["name"]="metal"
    doc["materials"][0]["pbrMetallicRoughness"]["metallicFactor"]=0.8
def nonmetallic(doc):
    doc["materials"][0]["pbrMetallicRoughness"]["metallicFactor"]=0.0

class Tests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"]="P4"
        self.f.work["phase"]="P4"
        for n,rid in zip(range(131,141),IDS):
            literal,phase=TEXT[str(n)]
            self.f.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":"N","catalog_phase":phase,
                "requirement":literal,
                "requirement_sha256":fixture.sha(literal.encode()),
                "source_sha256":"c"*64}
        self.native=rewrite_glb(with_embedded_texture(glb(
            QUAD,[(0,1,2),(0,2,3)],NORMALS)),metallic)
        self.views={
            "LIGHT_NEUTRAL_VIEW":png(gradient()),
            "LIGHT_CINEMATIC_VIEW":png(solid(230)),
            "LIGHT_DIRECT_VIEW":png(solid(180)),
            "LIGHT_SHADOW_VIEW":png(solid(30)),
            "VISUAL_VIEW_FRONT":png(solid(50)),
            "VISUAL_VIEW_REAR":png(solid(60)),
            "VISUAL_VIEW_SIDE":png(solid(70)),
            "VISUAL_VIEW_TOP":png(solid(90)),
            "VISUAL_VIEW_UNDERSIDE":png(solid(100)),
            "REFLECTION_VIEW":png(solid(200))}
        self.policy=copy.deepcopy(POLICY)
        self.report={"native_sha256":fixture.sha(self.native),
                     "qa_status":"PENDING","unresolved_findings":[]}
        self.put()
    def put(self):
        self.f.add_item("NATIVE_EXPORT","scene.glb",self.native)
        self.f.add_item("P4_LIGHTING_POLICY","p4_lighting_policy.json",
                        json.dumps(self.policy).encode())
        self.f.add_item("P4_MACHINE_REPORT","p4_machine_report.json",
                        json.dumps(self.report).encode())
        for role,raw in self.views.items():
            self.f.add_item(role,role.lower()+".png",raw)
        self.f.plan["p345_evidence_contract"]={
            "original_artifact_sha256":{role:row["sha256"]
                    for role,row in self.f.items.items()}}
        self.f.rebuild()
    def examine(self):
        return inspect(self.f.inv,self.f.plan,self.f.controller,
            self.f.asset,self.f.step,self.f.work,
            source_loader=lambda p:Path(p).read_bytes())
    def test_ten_original_pixel_oracles_no_full_mg0_or_fivem(self):
        r=self.examine()
        self.assertEqual(set(r["rules"]),set(IDS))
        self.assertEqual(r["source_rule_count"],10)
        self.assertEqual(r["machine_positive_obligations"],10)
        self.assertEqual(r["metrics"]["decoded_view_count"],10)
        self.assertEqual(r["metrics"]["native_triangles"],2)
        self.assertEqual(r["full_rule_semantic_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertFalse(r["advancement_authorized"])
    def test_every_rule_has_independent_negative(self):
        changes={
          131:("policy","max_neutral_luma",10),
          132:("views","LIGHT_CINEMATIC_VIEW",self.views["LIGHT_NEUTRAL_VIEW"]),
          133:("native",None,rewrite_glb(with_embedded_texture(glb(
                  QUAD,[(0,0,1)],NORMALS)),metallic)),
          134:("views","LIGHT_DIRECT_VIEW",png(solid(20))),
          135:("views","LIGHT_SHADOW_VIEW",png(solid(200))),
          136:("native",None,rewrite_glb(self.native,nonmetallic)),
          137:("policy","player_eye_height_m",0),
          138:("views","VISUAL_VIEW_SIDE",self.views["VISUAL_VIEW_FRONT"]),
          139:("views","VISUAL_VIEW_UNDERSIDE",self.views["LIGHT_CINEMATIC_VIEW"]),
          140:("report","native_sha256","0"*64),
        }
        for n,(kind,key,bad) in changes.items():
            with self.subTest(rule=n):
                if kind in ("policy","report"):
                    obj=getattr(self,kind);old=copy.deepcopy(obj[key]);obj[key]=bad
                elif kind=="views":
                    old=self.views[key];self.views[key]=bad
                else:old=self.native;self.native=bad
                self.put()
                row=self.examine()["rules"]["AAA-200-N-%03d"%n]
                self.assertEqual(row["machine_scope"],"UNKNOWN_OR_DEFECT")
                self.assertEqual(row["individual_mg0"],"UNKNOWN")
                if kind in ("policy","report"):obj[key]=old
                elif kind=="views":self.views[key]=old
                else:self.native=old
                self.put()
    def test_missing_pre_d_pins_cannot_become_positive(self):
        self.f.plan["p345_evidence_contract"]["original_artifact_sha256"].clear()
        self.f.rebuild()
        self.assertEqual(self.examine()["machine_positive_obligations"],0)
    def test_tamper_and_cross_attempt_replay_rejected(self):
        (self.f.root/"light_neutral_view.png").write_bytes(b"forged")
        with self.assertRaisesRegex(NativeEvidenceBlocked,"ARTIFACT_BYTES_CHANGED"):
            self.examine()
        self.put()
        self.f.work["attempt_id"]="f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,"EXACT_RESERVED_WORK"):
            self.examine()
    def test_changed_literal_blocked(self):
        self.f.inv["rules"][IDS[0]]["requirement"]="fake"
        with self.assertRaisesRegex(OriginalLightingBlocked,
                                    "LIGHTING_LITERAL_CHANGED"):
            self.examine()
    def test_duplicate_original_policy_json_key_blocked(self):
        self.f.add_item("P4_LIGHTING_POLICY","p4_lighting_policy.json",
                        b'{"min_neutral_luma":1,"min_neutral_luma":200}')
        self.f.plan["p345_evidence_contract"]["original_artifact_sha256"][
            "P4_LIGHTING_POLICY"]=self.f.items["P4_LIGHTING_POLICY"]["sha256"]
        self.f.rebuild()
        with self.assertRaisesRegex(ValueError,"DUPLICATE_JSON_KEY"):
            self.examine()
if __name__=="__main__":unittest.main()
