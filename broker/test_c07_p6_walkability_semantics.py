"""P6 P-155..160 adversarial original geometry and runtime non-attestation."""
import copy
import json
import unittest
from pathlib import Path
import test_c07_positive_native_process as fixture
from test_c07_p3_geometry_semantics import glb
from c07_p678_forty_native_domain import TEXT
from c07_p6_walkability_semantics import IDS,inspect,OriginalWalkabilityBlocked
from c07_positive_native_process import NativeEvidenceBlocked

TRI=[(0,0,0),(1,0,0),(0,1,0)]
NORMALS=[(0,0,1)]*3
POLICY={
 "solid_surfaces":[{"name":"floor","min_xyz":[-0.1,-0.1,-0.1],
                    "max_xyz":[1.1,1.1,0.1]}],
 "walkable_regions":[{"name":"walk","min_xyz":[-0.1,-0.1,-0.1],
                      "max_xyz":[1.1,1.1,0.1]}],
 "vehicle_corridors":[{"name":"road","kind":"vehicle",
                       "min_xyz":[2,2,-0.5],"max_xyz":[5,5,2]}],
 "min_vehicle_width_m":2.5,
 "min_vehicle_height_m":2.0,
 "min_player_width_m":0.8,
 "terrain_contact_regions":[{"name":"floor_contact",
     "min_xyz":[-0.1,-0.1,-0.1],"max_xyz":[1.1,1.1,0.1]}],
 "terrain_contact_max_gap_m":0.1,
}
class Tests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"]="P6"
        self.f.work["phase"]="P6"
        for n,rid in zip(range(155,161),IDS):
            literal,phase=TEXT[str(n)]
            self.f.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":"P","catalog_phase":phase,
                "requirement":literal,
                "requirement_sha256":fixture.sha(literal.encode()),
                "source_sha256":"c"*64}
        self.policy=copy.deepcopy(POLICY)
        self.collision=glb(TRI,[(0,1,2)],NORMALS)
        self.visual=glb(TRI,[(0,1,2)],NORMALS)
        self.terrain=glb(TRI,[(0,1,2)],NORMALS)
        self.put()
    def put(self):
        self.f.add_item("NATIVE_EXPORT","scene.glb",self.visual)
        self.f.add_item("COLLISION_EXPORT","collision.glb",self.collision)
        self.f.add_item("TERRAIN_EXPORT","terrain.glb",self.terrain)
        self.f.add_item("P6_COLLISION_POLICY","collision_policy.json",
                        json.dumps(self.policy,separators=(",",":")).encode())
        self.f.plan["p678_evidence_contract"]={
            "original_artifact_sha256":{role:row["sha256"]
                  for role,row in self.f.items.items()}}
        self.f.rebuild()
    def examine(self):
        return inspect(self.f.inv,self.f.plan,self.f.controller,
            self.f.asset,self.f.step,self.f.work,
            source_loader=lambda p:Path(p).read_bytes())
    def test_five_source_geometry_observations_runtime_unattested(self):
        r=self.examine()
        self.assertEqual(set(r["rules"]),set(IDS))
        self.assertEqual(r["machine_positive_obligations"],5)
        self.assertEqual(r["metrics"]["collision_triangles"],1)
        self.assertEqual(r["metrics"]["terrain_triangles"],1)
        self.assertEqual(r["rules"][IDS[-1]]["machine_scope"],"UNKNOWN_OR_DEFECT")
        self.assertFalse(r["metrics"]["fivem_runtime_independently_attested"])
        self.assertEqual(r["full_rule_semantic_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertFalse(r["advancement_authorized"])
    def test_each_clause_independent_negative_and_runtime_unattested(self):
        mutations={
          155:("policy","solid_surfaces",[
              {"name":"far","min_xyz":[8,8,8],"max_xyz":[9,9,9]}]),
          156:("collision",None,glb([(5,5,0),(6,5,0),(5,6,0)],
                                     [(0,1,2)],NORMALS)),
          157:("policy","walkable_regions",[
              {"name":"far","min_xyz":[8,8,8],"max_xyz":[9,9,9]}]),
          158:("terrain",None,glb([(0,0,1),(1,0,1),(0,1,1)],
                                   [(0,1,2)],NORMALS)),
          159:("policy","vehicle_corridors",[
              {"name":"blocked","kind":"vehicle",
               "min_xyz":[0,0,-1],"max_xyz":[3,3,1]}]),
        }
        for n,(kind,key,bad) in mutations.items():
            with self.subTest(rule=n):
                if kind=="policy":
                    old=copy.deepcopy(self.policy[key]);self.policy[key]=bad
                else:old=getattr(self,kind);setattr(self,kind,bad)
                self.put()
                r=self.examine()
                self.assertEqual(r["rules"]["AAA-200-P-%03d"%n]["machine_scope"],
                                 "UNKNOWN_OR_DEFECT")
                if kind=="policy":self.policy[key]=old
                else:setattr(self,kind,old)
                self.put()
        self.f.add_item("FIVEM_COLLISION_RUNTIME_LOG","fivem.log",
                        b"synthetic producer says PASS")
        self.f.plan["p678_evidence_contract"]["original_artifact_sha256"][
            "FIVEM_COLLISION_RUNTIME_LOG"]=self.f.items[
                "FIVEM_COLLISION_RUNTIME_LOG"]["sha256"]
        self.f.rebuild()
        self.assertEqual(self.examine()["rules"][IDS[-1]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")
    def test_player_contact_and_vehicle_height_originals_are_not_producer_labels(self):
        for key,value,rid in (
            ("min_player_width_m",2.0,"AAA-200-P-157"),
            ("terrain_contact_regions",[{"name":"remote",
                 "min_xyz":[8,8,8],"max_xyz":[9,9,9]}],"AAA-200-P-158"),
            ("min_vehicle_height_m",4.0,"AAA-200-P-159"),
        ):
            with self.subTest(rule=rid):
                old=copy.deepcopy(self.policy[key])
                self.policy[key]=value
                self.put()
                self.assertEqual(self.examine()["rules"][rid]["machine_scope"],
                                 "UNKNOWN_OR_DEFECT")
                self.policy[key]=old
                self.put()

    def test_missing_pre_d_pin_is_not_a_positive(self):
        self.f.plan["p678_evidence_contract"]["original_artifact_sha256"].pop(
            "P6_COLLISION_POLICY")
        self.f.rebuild()
        self.assertEqual(self.examine()["machine_positive_obligations"],1)
    def test_original_collision_tamper_fails_closed(self):
        (self.f.root/"collision.glb").write_bytes(b"changed")
        with self.assertRaisesRegex(NativeEvidenceBlocked,"ARTIFACT_BYTES_CHANGED"):
            self.examine()
    def test_cross_attempt_and_original_literal_rejected(self):
        self.f.work["attempt_id"]="f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,"EXACT_RESERVED_WORK"):
            self.examine()
        self.f.work["attempt_id"]="a"*64
        self.f.inv["rules"][IDS[0]]["requirement"]="fake"
        with self.assertRaisesRegex(OriginalWalkabilityBlocked,
                                    "WALKABILITY_LITERAL_CHANGED"):
            self.examine()
    def test_duplicate_json_policy_key_rejected(self):
        self.f.add_item("P6_COLLISION_POLICY","collision_policy.json",
                        b'{"walkable_regions":[],"walkable_regions":[]}')
        self.f.plan["p678_evidence_contract"]["original_artifact_sha256"][
            "P6_COLLISION_POLICY"]=self.f.items["P6_COLLISION_POLICY"]["sha256"]
        self.f.rebuild()
        with self.assertRaisesRegex(ValueError,"DUPLICATE_JSON_KEY"):
            self.examine()

if __name__=="__main__":unittest.main()
