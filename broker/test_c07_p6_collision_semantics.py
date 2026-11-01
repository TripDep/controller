"""Adversarial source-specific P6 collision GLB tests; no runtime PASS."""
import json
import unittest
from pathlib import Path

import test_c07_positive_native_process as fixture
from test_c07_p3_geometry_semantics import glb
from c07_p678_forty_native_domain import TEXT
from c07_p6_collision_semantics import IDS,inspect,OriginalCollisionBlocked
from c07_positive_native_process import NativeEvidenceBlocked

TRI=[(0,0,0),(1,0,0),(0,1,0)]
QUAD=[(0,0,0),(1,0,0),(1,1,0),(0,1,0)]
COLLISION=glb(TRI,[(0,1,2)],[(0,0,1)]*3)
VISUAL=glb(QUAD,[(0,1,2),(0,2,3)],[(0,0,1)]*4)
POLICY={
    "solid_surfaces":[{"name":"floor",
        "min_xyz":[-0.1,-0.1,-0.1],"max_xyz":[1.1,1.1,0.1]}],
    "openings":[{"kind":"door","min_xyz":[2,2,0],
                 "max_xyz":[3,3,2]}],
    "max_collision_triangles":1,
    "max_collision_to_visual_ratio":0.5,
}

class Tests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"]="P6"
        self.f.work["phase"]="P6"
        for n,rid in zip((151,152,153,154),IDS):
            source,phase=TEXT[str(n)]
            self.f.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":"P","catalog_phase":phase,
                "requirement":source,
                "requirement_sha256":fixture.sha(source.encode()),
                "source_sha256":"c"*64}
        self.put()

    def put(self,policy=None,collision=None,visual=None):
        self.f.add_item("NATIVE_EXPORT","scene.glb",
                        VISUAL if visual is None else visual)
        self.f.add_item("COLLISION_EXPORT","collision.glb",
                        COLLISION if collision is None else collision)
        self.f.add_item("P6_COLLISION_POLICY","collision_policy.json",
                        json.dumps(POLICY if policy is None else policy).encode())
        self.f.plan["p678_evidence_contract"]={
            "original_artifact_sha256":{
                role:self.f.items[role]["sha256"]
                for role in ("NATIVE_EXPORT","COLLISION_EXPORT",
                             "P6_COLLISION_POLICY")}}
        self.f.rebuild()

    def examine(self):
        return inspect(self.f.inv,self.f.plan,self.f.controller,
                       self.f.asset,self.f.step,self.f.work,
                       source_loader=lambda p:Path(p).read_bytes())

    def test_four_real_collision_oracles_not_fivem_or_mg0(self):
        r=self.examine()
        self.assertEqual(set(r["rules"]),set(IDS))
        self.assertEqual(r["machine_positive_obligations"],4)
        self.assertEqual(r["original_collision_metrics"]["collision_triangles"],1)
        self.assertEqual(r["original_collision_metrics"]["visual_triangles"],2)
        self.assertEqual(r["full_rule_semantic_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertFalse(r["advancement_authorized"])

    def test_clearance_box_intersecting_real_collision_rejected(self):
        bad=dict(POLICY,openings=[{"kind":"door",
            "min_xyz":[0,0,-1],"max_xyz":[0.8,0.8,1]}])
        self.put(policy=bad)
        self.assertEqual(self.examine()["rules"][IDS[3]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_original_collision_budget_exceeded(self):
        self.put(policy=dict(POLICY,max_collision_triangles=0))
        self.assertEqual(self.examine()["rules"][IDS[2]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_solid_region_without_collision_face_detected(self):
        bad=dict(POLICY,solid_surfaces=[{"name":"distant",
            "min_xyz":[4,4,-1],"max_xyz":[5,5,1]}])
        self.put(policy=bad)
        self.assertEqual(self.examine()["rules"][IDS[0]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_identical_visual_collision_is_not_separated(self):
        self.put(collision=VISUAL)
        self.assertEqual(self.examine()["rules"][IDS[1]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_missing_pre_d_collision_pin_cannot_be_positive(self):
        self.f.plan["p678_evidence_contract"]["original_artifact_sha256"].pop(
            "P6_COLLISION_POLICY")
        self.f.rebuild()
        r=self.examine()
        self.assertEqual(r["rules"][IDS[0]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")
        self.assertEqual(r["rules"][IDS[2]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_registered_collision_bytes_tamper_fails_closed(self):
        (self.f.root/"collision.glb").write_bytes(b"tampered")
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "ARTIFACT_BYTES_CHANGED"):
            self.examine()

    def test_changed_original_literal_rejected(self):
        self.f.inv["rules"][IDS[0]]["requirement"]="forged"
        with self.assertRaisesRegex(OriginalCollisionBlocked,
                                    "ORIGINAL_LITERAL_CHANGED"):
            self.examine()

    def test_cross_attempt_replay_rejected(self):
        self.f.work["attempt_id"]="f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "EXACT_RESERVED_WORK"):
            self.examine()

if __name__=="__main__":
    unittest.main()
