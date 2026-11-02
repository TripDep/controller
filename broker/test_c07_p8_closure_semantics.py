"""P8 T-195..200 adversarial original Controller source-byte tests.

All assets here are SYNTHETIC FIXTURES. A green test cannot prove production
quality, independent owner approval, FiveM runtime or individual MG0.
"""
import copy
import json
import unittest
from pathlib import Path

import test_c07_positive_native_process as fixture
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import QUAD, NORMALS
from c07_p678_forty_native_domain import TEXT
from c07_p8_closure_semantics import IDS, inspect, OriginalClosureBlocked
from c07_positive_native_process import NativeEvidenceBlocked

class Tests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"] = "P8"
        self.f.work["phase"] = "P8"
        for n, rid in zip(range(195,201), IDS):
            literal, phase = TEXT[str(n)]
            self.f.inv["rules"][rid] = {
                "family":"AAA-200","catalog_number":n,
                "catalog_section":"T","catalog_phase":phase,
                "requirement":literal,
                "requirement_sha256":fixture.sha(literal.encode()),
                "source_sha256":"c"*64,
            }
        self.f.add_item("NATIVE_EXPORT", "scene.glb",
                        glb(QUAD, [(0,1,2),(0,2,3)], NORMALS))
        self.f.add_item("BASELINE_SNAPSHOT", "baseline.glb",
                        glb(QUAD[:3], [(0,1,2)], NORMALS[:3]))
        self.f.add_item("P8_METHOD_BEFORE", "method_before.py", b"def run(): return 0\n")
        self.f.add_item("P8_METHOD_AFTER", "method_after.py", b"def run(): return 1\n")
        self.docs = {
            "P8_MAINTENANCE_GUIDE": {
                "asset":self.f.asset,
                "source_sha256":self.f.items["SOURCE_EDITABLE"]["sha256"],
                "export_sha256":self.f.items["NATIVE_EXPORT"]["sha256"],
                "install_paths":["stream/scene.ydr","stream/scene.ytyp"],
                "maintenance_steps":["Retain original editable source",
                                     "Check original exported SHA"],
                "status":"CANDIDATE","owner_approved":False,
            },
            "P8_TEST_MATRIX": {
                "tests":[
                    {"id":"SOURCE_BYTES","status":"RUN",
                     "evidence_role":"NATIVE_EXPORT",
                     "evidence_sha256":self.f.items["NATIVE_EXPORT"]["sha256"]},
                    {"id":"FIVEM_RUNTIME","status":"NOT_RUN",
                     "evidence_role":None,"evidence_sha256":None},
                ],
            },
            "P8_DEFECT_HISTORY": {
                "issues":[
                    {"id":"D-1","root_cause":"wrong origin",
                     "corrective_action":"rebuild pivot",
                     "before_sha256":self.f.items["BASELINE_SNAPSHOT"]["sha256"],
                     "after_sha256":self.f.items["NATIVE_EXPORT"]["sha256"]},
                    {"id":"D-2","root_cause":"wrong origin",
                     "corrective_action":"correct exporter transform",
                     "before_sha256":self.f.items["BASELINE_SNAPSHOT"]["sha256"],
                     "after_sha256":self.f.items["NATIVE_EXPORT"]["sha256"]},
                ],
            },
            "P8_METHOD_CHANGE": {
                "before_sha256":self.f.items["P8_METHOD_BEFORE"]["sha256"],
                "after_sha256":self.f.items["P8_METHOD_AFTER"]["sha256"],
                "root_cause":"wrong origin",
                "verification_method":"independent coordinate probe",
            },
        }
        self.put()

    def put(self):
        for role, doc in self.docs.items():
            self.f.add_item(role, role.lower()+".json",
                            json.dumps(doc, separators=(",", ":")).encode())
        roles = set(self.docs) | {
            "SOURCE_EDITABLE", "NATIVE_EXPORT", "BASELINE_SNAPSHOT",
            "P8_METHOD_BEFORE", "P8_METHOD_AFTER"}
        self.f.plan["p678_evidence_contract"] = {
            "original_artifact_sha256": {
                role:self.f.items[role]["sha256"] for role in roles}}
        self.f.rebuild()

    def examine(self):
        return inspect(self.f.inv,self.f.plan,self.f.controller,
                       self.f.asset,self.f.step,self.f.work,
                       source_loader=lambda p:Path(p).read_bytes())

    def test_five_scoped_observations_and_final_rule_unknown(self):
        r = self.examine()
        self.assertEqual(set(r["rules"]), set(IDS))
        self.assertEqual(r["machine_positive_obligations"], 5)
        self.assertEqual(r["metrics"]["run_rows"], 1)
        self.assertEqual(r["metrics"]["not_run_rows"], 1)
        self.assertEqual(r["metrics"]["recurrent_issues"], 2)
        self.assertEqual(r["rules"][IDS[-1]]["machine_scope"], "UNKNOWN_OR_DEFECT")
        self.assertEqual(r["full_rule_semantic_passes"], 0)
        self.assertEqual(r["individual_mg0_passes"], 0)
        self.assertFalse(r["advancement_authorized"])

    def test_each_original_clause_has_independent_negative(self):
        mutations = {
            195: ("P8_MAINTENANCE_GUIDE","source_sha256","0"*64),
            196: ("P8_TEST_MATRIX","tests",[
                {"id":"SOURCE_BYTES","status":"RUN","evidence_role":"NATIVE_EXPORT",
                 "evidence_sha256":"0"*64},
                {"id":"FIVEM_RUNTIME","status":"NOT_RUN",
                 "evidence_role":None,"evidence_sha256":None}]),
            197: ("P8_MAINTENANCE_GUIDE","owner_approved",True),
            198: ("P8_DEFECT_HISTORY","issues",[
                dict(self.docs["P8_DEFECT_HISTORY"]["issues"][0]),
                dict(self.docs["P8_DEFECT_HISTORY"]["issues"][1],
                     root_cause="different root cause")]),
            199: ("P8_METHOD_CHANGE","before_sha256","0"*64),
            200: ("P8_MAINTENANCE_GUIDE","status","APPROVED"),
        }
        for n,(role,key,bad) in mutations.items():
            with self.subTest(rule=n):
                old = copy.deepcopy(self.docs[role][key])
                self.docs[role][key] = bad
                self.put()
                row = self.examine()["rules"]["AAA-200-T-%03d" % n]
                self.assertEqual(row["machine_scope"], "UNKNOWN_OR_DEFECT")
                self.assertEqual(row["individual_mg0"], "UNKNOWN")
                self.docs[role][key] = old
                self.put()

    def test_forged_approval_and_test_yes_cannot_make_final_pass(self):
        self.docs["P8_MAINTENANCE_GUIDE"]["status"] = "APPROVED"
        self.docs["P8_MAINTENANCE_GUIDE"]["owner_approved"] = True
        self.docs["P8_TEST_MATRIX"]["tests"][1]["status"] = "RUN"
        self.put()
        r = self.examine()
        self.assertEqual(r["rules"][IDS[-1]]["full_rule_semantics"], "UNKNOWN")
        self.assertFalse(r["advancement_authorized"])

    def test_missing_original_pre_d_pins_yield_no_positive(self):
        self.f.plan["p678_evidence_contract"]["original_artifact_sha256"].clear()
        self.f.rebuild()
        self.assertEqual(self.examine()["machine_positive_obligations"], 0)

    def test_registered_source_tamper_and_cross_attempt_replay(self):
        (self.f.root / "method_after.py").write_bytes(b"forged")
        with self.assertRaisesRegex(NativeEvidenceBlocked, "ARTIFACT_BYTES_CHANGED"):
            self.examine()
        self.f.add_item("P8_METHOD_AFTER", "method_after.py",
                        b"def run(): return 1\n")
        self.put()
        self.f.work["attempt_id"] = "f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked, "EXACT_RESERVED_WORK"):
            self.examine()

    def test_original_literal_mutation_rejected(self):
        self.f.inv["rules"][IDS[0]]["requirement"] = "fake"
        with self.assertRaisesRegex(OriginalClosureBlocked, "CLOSURE_LITERAL_CHANGED"):
            self.examine()

    def test_duplicate_json_keys_rejected(self):
        self.f.add_item("P8_MAINTENANCE_GUIDE", "p8_maintenance_guide.json",
                        b'{"asset":"TEST","asset":"FAKE"}')
        self.f.plan["p678_evidence_contract"]["original_artifact_sha256"][
            "P8_MAINTENANCE_GUIDE"] = self.f.items["P8_MAINTENANCE_GUIDE"]["sha256"]
        self.f.rebuild()
        with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
            self.examine()

if __name__ == "__main__":
    unittest.main()
